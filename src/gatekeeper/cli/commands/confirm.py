"""gatekeeper pending / approve / reject: подтверждение опасных действий.

Порядок для approve/reject: сначала журнал, затем изменение заявки (C-05). Одобрение — это
разрешение на действие, поэтому след в журнале должен появиться раньше самого разрешения; если
журнал недоступен, подтверждение не выдаётся.

Подписанные одобрения (B1): при `[confirm] require_signed_approvals = true` одобрение без
подписи ключом оператора не выдаётся. `--sign-key` подписывает заявку закрытым ключом
(он остаётся на машине оператора), `--approval-out` пишет подписанный файл для переноса,
`--approval-file` применяет такой файл уже на машине шлюза.
"""
from __future__ import annotations

import json
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from gatekeeper.cli import output
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.events import EventType, Severity
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.config import load_config
from gatekeeper.store.approvals import (
    APPROVED,
    ID_LEN,
    ApprovalError,
    Approvals,
    load_operator_key,
    load_signing_key,
    make_preview,
)
from gatekeeper.store.layout import Layout

_DEFAULT_TTL = 300


def _load_config(layout: Layout):
    try:
        return load_config(layout.config_file)
    except GatekeeperError:
        return None  # нет конфига: старый режим, ttl и подпись по умолчанию


def _store(layout: Layout) -> Approvals:
    cfg = _load_config(layout)
    require_signed = bool(cfg is not None and cfg.confirm_require_signed)
    key = None
    if cfg is not None and cfg.confirm_operator_key:
        try:
            key = load_operator_key(Path(cfg.confirm_operator_key).read_bytes())
        except (OSError, GatekeeperError) as exc:
            raise ApprovalError(f"[confirm] operator_public_key: {exc}") from exc
    ttl = cfg.confirm_ttl if cfg is not None else _DEFAULT_TTL
    return Approvals(layout.approvals_file, ttl, require_signed=require_signed,
                     operator_key=key)


def _fmt_time(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%H:%M:%S")


def _audit(layout: Layout, event: EventType, entry: dict, sev: Severity) -> None:
    """Запись в журнал до изменения заявки: без неё изменение не делается."""
    AuditChain(FileSink(layout.audit_log)).append(
        event, {"client": entry["client"], "api": entry["api"], "approval": entry["id"],
                "body_sha256": entry["body_sha256"]}, sev)


_DOC_BOUND_FIELDS = ("client", "method", "api", "body_sha256", "content_type")


def _check_approval_matches(doc: object, entry: dict) -> None:
    """Подписанный файл должен относиться к заявке из --id, а не к другой.

    Иначе журнал (`CONFIRM_APPROVED` для args.id) расходится с тем, что реально
    одобрено: оператор может перепутать файлы, а след останется ложным.
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("entry"), dict):
        raise ApprovalError("malformed signed approval")
    candidate = doc["entry"]
    if (str(doc.get("key", ""))[:ID_LEN] != entry["id"]
            or any(candidate.get(f) != entry.get(f) for f in _DOC_BOUND_FIELDS)):
        raise ApprovalError(
            "the signed approval file is for another request "
            f"({str(doc.get('key', ''))[:ID_LEN]}), not for {entry['id']}")


def _audit_failed(layout: Layout, entry: dict, action: str, exc: BaseException) -> None:
    """Журнал уже говорит о намерении: фиксируем, что действие не выполнено."""
    with suppress(GatekeeperError, OSError):
        AuditChain(FileSink(layout.audit_log)).append(
            EventType.CONFIRM_ACTION_FAILED,
            {"client": entry["client"], "api": entry["api"], "approval": entry["id"],
             "action": action, "error": type(exc).__name__}, Severity.ALERT)


def pending(args, layout: Layout) -> int:
    try:
        store = _store(layout)
        items = store.list_items()
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1
    if store.last_dropped:
        output.error(f"warning: {store.last_dropped} damaged approval record(s) were ignored "
                     "and removed from approvals.json")
    if not items:
        output.info("no pending requests")
        return 0
    for rid, e in items:
        state = "APPROVED" if e["status"] == APPROVED else "pending"
        if store.require_signed:
            state += " (signed)" if e.get("signature") else " (signature required)"
        output.info(f"{rid}\t{state}\t{e['client']}\t{e['method']}:{e['api']}\t"
                    f"{e['body_len']} bytes\tsha256 {e['body_sha256'][:12]}\t"
                    f"until {_fmt_time(e['expires'])} UTC")
        # В preview лежат разобранные параметры запроса, а не первые байты тела (C-04).
        output.info(f"    params: {make_preview(e.get('preview', ''))}")
    return 0


def approve(args, layout: Layout) -> int:
    """Подтвердить заявку: журнал, затем подпись/изменение заявки."""
    try:
        store = _store(layout)
        e = store.peek(args.id)  # ничего не меняет: нужно для записи в журнал
        _audit(layout, EventType.CONFIRM_APPROVED, e, Severity.WARNING)
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1
    try:
        approval_file = getattr(args, "approval_file", None)
        sign_key = getattr(args, "sign_key", None)
        approval_out = getattr(args, "approval_out", None)
        if approval_file:
            try:
                doc = json.loads(Path(approval_file).read_text("utf-8"))
            except (OSError, ValueError) as exc:
                raise ApprovalError("cannot read the signed approval file") from exc
            _check_approval_matches(doc, e)
            store.import_signed(doc)
            output.info(f"approved {e['id']} with the signed approval from {approval_file}")
            return 0
        if sign_key:
            try:
                key = load_signing_key(Path(sign_key).read_bytes())
            except OSError as exc:
                raise ApprovalError("cannot read the signing key") from exc
            if approval_out:
                doc = store.sign(args.id, key)
                try:
                    Path(approval_out).write_text(
                        json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
                except OSError as exc:
                    raise ApprovalError("cannot write the signed approval file") from exc
                output.info(f"signed approval for {e['id']} written to {approval_out}")
                output.info("move it to the keyless gateway machine and run "
                            f"`gatekeeper approve --id {e['id']} --approval-file <file>`")
                return 0
            store.approve_with_key(args.id, key)
            output.info(f"approved {e['id']} with the operator signature")
            return 0
        store.approve(args.id)
    except (GatekeeperError, OSError) as exc:
        # Журнал уже говорит о намерении: фиксируем, что действие не выполнено.
        _audit_failed(layout, e, "approve", exc)
        output.error(f"approve failed after the intent was recorded: {exc}")
        return 1
    output.info(f"approved {e['id']}: {e['client']} {e['method']}:{e['api']}")
    return 0


def reject(args, layout: Layout) -> int:
    try:
        store = _store(layout)
        e = store.peek(args.id)
        _audit(layout, EventType.CONFIRM_REJECTED, e, Severity.INFO)
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1
    try:
        store.reject(args.id)
    except (GatekeeperError, OSError) as exc:
        _audit_failed(layout, e, "reject", exc)
        output.error(f"reject failed after the intent was recorded: {exc}")
        return 1
    output.info(f"rejected {e['id']}: {e['client']} {e['method']}:{e['api']}")
    return 0
