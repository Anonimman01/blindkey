"""gatekeeper pending / approve / reject: подтверждение опасных действий. Шлюз подхватывает сразу.

Порядок для approve/reject: сначала журнал, затем изменение заявки (C-05). Одобрение — это
разрешение на действие, поэтому след в журнале должен появиться раньше самого разрешения; если
журнал недоступен, подтверждение не выдаётся.
"""
from __future__ import annotations

from contextlib import suppress
from datetime import UTC, datetime

from gatekeeper.cli import output
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.events import EventType, Severity
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.config import load_config
from gatekeeper.store.approvals import APPROVED, Approvals, make_preview
from gatekeeper.store.layout import Layout


def _ttl(layout: Layout) -> int:
    try:
        return load_config(layout.config_file).confirm_ttl
    except GatekeeperError:
        return 300


def _store(layout: Layout) -> Approvals:
    return Approvals(layout.approvals_file, _ttl(layout))


def _fmt_time(ts: int) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%H:%M:%S")


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
        output.info(f"{rid}\t{state}\t{e['client']}\t{e['method']}:{e['api']}\t"
                    f"{e['body_len']} bytes\tsha256 {e['body_sha256'][:12]}\t"
                    f"until {_fmt_time(e['expires'])} UTC")
        # В preview лежат разобранные параметры запроса, а не первые байты тела (C-04).
        output.info(f"    params: {make_preview(e.get('preview', ''))}")
    return 0


def _make(action: str):
    event, sev = ((EventType.CONFIRM_APPROVED, Severity.WARNING) if action == "approve"
                  else (EventType.CONFIRM_REJECTED, Severity.INFO))

    def run(args, layout: Layout) -> int:
        try:
            store = _store(layout)
            e = store.peek(args.id)  # ничего не меняет: нужно для записи в журнал
            AuditChain(FileSink(layout.audit_log)).append(
                event, {"client": e["client"], "api": e["api"], "approval": e["id"],
                        "body_sha256": e["body_sha256"]}, sev)
        except (GatekeeperError, OSError) as exc:
            output.error(str(exc))
            return 1
        try:
            getattr(store, action)(args.id)
        except (GatekeeperError, OSError) as exc:
            # Журнал уже говорит о намерении: фиксируем, что действие не выполнено.
            with suppress(GatekeeperError, OSError):
                AuditChain(FileSink(layout.audit_log)).append(
                    EventType.CONFIRM_ACTION_FAILED,
                    {"client": e["client"], "api": e["api"], "approval": e["id"],
                     "action": action, "error": type(exc).__name__}, Severity.ALERT)
            output.error(f"{action} failed after the intent was recorded: {exc}")
            return 1
        output.info(f"{action}d {e['id']}: {e['client']} {e['method']}:{e['api']}")
        return 0

    return run


approve, reject = _make("approve"), _make("reject")
