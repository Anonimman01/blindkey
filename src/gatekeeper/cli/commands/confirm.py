"""gatekeeper pending / approve / reject: подтверждение опасных действий. Шлюз подхватывает сразу."""
from __future__ import annotations

from datetime import datetime, timezone

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
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%H:%M:%S")


def pending(args, layout: Layout) -> int:
    try:
        items = _store(layout).list_items()
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1
    if not items:
        output.info("no pending requests")
        return 0
    for rid, e in items:
        state = "APPROVED" if e["status"] == APPROVED else "pending"
        output.info(f"{rid}\t{state}\t{e['client']}\t{e['method']}:{e['api']}\t"
                    f"{e['body_len']} bytes\tsha256 {e['body_sha256'][:12]}\t"
                    f"until {_fmt_time(e['expires'])} UTC")
        output.info(f"    {make_preview(e.get('preview', ''))}")
    return 0


def _make(action: str):
    event, sev = ((EventType.CONFIRM_APPROVED, Severity.WARNING) if action == "approve"
                  else (EventType.CONFIRM_REJECTED, Severity.INFO))

    def run(args, layout: Layout) -> int:
        try:
            store = _store(layout)
            e = getattr(store, action)(args.id)
            AuditChain(FileSink(layout.audit_log)).append(
                event, {"client": e["client"], "api": e["api"], "approval": e["id"],
                        "body_sha256": e["body_sha256"]}, sev)
        except (GatekeeperError, OSError) as exc:
            output.error(str(exc))
            return 1
        output.info(f"{action}d {e['id']}: {e['client']} {e['method']}:{e['api']}")
        return 0

    return run


approve, reject = _make("approve"), _make("reject")
