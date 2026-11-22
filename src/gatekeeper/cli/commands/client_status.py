"""gatekeeper freeze / unfreeze / revoke: меняют статус клиента, шлюз подхватывает без перезапуска.

Порядок: сначала состояние, затем журнал (C-05). Для этих команд состояние — то, что
защищает клиента, поэтому оно меняется первым. Если журнал недоступен, команда возвращает 0
и явно сообщает «выполнено, в журнал не записано»: оператор в инциденте не должен думать,
что заморозка не сработала.
"""
from __future__ import annotations

from gatekeeper.cli import output
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.events import EventType, Severity
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry

_ACTIONS = {
    "freeze": ("frozen", EventType.CLIENT_FROZEN, Severity.WARNING),
    "unfreeze": ("active", EventType.CLIENT_UNFROZEN, Severity.INFO),
    "revoke": ("revoked", EventType.CLIENT_REVOKED, Severity.ALERT),
}


def _make(action: str):
    status, event, severity = _ACTIONS[action]

    def run(args, layout: Layout) -> int:
        try:
            reg = Registry(layout.clients_file)
            entry = reg.load().get(args.id)
            fp = entry.get("fingerprint") if isinstance(entry, dict) else None
            reg.set_status(args.id, status)
        except (GatekeeperError, OSError) as exc:
            output.error(str(exc))
            return 1
        try:
            AuditChain(FileSink(layout.audit_log)).append(
                event, {"client": args.id, "fingerprint": fp}, severity)
        except (GatekeeperError, OSError) as exc:
            output.info(f"client {args.id}: {status} (state changed)")
            output.error("WARNING: the state was changed but the audit log was not updated: "
                         f"{exc}")
            output.info("the change is in effect; record the incident manually and repair/verify "
                        "the journal (audit-repair, audit-verify)")
            return 0
        output.info(f"client {args.id}: {status}")
        return 0

    return run


freeze, unfreeze, revoke = _make("freeze"), _make("unfreeze"), _make("revoke")
