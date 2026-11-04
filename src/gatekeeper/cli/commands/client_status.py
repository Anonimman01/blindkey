"""gatekeeper freeze / unfreeze / revoke: меняют статус клиента, шлюз подхватывает без перезапуска."""
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
            fp = reg.load().get(args.id, {}).get("fingerprint")
            reg.set_status(args.id, status)
            AuditChain(FileSink(layout.audit_log)).append(
                event, {"client": args.id, "fingerprint": fp}, severity)
        except (GatekeeperError, OSError) as exc:
            output.error(str(exc))
            return 1
        output.info(f"client {args.id}: {status}")
        return 0

    return run


freeze, unfreeze, revoke = _make("freeze"), _make("unfreeze"), _make("revoke")
