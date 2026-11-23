"""gatekeeper freeze / unfreeze / revoke: меняют статус клиента, шлюз подхватывает без перезапуска.

Порядок: сначала состояние, затем журнал (C-05). Для этих команд состояние — то, что
защищает клиента, поэтому оно меняется первым. Если журнал недоступен, команда возвращает 0
и явно сообщает «выполнено, в журнал не записано»: оператор в инциденте не должен думать,
что заморозка не сработала.
"""
from __future__ import annotations

import sqlite3

from gatekeeper.cli import output
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.events import EventType, Severity
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.state import StateStore
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
        store = None
        try:
            reg = Registry(layout.clients_file)
            entry = reg.load().get(args.id)
            fp = entry.get("fingerprint") if isinstance(entry, dict) else None
            current = entry.get("status") if isinstance(entry, dict) else None
            # Второй слой заморозки живёт в state.db: unfreeze и revoke снимают и его (X-08).
            if action in ("unfreeze", "revoke") and layout.state_db.exists():
                # Не создаём state.db из CLI: на свежей установке его ещё нет (persist_state),
                # а unfreeze не должен оставлять после себя пустую базу.
                store = StateStore(layout.state_db)
                store.del_freeze(args.id)
            if action == "unfreeze" and current == "active":
                pass  # автозаморозка не трогала реестр: снимать в нём нечего
            else:
                reg.set_status(args.id, status)
        except (GatekeeperError, OSError, sqlite3.Error) as exc:
            output.error(str(exc))
            return 1
        finally:
            if store is not None:
                store.close()
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
