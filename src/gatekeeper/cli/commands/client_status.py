"""gatekeeper freeze / unfreeze / revoke: меняют статус клиента, шлюз подхватывает без перезапуска.

Порядок как у `approve`/`reject` (C-05): сначала журнал, затем состояние. След в журнале
должен появиться раньше самого изменения, иначе изменение без записи неотличимо от
взлома. Если журнал недоступен, команда не меняет состояние и возвращает ошибку.

Исключение — аварийный режим `revoke --force-no-audit`: отзыв скомпрометированного клиента
важнее записи, поэтому он выполняется и без журнала, но с громким предупреждением в stderr.
Снятие слоя автозаморозки (`state.db`) тоже меняет состояние и идёт после журнала.
"""
from __future__ import annotations

import sqlite3
from contextlib import suppress

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
        force = action == "revoke" and bool(getattr(args, "force_no_audit", False))
        try:
            reg = Registry(layout.clients_file)
            # Секрет для смены статуса не нужен: работаем и с шифрованным реестром без ключа.
            entry = reg.load(decrypt=False).get(args.id)
        except (GatekeeperError, OSError) as exc:
            output.error(str(exc))
            return 1
        if not isinstance(entry, dict):
            # Менять нечего: событие в журнале выглядело бы как реальная заморозка.
            output.error(f"{action}: unknown client {args.id}")
            return 1
        fp, current = entry.get("fingerprint"), entry.get("status")
        # Журнал первым: если он недоступен, состояние не меняется (кроме аварийного отзыва).
        try:
            AuditChain(FileSink(layout.audit_log)).append(
                event, {"client": args.id, "fingerprint": fp}, severity)
        except (GatekeeperError, OSError) as exc:
            if not force:
                output.error(f"{action}: the audit log is unavailable, the client state was not "
                             f"changed: {exc}")
                if action == "revoke":
                    output.info("in an emergency, `gatekeeper revoke --id <id> --force-no-audit` "
                                "revokes without an audit record")
                return 1
            output.error("WARNING: --force-no-audit: revoking the client WITHOUT an audit record "
                         f"(the journal is unavailable: {exc})")
            output.error("the incident is not in the journal: record it manually and repair the "
                         "journal (audit-repair, audit-verify)")
        store = None
        try:
            # Второй слой заморозки живёт в state.db: unfreeze и revoke снимают и его (X-08).
            if action in ("unfreeze", "revoke") and layout.state_db.exists():
                # Не создаём state.db из CLI: на свежей установке его ещё нет (persist_state),
                # а unfreeze не должен оставлять после себя пустую базу.
                store = StateStore(layout.state_db)
                store.del_freeze(args.id)
            if action == "unfreeze" and current == "active":
                pass  # автозаморозка не трогала реестр: снимать в нём нечего
            else:
                reg.set_status(args.id, status, decrypt=False)
        except (GatekeeperError, OSError, sqlite3.Error) as exc:
            # Журнал уже говорит о намерении: фиксируем явный итог «не выполнено».
            with suppress(GatekeeperError, OSError):
                AuditChain(FileSink(layout.audit_log)).append(
                    EventType.REQUEST_ABORTED,
                    {"client": args.id, "action": action, "reason": "state_change_failed",
                     "error": type(exc).__name__, "executed": False}, Severity.WARNING)
            output.error(f"{action} failed after the intent was recorded and the state was not "
                         f"changed: {exc}")
            return 1
        finally:
            if store is not None:
                store.close()
        output.info(f"client {args.id}: {status}")
        return 0

    return run


freeze, unfreeze, revoke = _make("freeze"), _make("unfreeze"), _make("revoke")
