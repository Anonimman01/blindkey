"""gatekeeper encrypt-registry: перевести clients.json на шифрование master_secret (B2).

Ключ берётся из файла, на который указывает `GATEKEEPER_REGISTRY_KEY_FILE` (32 байта или
64 hex-символа, права не шире 0400). `--decrypt` возвращает открытый текст.

Журнал пишется до изменения, как у остальных команд, которые меняют состояние: без
журнала реестр не переписывается.
"""
from __future__ import annotations

from gatekeeper.cli import output
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.events import EventType, Severity
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry
from gatekeeper.store.registry_key import load_key_from_env


def run(args, layout: Layout) -> int:
    decrypt = bool(getattr(args, "decrypt", False))
    action = "decrypt" if decrypt else "encrypt"
    try:
        key = None if decrypt else load_key_from_env()
        registry = Registry(layout.clients_file)
        clients = registry.load()          # с ключом из окружения, если он задан
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1
    try:
        AuditChain(FileSink(layout.audit_log)).append(
            EventType.REGISTRY_REKEYED, {"action": action, "clients": len(clients)},
            Severity.WARNING)
    except (GatekeeperError, OSError) as exc:
        output.error(f"encrypt-registry: the audit log is unavailable, clients.json was not "
                     f"changed: {exc}")
        return 1
    try:
        registry.rekey(key)
    except (GatekeeperError, OSError) as exc:
        output.error(f"encrypt-registry failed after the intent was recorded: {exc}")
        return 1
    if decrypt:
        output.info(f"clients.json: {len(clients)} master_secret value(s) stored in plain text")
        output.error("WARNING: master_secret is readable by anyone who can read clients.json "
                     "(keep the file 0600 and out of backups without encryption)")
    else:
        output.info(f"clients.json: {len(clients)} master_secret value(s) encrypted; the key "
                    "must be available to the gateway (GATEKEEPER_REGISTRY_KEY_FILE, for "
                    "example a systemd credential)")
    return 0
