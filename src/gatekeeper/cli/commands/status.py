"""gatekeeper status: сводка для оператора (клиенты, журнал, сертификат, состояние)."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from gatekeeper.cli import output
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.pki import ca
from gatekeeper.server.audit.anchor import load_anchors
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.audit.verify import verify_file
from gatekeeper.server.config import load_config
from gatekeeper.server.identity import _parse_entry
from gatekeeper.server.state import load_frozen_clients
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry, RegistryLockedError

_CERT_WARN_DAYS = 30


def _report_certificate(layout: Layout) -> None:
    """Серверный сертификат живёт 365 дней: предупредить заранее (C-03)."""
    try:
        cert = ca.load_cert_pem(layout.server_cert.read_bytes())
    except (OSError, GatekeeperError):
        output.error("server certificate: missing or unreadable (run `gatekeeper renew-server`)")
        return
    days = ca.cert_expires_in_days(cert)
    if days < 0:
        output.error(f"server certificate EXPIRED {-days} day(s) ago: clients cannot connect "
                     "(`gatekeeper renew-server`, then restart)")
    elif days <= _CERT_WARN_DAYS:
        output.error(f"warning: server certificate expires in {days} day(s) "
                     "(`gatekeeper renew-server`, then restart)")
    else:
        output.info(f"server certificate: {days} days left")


def _report_ca_key(path: str | None) -> None:
    """Незашифрованный ca.key — предупреждение (B3). Формат ключа не меняется."""
    if not path:
        return
    try:
        pem = Path(path).read_bytes()
    except OSError:
        output.error(f"ca.key: cannot read {path}")
        return
    try:
        encrypted = ca.key_is_encrypted(pem)
    except GatekeeperError as exc:
        output.error(f"ca.key: {exc}")
        return
    if encrypted:
        output.info("ca.key: encrypted with a passphrase")
    else:
        output.error("warning: ca.key is NOT encrypted: anyone who reads the file can issue "
                     "client certificates; protect it with --ca-key-pass-file "
                     "(or GATEKEEPER_CA_KEY_PASSPHRASE) and keep it offline")


def _report_anchors(layout: Layout, records: int) -> None:
    """Сколько записей прошло после последнего внешнего якоря (A8).

    Записи после последнего якоря не прикрыты: их удаление вместе с chain.head не будет
    обнаружено. Автоякорь выключается, если `[audit] anchor_file` не задан.
    """
    try:
        cfg = load_config(layout.config_file)
    except GatekeeperError:
        return
    if not cfg.audit_anchor_file:
        return
    try:
        anchors = load_anchors(cfg.audit_anchor_file)
    except GatekeeperError as exc:
        output.error(f"anchors: {exc}")
        return
    last = max(anchors, key=lambda a: a.seq)
    after = records - 1 - last.seq
    if after < 0:
        output.error(f"anchors: the last anchor (seq {last.seq}) is ahead of the log "
                     f"({records} record(s)): the tail may have been removed")
    elif after == 0:
        output.info(f"anchors: {len(anchors)}, last at seq {last.seq}; nothing after it")
    else:
        output.info(f"anchors: {len(anchors)}, last at seq {last.seq}; {after} record(s) after "
                    "it are not covered (gatekeeper audit-anchor --out <file>)")


def run(args, layout: Layout) -> int:
    registry = Registry(layout.clients_file)
    try:
        registry.check_permissions()
    except GatekeeperError as exc:
        output.error(str(exc))
        return 1
    locked = False
    try:
        clients = registry.load()
    except RegistryLockedError:
        # Реестр зашифрован, а ключа в окружении нет: показываем метаданные без проверки
        # записей (для неё нужен master_secret). Статусы и отпечатки доступны и так.
        clients, locked = registry.load(decrypt=False), True
    except GatekeeperError as exc:
        output.error(str(exc))
        return 1
    if locked:
        output.error("clients: metadata only (clients.json is encrypted and "
                     "GATEKEEPER_REGISTRY_KEY_FILE is not set): entries were not validated")
    by_status = Counter(str(c.get("status", "?") if isinstance(c, dict) else "?")
                        for c in clients.values())
    summary = ", ".join(f"{n} {st}" for st, n in sorted(by_status.items())) or "none"
    output.info(f"clients: {len(clients)} ({summary})")
    # Запись, которую шлюз не сможет разобрать, делает клиента «неизвестным» (403): показываем её.
    # Без ключа проверить запись нельзя (нет master_secret) — тогда пропускаем проверку.
    invalid = [] if locked else sorted(
        cid for cid, entry in clients.items() if _parse_entry(cid, entry) is None)
    if invalid:
        output.error(f"invalid client entries (the gateway will reject these clients): {', '.join(invalid)}")
    # Автозаморозка не меняет реестр, поэтому её не видно в сводке по статусам выше.
    autofrozen = sorted(load_frozen_clients(layout.state_db))
    if autofrozen:
        output.info(f"autofrozen (state db, registry untouched): {', '.join(autofrozen)}"
                    " — `gatekeeper unfreeze --id <id>`")

    _report_certificate(layout)
    _report_ca_key(getattr(args, "ca_key", None))

    sink = FileSink(layout.audit_log)
    res = verify_file(sink.path, sink.head_path)
    state = "ok" if res.ok else f"FAILED: {res.error} (line {res.line_no})"
    extra = ""
    if not res.ok and res.code == "incomplete_tail":
        extra = "; run `gatekeeper audit-repair` (the gateway repairs it on start as well)"
    output.info(f"audit: {state}; records {res.count}; size {sink.size()} bytes; "
                f"head {res.last_seq} {res.last_hash[:16]}{extra}")
    _report_anchors(layout, res.count)
    output.info(f"state db: {'present' if layout.state_db.exists() else 'absent'}")
    return 0 if res.ok else 2
