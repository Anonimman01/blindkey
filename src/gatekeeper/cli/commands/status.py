"""gatekeeper status: сводка для оператора (клиенты, журнал, сертификат, состояние)."""
from __future__ import annotations

from collections import Counter

from gatekeeper.cli import output
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.pki import ca
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.audit.verify import verify_file
from gatekeeper.server.identity import _parse_entry
from gatekeeper.server.state import load_frozen_clients
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry

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


def run(args, layout: Layout) -> int:
    registry = Registry(layout.clients_file)
    try:
        registry.check_permissions()
        clients = registry.load()
    except GatekeeperError as exc:
        output.error(str(exc))
        return 1
    by_status = Counter(str(c.get("status", "?") if isinstance(c, dict) else "?")
                        for c in clients.values())
    summary = ", ".join(f"{n} {st}" for st, n in sorted(by_status.items())) or "none"
    output.info(f"clients: {len(clients)} ({summary})")
    # Запись, которую шлюз не сможет разобрать, делает клиента «неизвестным» (403): показываем её.
    invalid = sorted(cid for cid, entry in clients.items() if _parse_entry(cid, entry) is None)
    if invalid:
        output.error(f"invalid client entries (the gateway will reject these clients): {', '.join(invalid)}")
    # Автозаморозка не меняет реестр, поэтому её не видно в сводке по статусам выше.
    autofrozen = sorted(load_frozen_clients(layout.state_db))
    if autofrozen:
        output.info(f"autofrozen (state db, registry untouched): {', '.join(autofrozen)}"
                    " — `gatekeeper unfreeze --id <id>`")

    _report_certificate(layout)

    sink = FileSink(layout.audit_log)
    res = verify_file(sink.path, sink.head_path)
    state = "ok" if res.ok else f"FAILED: {res.error} (line {res.line_no})"
    extra = ""
    if not res.ok and res.code == "incomplete_tail":
        extra = "; run `gatekeeper audit-repair` (the gateway repairs it on start as well)"
    output.info(f"audit: {state}; records {res.count}; size {sink.size()} bytes; "
                f"head {res.last_seq} {res.last_hash[:16]}{extra}")
    output.info(f"state db: {'present' if layout.state_db.exists() else 'absent'}")
    return 0 if res.ok else 2
