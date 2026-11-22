"""gatekeeper renew-server: перевыпустить серверный сертификат шлюза (C-03).

Серверный сертификат живёт 365 дней; без продления клиенты перестанут подключаться.
SAN берутся из текущего сертификата, если не передан `--host`. Старые `server.pem` и
`server.key` заменяются атомарно (0600); после этого нужен перезапуск шлюза. CA-сертификат
не меняется, поэтому клиентские пакеты остаются действительными.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from gatekeeper.cli import output
from gatekeeper.cli.cakey import load_ca_key, read_passphrase
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.events import EventType
from gatekeeper.pki import ca
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.store.atomic import atomic_write_private
from gatekeeper.store.layout import Layout


def _existing_hosts(layout: Layout) -> list[str]:
    try:
        cert = ca.load_cert_pem(layout.server_cert.read_bytes())
    except (OSError, GatekeeperError):
        return []
    return ca.cert_hosts(cert)


def run(args, layout: Layout) -> int:
    if not 1 <= args.days <= 3650:
        output.error("--days must be between 1 and 3650")
        return 1
    hosts = list(getattr(args, "host", None) or []) or _existing_hosts(layout)
    if not hosts:
        output.error("no --host given and the current server certificate has no SAN to reuse")
        return 1
    try:
        passphrase = read_passphrase(args)
        ca_cert = ca.load_cert_pem(layout.ca_cert.read_bytes())
        ca_key = load_ca_key(Path(args.ca_key), passphrase)
        if not ca.key_matches_cert(ca_key, ca_cert):
            raise GatekeeperError("this CA key does not match ca.pem")
        cert, key = ca.issue_server_cert(ca_cert, ca_key, hosts, days=args.days)
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1

    try:
        atomic_write_private(layout.server_cert, ca.cert_to_pem(cert))
        atomic_write_private(layout.server_key, ca.key_to_pem(key))
    except OSError as exc:
        output.error(f"cannot write the new server certificate: {exc}")
        return 1
    not_after = ca.cert_not_after(cert).strftime("%Y-%m-%d")
    try:
        AuditChain(FileSink(layout.audit_log), secrets=()).append(
            EventType.SERVER_CERT_RENEWED,
            {"hosts": hosts, "days": args.days, "not_after": not_after})
    except (GatekeeperError, OSError) as exc:
        output.info("server certificate replaced")
        output.error(f"WARNING: the new certificate is in place but not recorded in the journal: {exc}")
        return 0
    output.info(f"server certificate renewed for {', '.join(hosts)}: valid until {not_after} "
                f"({args.days} days)")
    output.info("restart the gateway (systemctl restart gatekeeper) to use the new certificate")
    output.info(f"renewed at {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    return 0
