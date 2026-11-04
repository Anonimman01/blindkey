"""gatekeeper renew: новый сертификат и ключ подписи для существующего клиента.

Права (allow) и статус сохраняются. Старый сертификат перестаёт работать сразу,
новый пакет записывается в --out. Отозванного клиента продлить нельзя.
"""
from __future__ import annotations

import secrets as _secrets
from pathlib import Path

from gatekeeper.cli import output
from gatekeeper.core import constants
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.events import EventType
from gatekeeper.core.timeutil import unix_now
from gatekeeper.pki import ca
from gatekeeper.pki.fingerprint import cert_fingerprint
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry, RegistryError


def run(args, layout: Layout) -> int:
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        output.error(f"output directory is not empty: {out}")
        return 1
    if not 1 <= args.days <= 3650:
        output.error("--days must be between 1 and 3650")
        return 1
    try:
        ca_cert = ca.load_cert_pem(layout.ca_cert.read_bytes())
        ca_key = ca.load_key_pem(Path(args.ca_key).read_bytes())
        reg = Registry(layout.clients_file)
        old = reg.load().get(args.id)
        if old is None:
            raise RegistryError("unknown client")
        if old.get("status") == "revoked":
            raise RegistryError("client is revoked: issue a new client instead")
        cert, key = ca.issue_client_cert(ca_cert, ca_key, args.id, days=args.days)
        fp = cert_fingerprint(cert)
        master = _secrets.token_bytes(constants.MASTER_SECRET_LEN)
        reg.renew(args.id, fingerprint=fp, master_secret=master.hex(),
                  expires=unix_now() + args.days * 86400)
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1

    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    ca.write_private_file(out / "ca.pem", ca.cert_to_pem(ca_cert))
    ca.write_private_file(out / "client.pem", ca.cert_to_pem(cert))
    ca.write_private_file(out / "client.key", ca.key_to_pem(key))
    ca.write_private_file(out / "master.secret", master.hex().encode("ascii"))

    AuditChain(FileSink(layout.audit_log), secrets=(master,)).append(
        EventType.CLIENT_RENEWED,
        {"client": args.id, "old_fingerprint": old.get("fingerprint"),
         "fingerprint": fp, "days": args.days})
    output.info(f"client {args.id} renewed, fingerprint {fp}")
    output.info(f"new bundle written to {out}; the old certificate no longer works")
    return 0
