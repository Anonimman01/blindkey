"""gatekeeper renew: новый сертификат и ключ подписи для существующего клиента.

Права (allow) и статус сохраняются. Старый сертификат перестаёт работать сразу,
новый пакет записывается в --out. Отозванного клиента продлить нельзя.

Порядок (issue #9): сначала пакет на диск, потом реестр. Пока реестр не изменён, старый
сертификат клиента остаётся рабочим, поэтому сбой записи пакета ничего не ломает и откатывать
реестр не нужно. Если сбой случился уже при записи реестра, новый пакет удаляется.
"""
from __future__ import annotations

import secrets as _secrets
from pathlib import Path

from gatekeeper.cli import output
from gatekeeper.cli.bundle import discard_bundle, write_bundle
from gatekeeper.cli.cakey import load_matching_ca_key, read_passphrase
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
        passphrase = read_passphrase(args)
        ca_cert = ca.load_cert_pem(layout.ca_cert.read_bytes())
        ca_key = load_matching_ca_key(Path(args.ca_key), passphrase, ca_cert)
        reg = Registry(layout.clients_file)
        old = reg.load().get(args.id)
        if not isinstance(old, dict):
            raise RegistryError("unknown client")
        if old.get("status") == "revoked":
            raise RegistryError("client is revoked: issue a new client instead")
        cert, key = ca.issue_client_cert(ca_cert, ca_key, args.id, days=args.days)
        fp = cert_fingerprint(cert)
        master = _secrets.token_bytes(constants.MASTER_SECRET_LEN)
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1

    out_existed = out.exists()
    try:
        write_bundle(out, {
            "ca.pem": ca.cert_to_pem(ca_cert),
            "client.pem": ca.cert_to_pem(cert),
            "client.key": ca.key_to_pem(key),
            "master.secret": master.hex().encode("ascii"),
        })
    except (GatekeeperError, OSError) as exc:  # write_bundle сам откатил свою запись
        output.error(f"cannot write the new bundle; the registry was not changed: {exc}")
        return 1
    try:
        reg.renew(args.id, fingerprint=fp, master_secret=master.hex(),
                  expires=unix_now() + args.days * 86400)
    except (GatekeeperError, OSError) as exc:
        discard_bundle(out, out_existed)  # реестр не принял изменение: новый пакет не нужен
        output.error(f"cannot update the client registry; the new bundle was removed: {exc}")
        return 1

    try:
        AuditChain(FileSink(layout.audit_log), secrets=(master,)).append(
            EventType.CLIENT_RENEWED,
            {"client": args.id, "old_fingerprint": old.get("fingerprint"),
             "fingerprint": fp, "days": args.days})
    except (GatekeeperError, OSError) as exc:
        output.info(f"client {args.id} renewed, fingerprint {fp}, bundle written to {out}")
        output.error(f"WARNING: the renewal is in place but the event was not recorded in the "
                     f"journal: {exc}")
        return 0
    output.info(f"client {args.id} renewed, fingerprint {fp}")
    output.info(f"new bundle written to {out}; the old certificate no longer works")
    return 0
