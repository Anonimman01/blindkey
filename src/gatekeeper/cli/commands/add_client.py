"""gatekeeper add-client: выпустить сертификат + ключ подписи, зарегистрировать клиента.

Порядок: сначала пакет на диске, затем запись в реестре. Иначе при сбое посередине в реестре
оставался бы активный клиент без пакета, и `add-client` с тем же id уже не повторить.
"""
from __future__ import annotations

import secrets as _secrets
from contextlib import suppress
from pathlib import Path

from gatekeeper.cli import output
from gatekeeper.cli.bundle import discard_bundle, write_bundle
from gatekeeper.cli.cakey import load_matching_ca_key, read_passphrase
from gatekeeper.core import constants
from gatekeeper.core.errors import GatekeeperError, PolicyError
from gatekeeper.core.events import EventType
from gatekeeper.core.signing import is_valid_client_id
from gatekeeper.core.timeutil import unix_now
from gatekeeper.pki import ca
from gatekeeper.pki.fingerprint import cert_fingerprint
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.policy import parse_rule
from gatekeeper.server.providers import KNOWN_PROVIDERS
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry, RegistryError


def _valid_rule(rule: str) -> bool:
    """Единый источник истины: то же правило, которое потом разберёт шлюз (policy.parse_rule)."""
    try:
        parse_rule(rule)
    except PolicyError:
        return False
    return True


def run(args, layout: Layout) -> int:
    if not is_valid_client_id(args.id):
        output.error("invalid client id (letters/digits/._-, must start with letter or digit, max 64)")
        return 1
    bad = [r for r in args.allow if not _valid_rule(r)]
    if bad:
        output.error(f"invalid --allow rule(s): {bad} (expected GET|POST:apiName, e.g. POST:sendMessage)")
        return 1
    provider = getattr(args, "provider", None)
    if provider is not None and provider not in KNOWN_PROVIDERS:
        output.error(f"unknown provider: {provider} (known: {', '.join(KNOWN_PROVIDERS)})")
        return 1
    out = Path(args.out)
    out_existed = out.exists()
    if out_existed and any(out.iterdir()):
        output.error(f"output directory is not empty: {out}")
        return 1
    try:
        passphrase = read_passphrase(args)
        ca_cert = ca.load_cert_pem(layout.ca_cert.read_bytes())
        ca_key = load_matching_ca_key(Path(args.ca_key), passphrase, ca_cert)
        reg = Registry(layout.clients_file)
        if args.id in reg.load():
            raise RegistryError(f"client already exists: {args.id}")
        cert, key = ca.issue_client_cert(ca_cert, ca_key, args.id, days=args.days)
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1

    fp = cert_fingerprint(cert)
    master = _secrets.token_bytes(constants.MASTER_SECRET_LEN)
    now = unix_now()
    entry = {
        "fingerprint": fp,
        "master_secret": master.hex(),
        "status": "active",
        "created": now,
        "expires": now + args.days * 86400,
        "allow": list(args.allow),
    }
    if provider is not None:
        entry["provider"] = provider  # без поля клиент работает с первым провайдером шлюза
    # Пакет — до реестра (см. docstring): при сбое клиента в реестре ещё нет.
    try:
        write_bundle(out, {
            "ca.pem": ca.cert_to_pem(ca_cert),
            "client.pem": ca.cert_to_pem(cert),
            "client.key": ca.key_to_pem(key),
            "master.secret": master.hex().encode("ascii"),
        })
    except (GatekeeperError, OSError) as exc:
        if not out_existed:
            with suppress(OSError):
                out.rmdir()
        output.error(f"cannot write the client bundle: {exc}")
        return 1
    try:
        reg.add(args.id, entry)
    except GatekeeperError as exc:
        discard_bundle(out, out_existed)
        output.error(str(exc))
        return 1

    try:
        AuditChain(FileSink(layout.audit_log), secrets=(master,)).append(
            EventType.CLIENT_ADDED,
            {"client": args.id, "fingerprint": fp, "allow": list(args.allow), "days": args.days,
             **({"provider": provider} if provider else {})},
        )
    except (GatekeeperError, OSError) as exc:
        output.info(f"client {args.id} added, fingerprint {fp}, bundle written to {out}")
        output.error(f"WARNING: the client is registered but the event was not recorded in the "
                     f"journal: {exc}")
        return 0
    output.info(f"client {args.id} added, fingerprint {fp}")
    output.info(f"bundle written to {out} (client.key and master.secret are secret)")
    return 0
