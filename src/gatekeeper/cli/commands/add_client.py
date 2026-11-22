"""gatekeeper add-client: выпустить сертификат + ключ подписи, зарегистрировать клиента."""
from __future__ import annotations

import secrets as _secrets
from pathlib import Path

from gatekeeper.cli import output
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
    if out.exists() and any(out.iterdir()):
        output.error(f"output directory is not empty: {out}")
        return 1
    try:
        ca_cert = ca.load_cert_pem(layout.ca_cert.read_bytes())
        ca_key = ca.load_key_pem(Path(args.ca_key).read_bytes())
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
    try:
        reg.add(args.id, entry)
    except GatekeeperError as exc:
        output.error(str(exc))
        return 1

    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    ca.write_private_file(out / "ca.pem", ca.cert_to_pem(ca_cert))
    ca.write_private_file(out / "client.pem", ca.cert_to_pem(cert))
    ca.write_private_file(out / "client.key", ca.key_to_pem(key))
    ca.write_private_file(out / "master.secret", master.hex().encode("ascii"))

    AuditChain(FileSink(layout.audit_log), secrets=(master,)).append(
        EventType.CLIENT_ADDED,
        {"client": args.id, "fingerprint": fp, "allow": list(args.allow), "days": args.days,
         **({"provider": provider} if provider else {})},
    )
    output.info(f"client {args.id} added, fingerprint {fp}")
    output.info(f"bundle written to {out} (client.key and master.secret are secret)")
    return 0
