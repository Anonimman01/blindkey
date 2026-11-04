"""gatekeeper decoy-create: выпустить приманку (пакет, неотличимый от настоящего клиента)."""
from __future__ import annotations

import secrets as _secrets
from pathlib import Path

from gatekeeper.cli import output
from gatekeeper.core import constants
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.signing import is_valid_client_id
from gatekeeper.core.timeutil import unix_now
from gatekeeper.pki import ca
from gatekeeper.pki.fingerprint import cert_fingerprint
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.honey.decoys import DecoyStore
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry


def run(args, layout: Layout) -> int:
    if not is_valid_client_id(args.name):
        output.error("invalid decoy name")
        return 1
    out = Path(args.out)
    if out.exists() and any(out.iterdir()):
        output.error(f"output directory is not empty: {out}")
        return 1
    try:
        if args.name in Registry(layout.clients_file).load():
            output.error("name is used by a real client")
            return 1
        ca_cert = ca.load_cert_pem(layout.ca_cert.read_bytes())
        ca_key = ca.load_key_pem(Path(args.ca_key).read_bytes())
        cert, key = ca.issue_client_cert(ca_cert, ca_key, args.name, days=args.days)
        fp = cert_fingerprint(cert)
        DecoyStore(layout.decoys_file).add(args.name, fp, unix_now(), args.hint)
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    ca.write_private_file(out / "ca.pem", ca.cert_to_pem(ca_cert))
    ca.write_private_file(out / "client.pem", ca.cert_to_pem(cert))
    ca.write_private_file(out / "client.key", ca.key_to_pem(key))
    # Ключ подписи случайный и нигде не хранится: подпись всё равно не нужна,
    # тревога срабатывает по сертификату.
    ca.write_private_file(out / "master.secret",
                          _secrets.token_bytes(constants.MASTER_SECRET_LEN).hex().encode("ascii"))
    AuditChain(FileSink(layout.audit_log)).append(
        "decoy_created", {"name": args.name, "fingerprint": fp, "hint": args.hint})
    output.info(f"decoy {args.name} created, fingerprint {fp}")
    output.info(f"bundle written to {out}: place it where an intruder would look (old dir, repo, backup)")
    return 0
