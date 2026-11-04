"""gatekeeper list-clients: id, статус, отпечаток, срок. Секреты не показываются."""
from __future__ import annotations

from datetime import datetime, timezone

from gatekeeper.cli import output
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry


def run(args, layout: Layout) -> int:
    try:
        clients = Registry(layout.clients_file).load()
    except GatekeeperError as exc:
        output.error(str(exc))
        return 1
    if not clients:
        output.info("no clients")
        return 0
    for cid in sorted(clients):
        c = clients[cid]
        exp = datetime.fromtimestamp(c.get("expires", 0), timezone.utc).strftime("%Y-%m-%d")
        output.info(f"{cid}\t{c.get('status','?')}\t{c.get('fingerprint','?')}\texpires {exp}")
    return 0
