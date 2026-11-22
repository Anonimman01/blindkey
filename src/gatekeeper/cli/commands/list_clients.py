"""gatekeeper list-clients: id, статус, отпечаток, срок. Секреты не показываются.

Одна испорченная запись не должна скрывать весь список (B-15): нечисловой/отсутствующий
`expires` и немассивная запись выводятся как «invalid», остальные клиенты видны.
"""
from __future__ import annotations

from datetime import UTC, datetime

from gatekeeper.cli import output
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry


def _expiry(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "invalid"
    try:
        return datetime.fromtimestamp(value, UTC).strftime("%Y-%m-%d")
    except (OverflowError, OSError, ValueError):
        return "invalid"


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
        if not isinstance(c, dict):
            output.info(f"{cid}\tinvalid\trecord is not an object")
            continue
        fp = c.get("fingerprint")
        prov = c.get("provider")
        output.info(f"{cid}\t{c.get('status','?')}\t"
                    f"{fp if isinstance(fp, str) else '?'}\texpires {_expiry(c.get('expires'))}"
                    + (f"\tprovider {prov}" if isinstance(prov, str) else ""))
    return 0
