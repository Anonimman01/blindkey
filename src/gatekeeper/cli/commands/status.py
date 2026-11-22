"""gatekeeper status: сводка для оператора (клиенты, журнал, состояние)."""
from __future__ import annotations

from collections import Counter

from gatekeeper.cli import output
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.audit.verify import verify_file
from gatekeeper.server.identity import _parse_entry
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry


def run(args, layout: Layout) -> int:
    registry = Registry(layout.clients_file)
    try:
        registry.check_permissions()
        clients = registry.load()
    except GatekeeperError as exc:
        output.error(str(exc))
        return 1
    by_status = Counter(str(c.get("status", "?")) for c in clients.values())
    summary = ", ".join(f"{n} {st}" for st, n in sorted(by_status.items())) or "none"
    output.info(f"clients: {len(clients)} ({summary})")
    # Запись, которую шлюз не сможет разобрать, делает клиента «неизвестным» (403): показываем её.
    invalid = sorted(cid for cid, entry in clients.items() if _parse_entry(cid, entry) is None)
    if invalid:
        output.error(f"invalid client entries (the gateway will reject these clients): {', '.join(invalid)}")

    sink = FileSink(layout.audit_log)
    res = verify_file(sink.path, sink.head_path)
    state = "ok" if res.ok else f"FAILED: {res.error} (line {res.line_no})"
    output.info(f"audit: {state}; records {res.count}; size {sink.size()} bytes; "
                f"head {res.last_seq} {res.last_hash[:16]}")
    output.info(f"state db: {'present' if layout.state_db.exists() else 'absent'}")
    return 0 if res.ok else 2
