"""gatekeeper audit-verify: проверить цепочку журнала. Код возврата 0 = цепочка цела."""
from __future__ import annotations

from gatekeeper.cli import output
from gatekeeper.server.audit.verify import verify_file
from gatekeeper.store.layout import Layout


def run(args, layout: Layout) -> int:
    res = verify_file(layout.audit_log)
    if res.ok:
        output.info(f"OK: {res.count} records, head checked: {res.head_checked}")
        return 0
    where = f" (line {res.line_no})" if res.line_no else ""
    output.error(f"audit chain BROKEN{where}: {res.error}")
    return 2
