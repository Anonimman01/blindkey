"""gatekeeper audit-verify: проверить цепочку журнала. Код возврата 0 = цепочка цела.

С --anchors FILE журнал дополнительно сверяется с внешними якорями (см. audit-anchor):
так обнаруживаются удаление хвоста вместе с chain.head и полная перезапись журнала.
"""
from __future__ import annotations

from gatekeeper.cli import output
from gatekeeper.server.audit.anchor import load_anchors
from gatekeeper.server.audit.verify import verify_file
from gatekeeper.store.layout import Layout


def run(args, layout: Layout) -> int:
    anchors = load_anchors(args.anchors) if getattr(args, "anchors", None) else None
    res = verify_file(layout.audit_log, anchors=anchors)
    if res.ok:
        extra = f", anchors checked: {res.anchors_checked}" if anchors else ""
        output.info(f"OK: {res.count} records, head checked: {res.head_checked}{extra}")
        return 0
    where = f" (line {res.line_no})" if res.line_no else ""
    output.error(f"audit chain BROKEN{where}: {res.error}")
    return 2
