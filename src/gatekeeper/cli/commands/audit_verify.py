"""gatekeeper audit-verify: проверить цепочку журнала. Код возврата 0 = цепочка цела.

С --anchors FILE журнал дополнительно сверяется с внешними якорями (см. audit-anchor):
так обнаруживаются удаление хвоста вместе с chain.head и полная перезапись журнала.
С --all-segments проверяются и ротированные сегменты: каждый из них — самостоятельная
цепочка, и без этого флага сбой в архиве не виден (X-09).
"""
from __future__ import annotations

from gatekeeper.cli import output
from gatekeeper.server.audit.anchor import load_anchors
from gatekeeper.server.audit.verify import verify_all_segments, verify_file
from gatekeeper.store.layout import Layout


def run(args, layout: Layout) -> int:
    anchors = load_anchors(args.anchors) if getattr(args, "anchors", None) else None
    if getattr(args, "all_segments", False):
        segments = verify_all_segments(layout.audit_log, anchors=anchors)
        for seg in segments:
            if not seg.result.ok:
                where = f" (line {seg.result.line_no})" if seg.result.line_no else ""
                output.error(f"audit chain BROKEN in {seg.segment}{where}: {seg.result.error}")
                return 2
        total = sum(seg.result.count for seg in segments)
        output.info(f"OK: {total} records in {len(segments)} segments")
        return 0
    res = verify_file(layout.audit_log, anchors=anchors)
    if res.ok:
        extra = f", anchors checked: {res.anchors_checked}" if anchors else ""
        output.info(f"OK: {res.count} records, head checked: {res.head_checked}{extra}")
        return 0
    where = f" (line {res.line_no})" if res.line_no else ""
    output.error(f"audit chain BROKEN{where}: {res.error}")
    return 2
