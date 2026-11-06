"""gatekeeper audit-anchor: проверить журнал и выдать якорь головы цепочки.

Якорь печатается в stdout (его можно переслать куда угодно: `... | ssh host 'cat >> anchors.log'`)
и, с --out, дописывается в файл. Файл имеет смысл держать вне каталога данных шлюза.
Код возврата: 0 = якорь выдан, 2 = цепочка журнала повреждена, 1 = журнал пуст.
"""
from __future__ import annotations

from gatekeeper.cli import output
from gatekeeper.core.timeutil import unix_now
from gatekeeper.server.audit.anchor import Anchor, append_anchor, serialize_anchor
from gatekeeper.server.audit.verify import verify_file
from gatekeeper.store.layout import Layout


def run(args, layout: Layout) -> int:
    res = verify_file(layout.audit_log)
    if not res.ok:
        where = f" (line {res.line_no})" if res.line_no else ""
        output.error(f"audit chain BROKEN{where}: {res.error}; anchor not issued")
        return 2
    if res.count == 0:
        output.error("audit log is empty: nothing to anchor")
        return 1
    anchor = Anchor(res.last_seq, res.last_hash, unix_now())
    if args.out:
        append_anchor(args.out, anchor)
    output.info(serialize_anchor(anchor))
    return 0
