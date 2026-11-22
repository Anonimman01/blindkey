"""gatekeeper audit-repair: убрать недописанную последнюю строку журнала (B-02).

Оборванная запись не была подтверждена клиенту (fsync не прошёл), поэтому её можно отрезать
по последнему `\\n`. В журнал пишется `audit_tail_repaired` с числом и SHA-256 удалённых байт,
так что правка не остаётся незамеченной. Другие повреждения (правка, удаление, разрыв
цепочки) не чинятся: команда сообщает об ошибке и возвращает 2.

Шлюз делает то же самое сам при старте (`repair_tail=True`), команда нужна, если шлюз
остановлен и нужно проверить состояние до запуска.
"""
from __future__ import annotations

from gatekeeper.cli import output
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.events import EventType, Severity
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.repair import truncate_incomplete_tail
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.audit.verify import verify_file
from gatekeeper.store.layout import Layout


def run(args, layout: Layout) -> int:
    sink = FileSink(layout.audit_log)
    repair = None
    try:
        with sink.locked():
            res = verify_file(sink.path, sink.head_path, lock=False)
            if res.ok:
                output.info(f"audit log is intact: {res.count} records, nothing to repair")
                return 0
            if res.code != "incomplete_tail":
                where = f" (line {res.line_no})" if res.line_no else ""
                output.error(f"cannot repair automatically{where}: {res.error}")
                return 2
            repair = truncate_incomplete_tail(sink)
            res = verify_file(sink.path, sink.head_path, lock=False)
            if not res.ok:
                output.error(f"tail was removed, but the chain is still broken: {res.error}")
                return 2
        AuditChain(sink).append(
            EventType.AUDIT_TAIL_REPAIRED,
            {"removed_bytes": repair.removed_bytes, "removed_sha256": repair.removed_sha256,
             "action": "audit-repair"},
            Severity.WARNING)
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1
    output.info(f"removed {repair.removed_bytes} bytes of an incomplete last line "
                f"(sha256 {repair.removed_sha256[:16]}); recorded as audit_tail_repaired")
    output.info("run `gatekeeper audit-verify` and issue a fresh anchor (`gatekeeper audit-anchor`)")
    return 0
