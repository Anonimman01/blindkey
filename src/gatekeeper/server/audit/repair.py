"""Восстановление журнала с оборванной последней строкой (B-02).

Последняя строка `audit.log` может остаться недописанной: `kill -9`, полный диск, потеря
питания. Такая запись не могла быть подтверждена клиенту (fsync не прошёл), поэтому её
безопасно отрезать по последнему `\\n`. В журнале остаётся след правки: вызывающий пишет
событие `audit_tail_repaired` с числом и хешем удалённых байт.

Усечение не делается, если в файле нет ни одной полной строки: тогда восстанавливать нечего
и журнал нужно брать из бэкапа. Здесь только работа с файлом под уже взятым замком.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from gatekeeper.core.errors import AuditError
from gatekeeper.server.audit.sink import FileSink


@dataclass(frozen=True)
class TailRepair:
    """Что именно отрезано: размер и SHA-256 удалённого хвоста (без секретов)."""

    removed_bytes: int
    removed_sha256: str


def truncate_incomplete_tail(sink: FileSink) -> TailRepair:
    """Отрезать недописанную последнюю строку. Вызывать под `sink.locked()`."""
    data = sink.read_bytes()
    if not data:
        raise AuditError("audit log is empty")
    if data.endswith(b"\n"):
        raise AuditError("audit log ends with a complete line")
    cut = data.rfind(b"\n") + 1
    if cut == 0:
        raise AuditError(
            "audit log has no complete record: restore it from a backup instead of truncating")
    removed = data[cut:]
    sink.truncate(cut)
    return TailRepair(len(removed), hashlib.sha256(removed).hexdigest())
