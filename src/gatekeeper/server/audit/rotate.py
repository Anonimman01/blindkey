"""Ротация журнала по размеру с сохранением проверяемости цепочки (C-06).

Каждый сегмент (`audit.log`, затем `audit.log.<unix-ts>`) это самостоятельная цепочка
от GENESIS, и её первая запись — `audit_segment_started`: имя предыдущего сегмента, его
размер, последние seq и hash. Так голова старого сегмента остаётся зафиксированной в
новом, а `audit-verify` по-прежнему проверяет текущий файл целиком.

Порядок операций рассчитан на сбой в любой точке: новая голова (seq 0) пишется до подмены
файлов, поэтому старая голова всегда не опережает журнал; недописанный новый сегмент
`audit.log.new` подбирается при следующем открытии (`recover_pending_rotation`).

Ротация выполняется только под межпроцессным замком журнала: её вызывает владелец замка.
"""
from __future__ import annotations

import contextlib
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from gatekeeper.core.errors import AuditError
from gatekeeper.core.events import EventType, Severity
from gatekeeper.core.fileio import write_all
from gatekeeper.core.timeutil import unix_now
from gatekeeper.server.audit.sink import _BINARY, FileSink, _fsync_dir

_ARCHIVE_TS = re.compile(r"^(\d+)(?:\.\d+)?$")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)  # POSIX: не идти по подложенному симлинку


@dataclass(frozen=True)
class SegmentStart:
    """Первая запись нового сегмента: seq и hash (следующая запись будет seq + 1).

    `archive`/`head` — закрытый сегмент и его голова (для хука архивации, A7): они нужны
    вызывающему уже после снятия замка, поэтому ротация возвращает их, а не запускает
    внешнюю команду сама (внешняя команда не должна держать замок журнала).
    """

    seq: int
    hash: str
    archive: Path | None = None
    head: Path | None = None


def _archive_path(sink: FileSink, ts: int) -> Path:
    base, n = sink.path.name, 0
    while True:
        suffix = f".{ts}" if n == 0 else f".{ts}.{n}"
        candidate = sink.path.with_name(base + suffix)
        if not candidate.exists():
            return candidate
        n += 1
        if n > 1000:
            raise AuditError("cannot pick an archive name for the audit log")


def _archives(sink: FileSink) -> list[tuple[int, Path]]:
    prefix = sink.path.name + "."
    out: list[tuple[int, Path]] = []
    try:
        entries = list(sink.path.parent.iterdir())
    except FileNotFoundError:
        return out
    for p in entries:
        if not p.name.startswith(prefix):
            continue
        m = _ARCHIVE_TS.fullmatch(p.name[len(prefix):])
        if m is not None:
            out.append((int(m.group(1)), p))
    return sorted(out, key=lambda t: (t[0], t[1].name))


def _prune(sink: FileSink, keep: int) -> None:
    archives = _archives(sink)
    for _ts, path in archives[:max(0, len(archives) - keep)]:
        with contextlib.suppress(OSError):
            path.unlink()  # не мешаем ротации из-за старого архива
        with contextlib.suppress(OSError):
            path.with_name(path.name + ".head").unlink()


def recover_pending_rotation(sink: FileSink) -> None:
    """Довести до конца подмену файлов, прерванную сбоем (вызывать под замком)."""
    pending = sink.path.with_name(sink.path.name + ".new")
    if not pending.exists():
        return
    if sink.path.exists():
        # Сбой до первой подмены: журнал на месте, недописанный сегмент не нужен.
        with contextlib.suppress(OSError):
            pending.unlink()
        return
    os.replace(pending, sink.path)
    _fsync_dir(sink.path.parent)


def rotate_audit_locked(
    sink: FileSink, *, keep: int, clock: Callable[[], int] = unix_now
) -> SegmentStart:
    """Ротировать журнал. Вызывать под `sink.locked()`; прерывание = AuditError."""
    from gatekeeper.server.audit.chain import GENESIS_HASH, serialize_record
    from gatekeeper.server.audit.verify import verify_file

    res = verify_file(sink.path, sink.head_path, lock=False)
    if not res.ok:
        # Битый журнал не ротируем: иначе ошибка потеряется в архиве.
        raise AuditError(f"cannot rotate a broken audit log: {res.error}")
    size = sink.size()
    head = sink.read_head()
    ts = clock()
    archive = _archive_path(sink, ts)
    data = {
        "previous_segment": archive.name,
        "previous_size": size,
        "previous_seq": res.last_seq,
        "previous_hash": res.last_hash,
    }
    if head is not None:
        data["previous_head_seq"], data["previous_head_hash"] = head
    line, digest = serialize_record(
        0, ts, EventType.AUDIT_SEGMENT_STARTED.value, Severity.INFO.value, data, GENESIS_HASH)
    pending = sink.path.with_name(sink.path.name + ".new")
    # Имя предсказуемо (его ищет recover_pending_rotation), поэтому O_NOFOLLOW обязателен.
    fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _BINARY | _NOFOLLOW, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        write_all(fd, line + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)
    # Голова нового сегмента — до подмены: при сбое посередине старая голова (0) валидна.
    sink.write_head(0, digest)
    os.replace(sink.path, archive)
    # Голова архива рядом с ним: проверять старый сегмент можно и после ротации.
    FileSink(archive, archive.with_name(archive.name + ".head")).write_head(
        res.last_seq, res.last_hash)
    os.replace(pending, sink.path)
    _fsync_dir(sink.path.parent)
    _prune(sink, keep)
    return SegmentStart(0, digest, archive, archive.with_name(archive.name + ".head"))
