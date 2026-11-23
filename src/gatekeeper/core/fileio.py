"""Низкоуровневая запись в файловый дескриптор без циклов импорта.

`os.write` может записать лишь часть буфера (short write) и прерывается сигналом
(InterruptedError). Раньше это учитывали только в `audit/sink.py`, а остальные места
(`atomic`, `rotate`, `anchor`, `pki/ca`) писали одним вызовом и могли потерять хвост
секрета или записи журнала (X-06). Функция живёт в `core`, потому что `store.atomic`
импортирует `_fsync_dir` из `server.audit.sink`: если бы `sink` импортировал её обратно
из `store.atomic`, получился бы цикл.
"""
from __future__ import annotations

import os


def write_all(fd: int, data: bytes) -> None:
    """Записать все байты в дескриптор: повторы при short write и InterruptedError."""
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except InterruptedError:
            continue
        if n == 0:
            raise OSError("os.write returned 0")
        view = view[n:]
