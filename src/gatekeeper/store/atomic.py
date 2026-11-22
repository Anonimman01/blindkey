"""Атомарная запись приватного файла: tmp + fsync, rename, fsync каталога.

fsync каталога нужен, чтобы сам rename пережил потерю питания. Без него отозванный клиент
или заморозка могли откатиться к предыдущей версии файла.
"""
from __future__ import annotations

import os
from pathlib import Path

from gatekeeper.server.audit.sink import _fsync_dir

_BINARY = getattr(os, "O_BINARY", 0)


def atomic_write_private(path: str | os.PathLike, data: bytes) -> None:
    """Записывает файл с правами 0600 так, чтобы результат пережил сбой питания."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _BINARY, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    _fsync_dir(path.parent)
