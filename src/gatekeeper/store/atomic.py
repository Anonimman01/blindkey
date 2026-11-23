"""Атомарная запись приватного файла: tmp + fsync, rename, fsync каталога.

fsync каталога нужен, чтобы сам rename пережил потерю питания. Без него отозванный клиент
или заморозка могли откатиться к предыдущей версии файла.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from gatekeeper.core import fileio
from gatekeeper.core.fileio import write_all as write_all  # реэкспорт для прежних импортов
from gatekeeper.server.audit.sink import _fsync_dir

_BINARY = getattr(os, "O_BINARY", 0)


def atomic_write_private(path: str | os.PathLike, data: bytes) -> None:
    """Записывает файл с правами 0600 так, чтобы результат пережил сбой питания.

    Временный файл создаёт mkstemp в том же каталоге: имя непредсказуемо, а O_EXCL внутри
    mkstemp не даёт открыть подложенный симлинк с предсказуемым именем `<файл>.tmp`.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            fileio.write_all(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)  # сбой до replace: не оставляем файл с секретом
        raise
    _fsync_dir(path.parent)
