"""Проверка и приведение прав файлов данных (аудит 0.3.3: N-03, GK-04, GK-05).

`os.open(..., O_CREAT, 0o600)` действует только при создании: уже существующий файл с 0644
(бэкап, `cp` без `-p`, umask 022) остался бы читаемым для группы/остальных. Эта функция при
старте приводит режим к 0600, а подозрительные случаи (симлинк, не обычный файл, чужой
владелец) считает ошибкой. На Windows не проверяется.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from gatekeeper.core.errors import GatekeeperError

_SIDECARS = ("-wal", "-shm", "-journal")


class FilePermissionError(GatekeeperError):
    """Файл данных нельзя использовать безопасно (тип, владелец, права)."""


def harden_private_file(path: str | os.PathLike, *, missing_ok: bool = True) -> None:
    """Файл должен быть обычным, принадлежать текущему пользователю и иметь режим 0600.

    Лишние биты режима снимаются (chmod 0600). Символьная ссылка, не обычный файл или чужой
    владелец — FilePermissionError. Отсутствующий файл допустим (создастся с 0600).
    """
    if os.name == "nt":
        return
    p = os.fspath(path)
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        if missing_ok:
            return
        raise FilePermissionError(f"{Path(p).name} is missing") from None
    name = Path(p).name
    if stat.S_ISLNK(st.st_mode):
        raise FilePermissionError(f"{name} must not be a symlink")
    if not stat.S_ISREG(st.st_mode):
        raise FilePermissionError(f"{name} is not a regular file")
    if st.st_uid != os.geteuid():  # type: ignore[attr-defined,unused-ignore]
        raise FilePermissionError(f"{name} must be owned by the user running gatekeeper")
    if stat.S_IMODE(st.st_mode) != 0o600:
        os.chmod(p, 0o600)


def harden_sqlite_files(path: str | os.PathLike) -> None:
    """state.db и его -wal/-shm/-journal."""
    harden_private_file(path)
    for suffix in _SIDECARS:
        harden_private_file(os.fspath(path) + suffix)
