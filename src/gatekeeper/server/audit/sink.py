"""Файловое хранилище журнала: права 0600, fsync после каждой записи."""
from __future__ import annotations

import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from gatekeeper.core.errors import AuditError

_BINARY = getattr(os, "O_BINARY", 0)  # Windows: не переводить \n в \r\n


def _fsync_dir(path: Path) -> None:
    """fsync каталога, чтобы rename/создание файла пережили сбой (не на Windows)."""
    if os.name == "nt":
        return
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _try_lock(fd: int) -> None:
    """Неблокирующая попытка взять эксклюзивный замок; OSError, если занят."""
    if os.name == "nt":
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)


def _unlock(fd: int) -> None:
    if os.name == "nt":
        import msvcrt
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)


class FileSink:
    def __init__(self, path: str | os.PathLike, head_path: str | os.PathLike | None = None):
        self.path = Path(path)
        self.head_path = Path(head_path) if head_path else self.path.parent / "chain.head"
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    @property
    def lock_path(self) -> Path:
        return self.path.with_name(self.path.name + ".lock")

    @contextmanager
    def locked(self, *, required: bool = True, timeout: float = 10.0) -> Iterator[bool]:
        """Межпроцессный эксклюзивный замок на журнал (файл <журнал>.lock).

        Замок рекомендательный (advisory): защищает от одновременной записи шлюза и CLI,
        а не от злонамеренного процесса. Снимается ОС при смерти процесса.
        required=True: не удалось взять замок за timeout секунд = AuditError.
        required=False (для чтения): не вышло, работаем без замка, значение True/False.
        """
        fd = -1
        got = False
        try:
            try:
                fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | _BINARY, 0o600)
                deadline = time.monotonic() + timeout
                while True:
                    try:
                        _try_lock(fd)
                        got = True
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise AuditError("audit log lock timeout") from None
                        time.sleep(0.005)
            except (OSError, AuditError) as exc:
                if required:
                    if isinstance(exc, AuditError):
                        raise
                    raise AuditError("cannot open audit lock file") from exc
            yield got
        finally:
            if fd >= 0:
                if got:
                    try:
                        _unlock(fd)
                    except OSError:
                        pass
                os.close(fd)

    def size(self) -> int:
        try:
            return self.path.stat().st_size
        except FileNotFoundError:
            return 0

    def read_range(self, start: int, end: int) -> bytes:
        """Байты журнала [start, end)."""
        try:
            with open(self.path, "rb") as f:
                f.seek(start)
                return f.read(max(0, end - start))
        except FileNotFoundError:
            return b""

    def append_line(self, line: bytes) -> None:
        if b"\n" in line:
            raise AuditError("line must not contain newline")
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | _BINARY
        fd = os.open(self.path, flags, 0o600)
        try:
            os.write(fd, line + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)

    def write_head(self, seq: int, hash_hex: str) -> None:
        """Атомарно записать голову цепочки: '<seq> <hash>'."""
        tmp = self.head_path.with_name(self.head_path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _BINARY, 0o600)
        try:
            os.write(fd, f"{seq} {hash_hex}\n".encode("ascii"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.head_path)
        _fsync_dir(self.head_path.parent)

    def read_bytes(self) -> bytes:
        try:
            return self.path.read_bytes()
        except FileNotFoundError:
            return b""

    def read_head(self) -> tuple[int, str] | None:
        try:
            raw = self.head_path.read_text("ascii").strip()
        except FileNotFoundError:
            return None
        except (OSError, UnicodeDecodeError) as exc:
            raise AuditError("cannot read chain.head") from exc
        parts = raw.split(" ")
        if len(parts) != 2 or not parts[0].isdigit() or len(parts[1]) != 64:
            raise AuditError("chain.head is malformed")
        return int(parts[0]), parts[1]
