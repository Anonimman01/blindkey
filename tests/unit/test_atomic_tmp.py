"""Временные файлы: непредсказуемое имя, права 0600, подложенный симлинк не используется."""
import os

import pytest

from gatekeeper.server.audit.sink import FileSink
from gatekeeper.store.atomic import atomic_write_private, write_all

pytestmark = pytest.mark.skipif(os.name == "nt", reason="симлинки и режимы — POSIX")


def test_symlink_at_old_predictable_tmp_is_not_followed(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"original")
    target = tmp_path / "clients.json"
    planted = tmp_path / "clients.json.tmp"
    planted.symlink_to(victim)
    atomic_write_private(target, b"secret")
    assert victim.read_bytes() == b"original"      # симлинк не пройден
    assert target.read_bytes() == b"secret"
    assert planted.is_symlink()
    assert not list(tmp_path.glob("clients.json.*.tmp"))  # временный файл не оставлен
    assert (target.stat().st_mode & 0o777) == 0o600


def test_chain_head_symlink_is_not_followed(tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"original")
    sink = FileSink(tmp_path / "audit.log")
    (tmp_path / "chain.head.tmp").symlink_to(victim)
    sink.write_head(3, "a" * 64)
    assert victim.read_bytes() == b"original"
    assert sink.read_head() == (3, "a" * 64)
    assert (sink.head_path.stat().st_mode & 0o777) == 0o600


def test_temp_file_is_removed_when_write_fails(tmp_path, monkeypatch):
    """Сбой до replace не должен оставлять на диске временный файл с секретом."""
    def boom(fd, data):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "write", boom)
    target = tmp_path / "state.bin"
    with pytest.raises(OSError):
        atomic_write_private(target, b"secret")
    assert not target.exists()
    assert not list(tmp_path.glob("state.bin.*.tmp"))


def test_write_all_handles_short_writes(tmp_path, monkeypatch):
    real = os.write

    def half(fd, data):
        return real(fd, bytes(data[: max(1, len(data) // 2)]))

    monkeypatch.setattr(os, "write", half)
    target = tmp_path / "state.bin"
    atomic_write_private(target, b"x" * 4096)
    assert target.read_bytes() == b"x" * 4096


def test_write_all_retries_on_interrupted_error(tmp_path, monkeypatch):
    real = os.write
    calls = []

    def flaky(fd, data):
        calls.append(1)
        if len(calls) == 1:
            raise InterruptedError
        return real(fd, data)

    monkeypatch.setattr(os, "write", flaky)
    fd = os.open(tmp_path / "f", os.O_WRONLY | os.O_CREAT, 0o600)
    try:
        write_all(fd, b"payload")
    finally:
        os.close(fd)
    assert (tmp_path / "f").read_bytes() == b"payload"
    assert len(calls) == 2
