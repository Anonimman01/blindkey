"""audit/sink.py: запись, чтение, голова цепочки, усечение и ошибки."""
import os

import pytest

from gatekeeper.core.errors import AuditError
from gatekeeper.server.audit.sink import FileSink

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")


def test_append_read_and_size(tmp_path):
    sink = FileSink(tmp_path / "a" / "audit.log")
    sink.append_line(b'{"a":1}')
    sink.append_lines([b'{"b":2}', b'{"c":3}'])
    data = sink.read_bytes()
    assert data == b'{"a":1}\n{"b":2}\n{"c":3}\n'
    assert sink.size() == len(data)
    assert sink.read_range(0, 8) == b'{"a":1}\n'
    assert sink.read_range(4, 100) == data[4:]


def test_missing_files_are_empty(tmp_path):
    sink = FileSink(tmp_path / "a" / "audit.log")
    assert sink.size() == 0
    assert sink.read_bytes() == b""
    assert sink.read_range(0, 10) == b""
    assert sink.read_head() is None


def test_head_roundtrip_and_malformed(tmp_path):
    sink = FileSink(tmp_path / "a" / "audit.log")
    sink.write_head(7, "ab" * 32)
    assert sink.read_head() == (7, "ab" * 32)
    head = tmp_path / "a" / "chain.head"
    for bad in ("7 zz\n", "abc " + "a" * 64 + "\n", "7\n"):
        head.write_text(bad, "ascii")
        with pytest.raises(AuditError, match="malformed"):
            sink.read_head()


def test_truncate_cuts_the_file(tmp_path):
    sink = FileSink(tmp_path / "a" / "audit.log")
    sink.append_lines([b"one", b"two", b"three"])
    sink.truncate(len(b"one\ntwo\n"))
    assert sink.read_bytes() == b"one\ntwo\n"


def test_truncate_missing_file_raises(tmp_path):
    sink = FileSink(tmp_path / "a" / "audit.log")
    with pytest.raises(AuditError, match="missing"):
        sink.truncate(0)


def test_newline_inside_line_is_rejected(tmp_path):
    sink = FileSink(tmp_path / "a" / "audit.log")
    with pytest.raises(AuditError, match="newline"):
        sink.append_line(b"a\nb")


def test_lock_can_be_taken(tmp_path):
    sink = FileSink(tmp_path / "a" / "audit.log")
    with sink.locked() as got:
        assert got is True


@posix_only
def test_append_on_preexisting_loose_file_resets_mode(tmp_path):
    sink = FileSink(tmp_path / "a" / "audit.log")
    sink.path.write_bytes(b"")
    sink.path.chmod(0o644)
    sink.append_line(b"x")
    assert (sink.path.stat().st_mode & 0o777) == 0o600
