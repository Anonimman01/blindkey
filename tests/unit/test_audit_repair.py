"""B-02 (оборванная последняя строка) и C-06 (ротация журнала)."""
import json

import pytest

from gatekeeper.cli.main import main
from gatekeeper.core.errors import AuditError
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.repair import truncate_incomplete_tail
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.audit.verify import verify_file


def _sink(tmp_path) -> FileSink:
    return FileSink(tmp_path / "audit" / "audit.log", tmp_path / "audit" / "chain.head")


def _records(sink: FileSink) -> list[dict]:
    return [json.loads(line) for line in sink.path.read_text().splitlines()]


def test_chain_repairs_unfinished_tail_and_logs_event(tmp_path):
    sink = _sink(tmp_path)
    chain = AuditChain(sink, clock=lambda: 100, repair_tail=True)
    chain.append("request_ok", {"i": 1})
    with open(sink.path, "ab") as f:
        f.write(b'{"seq":1,"ts":100')
    reopened = AuditChain(sink, repair_tail=True, clock=lambda: 101)
    assert reopened.next_seq == 2
    assert verify_file(sink.path, sink.head_path).ok
    records = _records(sink)
    assert records[-1]["type"] == "audit_tail_repaired"
    assert records[-1]["data"]["removed_bytes"] == len(b'{"seq":1,"ts":100')


def test_strict_chain_still_refuses_unfinished_tail(tmp_path):
    sink = _sink(tmp_path)
    AuditChain(sink).append("request_ok", {"i": 1})
    with open(sink.path, "ab") as f:
        f.write(b'{"seq":1')
    with pytest.raises(AuditError):
        AuditChain(sink)
    assert not verify_file(sink.path, sink.head_path).ok


def test_repair_does_not_truncate_a_file_without_records(tmp_path):
    sink = FileSink(tmp_path / "audit" / "audit.log")
    sink.path.write_bytes(b"not a record")
    with sink.locked(), pytest.raises(AuditError, match="no complete record"):
        truncate_incomplete_tail(sink)


def test_cli_audit_repair(tmp_path, capsys):
    base = ["--config-dir", str(tmp_path / "cfg"), "--data-dir", str(tmp_path / "data")]
    cakey = tmp_path / "off" / "ca.key"
    cakey.parent.mkdir()
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(cakey)]) == 0
    log = tmp_path / "data" / "audit" / "audit.log"
    log.write_bytes(log.read_bytes() + b'{"seq":99')
    assert main([*base, "audit-verify"]) == 2
    assert main([*base, "audit-repair"]) == 0
    assert main([*base, "audit-verify"]) == 0
    assert "audit_tail_repaired" in log.read_text()
    capsys.readouterr()
    assert main([*base, "audit-repair"]) == 0
    assert "nothing to repair" in capsys.readouterr().out


def test_cli_audit_repair_refuses_other_damage(tmp_path, capsys):
    base = ["--config-dir", str(tmp_path / "cfg"), "--data-dir", str(tmp_path / "data")]
    cakey = tmp_path / "off" / "ca.key"
    cakey.parent.mkdir()
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(cakey)]) == 0
    log = tmp_path / "data" / "audit" / "audit.log"
    log.write_bytes(log.read_bytes().replace(b"init", b"hack"))
    assert main([*base, "audit-repair"]) == 2
    assert "cannot repair automatically" in capsys.readouterr().err


def test_rotation_starts_a_verifiable_new_segment(tmp_path):
    sink = _sink(tmp_path)
    chain = AuditChain(sink, clock=lambda: 1_700_000_000, max_bytes=1, keep=2)
    chain.append("request_ok", {"i": 1})
    chain.append("request_ok", {"i": 2})
    res = verify_file(sink.path, sink.head_path)
    assert res.ok and res.count == 2
    records = _records(sink)
    assert records[0]["type"] == "audit_segment_started"
    assert records[0]["data"]["previous_seq"] == 0
    assert records[1]["seq"] == 1          # нумерация продолжилась в новом сегменте
    archives = [p for p in sink.path.parent.iterdir()
                if p.name.startswith("audit.log.") and p.name[-1].isdigit()]
    assert len(archives) == 1
    # Архив остаётся самостоятельной цепочкой: рядом лежит его собственная голова.
    archive_head = archives[0].with_name(archives[0].name + ".head")
    assert verify_file(archives[0], archive_head).ok


def test_rotation_keeps_only_configured_number_of_archives(tmp_path):
    sink = _sink(tmp_path)
    chain = AuditChain(sink, clock=lambda: 1_700_000_000, max_bytes=1, keep=2)
    for i in range(6):
        chain.append("request_ok", {"i": i})
    archives = [p for p in sink.path.parent.iterdir()
                if p.name.startswith("audit.log.") and p.name[-1].isdigit()]
    assert len(archives) <= 2
    assert verify_file(sink.path, sink.head_path).ok


def test_second_process_accepts_rotation_by_another_process(tmp_path):
    sink = _sink(tmp_path)
    writer = AuditChain(sink, clock=lambda: 1_700_000_000, max_bytes=1)
    other = AuditChain(sink, clock=lambda: 1_700_000_000)
    writer.append("request_ok", {"who": "writer"})
    other.append("request_ok", {"who": "other"})
    writer.append("request_ok", {"who": "writer"})  # ротация здесь
    # «другой» процесс видит укоротившийся журнал и перепроверяет его, а не падает.
    result = other.append("request_ok", {"who": "other"})
    assert isinstance(result["seq"], int)
    assert verify_file(sink.path, sink.head_path).ok
