import json
import os
import threading

import pytest

from gatekeeper.core.errors import AuditError
from gatekeeper.core.events import EventType, Severity
from gatekeeper.server.audit.chain import GENESIS_HASH, AuditChain, serialize_record
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.audit.verify import verify_file


@pytest.fixture
def paths(tmp_path):
    return tmp_path / "audit" / "audit.log", tmp_path / "audit" / "chain.head"


def make_chain(paths, n=5):
    log, head = paths
    chain = AuditChain(FileSink(log, head), clock=lambda: 1_700_000_000)
    for i in range(n):
        chain.append(EventType.REQUEST_OK, {"i": i, "client": "bot-1"})
    return chain


def read_lines(log):
    return log.read_bytes().split(b"\n")[:-1]


def write_lines(log, lines):
    log.write_bytes(b"\n".join(lines) + b"\n")


def dump(rec):
    return json.dumps(rec, sort_keys=True, separators=(",", ":")).encode()


def test_empty_log_is_ok(paths):
    res = verify_file(*paths)
    assert res.ok and res.count == 0


def test_append_and_verify(paths):
    make_chain(paths, 5)
    res = verify_file(*paths)
    assert res.ok and res.count == 5 and res.last_seq == 4 and res.head_checked


def test_records_are_linked(paths):
    make_chain(paths, 3)
    recs = [json.loads(l) for l in read_lines(paths[0])]
    assert recs[0]["prev"] == GENESIS_HASH
    assert recs[1]["prev"] == recs[0]["hash"]
    assert recs[2]["prev"] == recs[1]["hash"]
    assert [r["seq"] for r in recs] == [0, 1, 2]


def test_reopen_continues_chain(paths):
    make_chain(paths, 3)
    chain = AuditChain(FileSink(*paths), clock=lambda: 1)
    chain.append(EventType.DENY_REPLAY, severity=Severity.WARNING)
    res = verify_file(*paths)
    assert res.ok and res.count == 4


def test_edit_record_breaks_chain(paths):
    make_chain(paths, 5)
    lines = read_lines(paths[0])
    rec = json.loads(lines[2])
    rec["data"]["client"] = "someone-else"
    lines[2] = dump(rec)
    write_lines(paths[0], lines)
    res = verify_file(*paths)
    assert not res.ok and res.line_no == 3


def test_delete_middle_record_breaks_chain(paths):
    make_chain(paths, 5)
    lines = read_lines(paths[0])
    del lines[2]
    write_lines(paths[0], lines)
    res = verify_file(*paths)
    assert not res.ok and res.line_no == 3


def test_swap_records_breaks_chain(paths):
    make_chain(paths, 5)
    lines = read_lines(paths[0])
    lines[1], lines[2] = lines[2], lines[1]
    write_lines(paths[0], lines)
    assert not verify_file(*paths).ok


def test_delete_first_record_breaks_chain(paths):
    make_chain(paths, 3)
    write_lines(paths[0], read_lines(paths[0])[1:])
    assert not verify_file(*paths).ok


def test_tail_truncation_caught_by_head(paths):
    make_chain(paths, 5)
    write_lines(paths[0], read_lines(paths[0])[:3])
    res = verify_file(*paths)
    assert not res.ok and "shorter" in res.error


def test_tail_truncation_without_head_is_not_detected(paths):
    # Известное ограничение: без chain.head/якорей хвост можно отрезать незаметно.
    make_chain(paths, 5)
    write_lines(paths[0], read_lines(paths[0])[:3])
    paths[1].unlink()
    res = verify_file(*paths)
    assert res.ok and not res.head_checked


def test_full_rewrite_detected_only_by_old_head(paths):
    # Известное ограничение: взломщик с доступом к журналу может пересчитать всю цепочку.
    make_chain(paths, 4)
    old_head = paths[1].read_text()
    prev = GENESIS_HASH
    lines = []
    for i in range(4):
        line, prev = serialize_record(i, 1_700_000_000, "request_ok", "info",
                                      {"i": i, "client": "FORGED"}, prev)
        lines.append(line)
    write_lines(paths[0], lines)
    paths[1].unlink()
    assert verify_file(*paths).ok            # без внешней головы не поймать
    paths[1].write_text(old_head)            # со старой головой (якорь) ловится
    assert not verify_file(*paths).ok


def test_head_lag_after_crash_is_tolerated(paths):
    make_chain(paths, 3)
    lines = read_lines(paths[0])
    paths[1].write_text(f"1 {json.loads(lines[1])['hash']}\n")
    res = verify_file(*paths)
    assert res.ok and res.head_checked


def test_wrong_head_hash_fails(paths):
    make_chain(paths, 3)
    paths[1].write_text(f"2 {'0' * 64}\n")
    assert not verify_file(*paths).ok


@pytest.mark.parametrize("junk", [b"not json", b"[]", b'{"a":1}', b"\xff\xfe", b""])
def test_garbage_line_fails(paths, junk):
    make_chain(paths, 2)
    lines = read_lines(paths[0])
    lines.insert(1, junk)
    write_lines(paths[0], lines)
    assert not verify_file(*paths).ok


def test_extra_field_fails(paths):
    make_chain(paths, 2)
    lines = read_lines(paths[0])
    rec = json.loads(lines[1])
    rec["extra"] = 1
    lines[1] = dump(rec)
    write_lines(paths[0], lines)
    assert not verify_file(*paths).ok


def test_non_canonical_whitespace_fails(paths):
    make_chain(paths, 2)
    lines = read_lines(paths[0])
    lines[1] = json.dumps(json.loads(lines[1]), sort_keys=True).encode()  # с пробелами
    write_lines(paths[0], lines)
    res = verify_file(*paths)
    assert not res.ok and "canonical" in res.error


def test_incomplete_last_line_fails(paths):
    make_chain(paths, 2)
    with open(paths[0], "ab") as f:
        f.write(b'{"seq":2')
    assert not verify_file(*paths).ok


def test_open_refuses_tampered_log(paths):
    make_chain(paths, 3)
    lines = read_lines(paths[0])
    del lines[1]
    write_lines(paths[0], lines)
    with pytest.raises(AuditError):
        AuditChain(FileSink(*paths))


def test_non_serializable_data_rejected(paths):
    chain = make_chain(paths, 1)
    with pytest.raises(AuditError):
        chain.append("x", {"bad": object()})
    with pytest.raises(AuditError):
        chain.append("x", {"bad": float("nan")})
    with pytest.raises(AuditError):
        chain.append("x", "not a dict")
    assert verify_file(*paths).ok  # неудачные записи не испортили журнал


def test_unicode_data_roundtrip(paths):
    chain = make_chain(paths, 0)
    chain.append("x", {"text": "привет \u2028 \n"})
    assert verify_file(*paths).ok


def test_concurrent_appends(paths):
    chain = make_chain(paths, 0)

    def work():
        for i in range(25):
            chain.append(EventType.REQUEST_OK, {"i": i})

    threads = [threading.Thread(target=work) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    res = verify_file(*paths)
    assert res.ok and res.count == 200


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_files_are_0600(paths):
    make_chain(paths, 1)
    assert oct(paths[0].stat().st_mode & 0o777) == "0o600"
    assert oct(paths[1].stat().st_mode & 0o777) == "0o600"


# ---------- несколько процессов / несколько AuditChain на одном журнале ----------

def test_two_chains_interleaved_stay_one_chain(paths):
    a = AuditChain(FileSink(*paths), clock=lambda: 1)
    b = AuditChain(FileSink(*paths), clock=lambda: 1)
    for i in range(3):
        a.append(EventType.REQUEST_OK, {"w": "a", "i": i})
        b.append(EventType.CLIENT_ADDED, {"w": "b", "i": i})
    res = verify_file(*paths)
    assert res.ok and res.count == 6 and res.head_checked
    assert [json.loads(l)["seq"] for l in read_lines(paths[0])] == list(range(6))


def test_server_chain_survives_cli_write_in_between(paths):
    # Исходная ошибка: шлюз открыл журнал, add-client дописал запись, шлюз продолжил писать.
    server = AuditChain(FileSink(*paths), clock=lambda: 1)
    server.append(EventType.SERVER_STARTED)
    AuditChain(FileSink(*paths), clock=lambda: 1).append(EventType.CLIENT_ADDED, {"client": "x"})
    server.append(EventType.REQUEST_OK)
    assert verify_file(*paths).ok
    # и новый процесс, открывшийся позже, тоже видит целую цепочку
    AuditChain(FileSink(*paths), clock=lambda: 1).append(EventType.DENY_REPLAY)
    assert verify_file(*paths).count == 4


_WRITER = (
    "import sys\n"
    "from gatekeeper.server.audit.chain import AuditChain\n"
    "from gatekeeper.server.audit.sink import FileSink\n"
    "log, head, tag, n = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])\n"
    "chain = AuditChain(FileSink(log, head))\n"
    "for i in range(n):\n"
    "    chain.append('request_ok', {'w': tag, 'i': i})\n"
)


def test_parallel_processes_keep_chain_valid(paths):
    import subprocess
    import sys

    import os
    from pathlib import Path

    import gatekeeper

    # дочерним процессам нужен путь к пакету (src-layout, пакет может быть не установлен)
    src = str(Path(gatekeeper.__file__).resolve().parents[1])
    env = dict(os.environ)
    env["PYTHONPATH"] = src + os.pathsep + env.get("PYTHONPATH", "")

    log, head = paths
    FileSink(log, head)  # создать каталог
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _WRITER, str(log), str(head), f"p{k}", "25"], env=env
        )
        for k in range(4)
    ]
    assert all(p.wait(timeout=120) == 0 for p in procs)
    res = verify_file(log, head)
    assert res.ok and res.count == 100 and res.head_checked
    recs = [json.loads(l) for l in read_lines(log)]
    for k in range(4):  # у каждого процесса порядок его записей сохранён
        assert [r["data"]["i"] for r in recs if r["data"]["w"] == f"p{k}"] == list(range(25))


def test_append_detects_truncated_log(paths):
    chain = make_chain(paths, 3)
    write_lines(paths[0], read_lines(paths[0])[:1])
    with pytest.raises(AuditError, match="truncated"):
        chain.append(EventType.REQUEST_OK)
    assert len(read_lines(paths[0])) == 1  # ничего не дописано


def test_append_refuses_foreign_garbage_in_log(paths):
    chain = make_chain(paths, 2)
    with open(paths[0], "ab") as f:
        f.write(b"this is not a record\n")
    before = paths[0].read_bytes()
    with pytest.raises(AuditError, match="verification"):
        chain.append(EventType.REQUEST_OK)
    assert paths[0].read_bytes() == before


def test_append_refuses_forged_foreign_record(paths):
    chain = make_chain(paths, 2)
    bad, _ = serialize_record(2, 1, "request_ok", "info", {}, "f" * 64)  # чужой prev
    with open(paths[0], "ab") as f:
        f.write(bad + b"\n")
    with pytest.raises(AuditError):
        chain.append(EventType.REQUEST_OK)


def test_lock_is_exclusive_and_times_out(paths):
    holder, other = FileSink(*paths), FileSink(*paths)
    with holder.locked():
        with pytest.raises(AuditError, match="timeout"):
            with other.locked(timeout=0.1):
                pass
        with other.locked(required=False, timeout=0.1) as got:
            assert got is False  # чтение без замка допустимо
    with other.locked(timeout=1) as got:  # после снятия берётся
        assert got is True

