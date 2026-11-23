"""audit-verify --all-segments: все сегменты по порядку, первый сбой называется по имени."""
from gatekeeper.cli.main import build_parser
from gatekeeper.core.events import EventType
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.audit.verify import verify_all_segments, verify_file


def make_log(tmp_path):
    chain = AuditChain(FileSink(tmp_path / "audit.log"), max_bytes=800, keep=10)
    for i in range(40):
        chain.append(EventType.SERVER_STARTED, {"i": i})
    return tmp_path / "audit.log"


def archives(path):
    return sorted(p for p in path.parent.iterdir()
                  if p.name.startswith("audit.log.") and p.name[-1].isdigit())


def test_all_segments_are_verified_in_order(tmp_path):
    path = make_log(tmp_path)
    segs = verify_all_segments(path)
    assert len(segs) > 1
    assert all(s.result.ok for s in segs)
    assert segs[-1].segment == "audit.log"
    assert [s.segment for s in segs[:-1]] == [p.name for p in archives(path)]


def test_tampered_segment_is_named(tmp_path):
    path = make_log(tmp_path)
    victim = archives(path)[0]
    data = victim.read_bytes()
    cut = len(data) // 2
    victim.write_bytes(data[:cut] + b"X" + data[cut + 1:])
    segs = verify_all_segments(path)
    assert segs[-1].segment == victim.name
    assert not segs[-1].result.ok
    assert verify_file(path).ok  # текущий журнал цел: без флага сбой не виден


def test_archive_without_head_is_an_error(tmp_path):
    """Без .head сегмент нечем проверить: это ошибка, а не «пропустить» (fail closed)."""
    path = make_log(tmp_path)
    victim = archives(path)[0]
    victim.with_name(victim.name + ".head").unlink()
    segs = verify_all_segments(path)
    assert segs[-1].segment == victim.name
    assert not segs[-1].result.ok
    assert segs[-1].result.code == "missing_head"


def test_flag_is_parsed_and_default_is_off():
    assert build_parser().parse_args(["audit-verify", "--all-segments"]).all_segments is True
    assert build_parser().parse_args(["audit-verify"]).all_segments is False
