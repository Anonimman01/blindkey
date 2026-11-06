import json

import pytest

from gatekeeper.cli.main import main
from gatekeeper.core.errors import AuditError
from gatekeeper.core.events import EventType
from gatekeeper.server.audit.anchor import (
    Anchor, append_anchor, load_anchors, parse_anchors, serialize_anchor,
)
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.audit.verify import verify_file

H = "ab" * 32


@pytest.fixture
def paths(tmp_path):
    return tmp_path / "audit" / "audit.log", tmp_path / "audit" / "chain.head"


def make_chain(paths, n=5):
    log, head = paths
    chain = AuditChain(FileSink(log, head), clock=lambda: 1_700_000_000)
    for i in range(n):
        chain.append(EventType.REQUEST_OK, {"i": i})
    return chain


def anchor_at(paths, seq):
    rec = json.loads(paths[0].read_bytes().split(b"\n")[seq])
    return Anchor(seq, rec["hash"], 1_700_000_000)


def rewrite_whole_log(paths, n):
    """Взломщик с правом записи: стирает журнал и chain.head и пишет свою цепочку."""
    paths[0].unlink()
    paths[1].unlink()
    chain = AuditChain(FileSink(*paths), clock=lambda: 1_700_000_001)
    for i in range(n):
        chain.append(EventType.REQUEST_OK, {"forged": i})


# --- формат ---

def test_serialize_parse_roundtrip():
    a = Anchor(7, H, 1_700_000_000)
    assert parse_anchors(serialize_anchor(a) + "\n") == [a]


def test_parse_skips_blank_lines_and_crlf():
    a, b = Anchor(1, H, 1), Anchor(2, H, 2)
    text = serialize_anchor(a) + "\r\n\r\n" + serialize_anchor(b) + "\r\n"
    assert parse_anchors(text) == [a, b]


@pytest.mark.parametrize("bad", [
    "",
    "\n\n",
    "not json",
    "[]",
    json.dumps({"seq": 1, "ts": 1}),
    json.dumps({"seq": 1, "ts": 1, "hash": H, "x": 1}),
    json.dumps({"seq": True, "ts": 1, "hash": H}),
    json.dumps({"seq": -1, "ts": 1, "hash": H}),
    json.dumps({"seq": 1, "ts": "1", "hash": H}),
    json.dumps({"seq": 1, "ts": 1, "hash": "AB" * 32}),
    json.dumps({"seq": 1, "ts": 1, "hash": "ab" * 31}),
])
def test_parse_rejects_bad_input(bad):
    with pytest.raises(AuditError):
        parse_anchors(bad)


def test_load_missing_file(tmp_path):
    with pytest.raises(AuditError):
        load_anchors(tmp_path / "nope.log")


def test_append_anchor_appends_lines(tmp_path):
    f = tmp_path / "anchors.log"
    append_anchor(f, Anchor(1, H, 1))
    append_anchor(f, Anchor(2, H, 2))
    assert [a.seq for a in load_anchors(f)] == [1, 2]


# --- сверка журнала ---

def test_matching_anchors_pass(paths):
    make_chain(paths, 5)
    res = verify_file(*paths, anchors=[anchor_at(paths, 2), anchor_at(paths, 4)])
    assert res.ok and res.anchors_checked == 2 and res.head_checked


def test_no_anchors_keeps_old_behaviour(paths):
    make_chain(paths, 3)
    res = verify_file(*paths)
    assert res.ok and res.anchors_checked == 0


def test_log_may_grow_after_anchor(paths):
    chain = make_chain(paths, 3)
    anchor = anchor_at(paths, 2)
    chain.append(EventType.REQUEST_OK, {"i": 3})
    assert verify_file(*paths, anchors=[anchor]).ok


def test_tail_removed_with_head_rewritten_is_caught(paths):
    make_chain(paths, 5)
    anchor = anchor_at(paths, 4)
    lines = paths[0].read_bytes().split(b"\n")[:-1]
    paths[0].write_bytes(b"\n".join(lines[:3]) + b"\n")
    rec = json.loads(lines[2])
    paths[1].write_text(f"2 {rec['hash']}\n", "ascii")
    # без якорей подмена не видна
    assert verify_file(*paths).ok
    res = verify_file(*paths, anchors=[anchor])
    assert not res.ok and "tail removed" in res.error


def test_full_rewrite_is_caught(paths):
    make_chain(paths, 5)
    anchor = anchor_at(paths, 4)
    rewrite_whole_log(paths, 6)
    assert verify_file(*paths).ok  # цепочка и head согласованы сами с собой
    res = verify_file(*paths, anchors=[anchor])
    assert not res.ok and "rewritten" in res.error


def test_anchor_for_empty_log_fails(paths):
    paths[0].parent.mkdir(parents=True)
    res = verify_file(*paths, anchors=[Anchor(0, H, 1)])
    assert not res.ok


# --- CLI ---

def run_cli(tmp_path, *argv):
    return main(["--config-dir", str(tmp_path / "etc"), "--data-dir", str(tmp_path), *argv])


def test_cli_anchor_then_verify(tmp_path, capsys):
    make_chain((tmp_path / "audit" / "audit.log", tmp_path / "audit" / "chain.head"), 4)
    out_file = tmp_path / "elsewhere" / "anchors.log"
    out_file.parent.mkdir()
    assert run_cli(tmp_path, "audit-anchor", "--out", str(out_file)) == 0
    printed = capsys.readouterr().out.strip()
    assert parse_anchors(printed)[0].seq == 3
    assert parse_anchors(out_file.read_text()) == parse_anchors(printed)
    assert run_cli(tmp_path, "audit-verify", "--anchors", str(out_file)) == 0
    assert "anchors checked: 1" in capsys.readouterr().out


def test_cli_verify_without_anchors_output_unchanged(tmp_path, capsys):
    make_chain((tmp_path / "audit" / "audit.log", tmp_path / "audit" / "chain.head"), 2)
    assert run_cli(tmp_path, "audit-verify") == 0
    assert capsys.readouterr().out.strip() == "OK: 2 records, head checked: True"


def test_cli_verify_detects_rewrite(tmp_path, capsys):
    p = (tmp_path / "audit" / "audit.log", tmp_path / "audit" / "chain.head")
    make_chain(p, 4)
    out_file = tmp_path / "anchors.log"
    assert run_cli(tmp_path, "audit-anchor", "--out", str(out_file)) == 0
    rewrite_whole_log(p, 4)
    capsys.readouterr()
    assert run_cli(tmp_path, "audit-verify", "--anchors", str(out_file)) == 2
    assert "rewritten" in capsys.readouterr().err


def test_cli_anchor_on_empty_log(tmp_path, capsys):
    assert run_cli(tmp_path, "audit-anchor") == 1
    assert "nothing to anchor" in capsys.readouterr().err


def test_cli_anchor_refuses_broken_chain(tmp_path, capsys):
    p = (tmp_path / "audit" / "audit.log", tmp_path / "audit" / "chain.head")
    make_chain(p, 3)
    lines = p[0].read_bytes().split(b"\n")[:-1]
    p[0].write_bytes(b"\n".join([lines[0], lines[2]]) + b"\n")
    out_file = tmp_path / "anchors.log"
    assert run_cli(tmp_path, "audit-anchor", "--out", str(out_file)) == 2
    assert not out_file.exists()


def test_cli_verify_bad_anchor_file(tmp_path, capsys):
    make_chain((tmp_path / "audit" / "audit.log", tmp_path / "audit" / "chain.head"), 2)
    bad = tmp_path / "anchors.log"
    bad.write_text("garbage\n")
    assert run_cli(tmp_path, "audit-verify", "--anchors", str(bad)) == 1
