"""A8: автоматический якорь по расписанию и счётчик записей после последнего якоря.

Якорь — это голова цепочки, записанная туда, куда взломщик со шлюза не дотягивается.
Планировщик только дописывает файл; выбор места (вне каталога данных) — задача оператора,
и `status` показывает, сколько записей после последнего якоря им не прикрыты.
"""
import asyncio
from types import SimpleNamespace

import pytest

from gatekeeper.cli.main import main
from gatekeeper.core.events import EventType
from gatekeeper.server.app import GatekeeperApp
from gatekeeper.server.audit.anchor import Anchor, append_anchor, load_anchors
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.config import ConfigError, load_config
from gatekeeper.server.http_io import HttpLimits
from gatekeeper.server.limits import ConnectionLimiter
from gatekeeper.server.nonce_cache import NonceCache


def make_app(tmp_path, anchor_file=None):
    audit = AuditChain(FileSink(tmp_path / "audit.log"))
    audit.append(EventType.SERVER_STARTED, {"action": "init"})
    return GatekeeperApp(
        pipeline=SimpleNamespace(nonces=NonceCache()), bans=SimpleNamespace(),
        limiter=ConnectionLimiter(2, 2), audit=audit, http_limits=HttpLimits(),
        ssl_ctx=None, host="127.0.0.1", port=0,
        anchor_file=str(anchor_file) if anchor_file else None, anchor_interval=60)


def test_anchor_is_the_current_head(tmp_path):
    target = tmp_path / "anchors" / "a.jsonl"
    app = make_app(tmp_path, target)
    target.parent.mkdir()
    asyncio.run(app._write_anchor())
    (anchor,) = load_anchors(target)
    assert anchor.seq == app.audit.head[0] == 0
    assert anchor.hash == app.audit.head[1]


def test_anchor_is_off_without_a_file(tmp_path, capsys):
    app = make_app(tmp_path, None)
    asyncio.run(app._write_anchor())
    assert capsys.readouterr().err == ""


def test_failed_anchor_is_reported_and_does_not_stop_the_gateway(tmp_path, capsys):
    app = make_app(tmp_path, tmp_path / "no-such-dir" / "a.jsonl")
    asyncio.run(app._write_anchor())
    assert "cannot write the audit anchor" in capsys.readouterr().err
    assert "audit_anchor_failed" in (tmp_path / "audit.log").read_text()
    # Шлюз продолжает писать журнал (seq 1 — само событие об ошибке).
    assert app.audit.append(EventType.SERVER_STARTED, {"after": True})["seq"] == 2


def test_empty_log_is_not_anchored(tmp_path):
    target = tmp_path / "a.jsonl"
    audit = AuditChain(FileSink(tmp_path / "empty.log"))
    app = GatekeeperApp(
        pipeline=SimpleNamespace(nonces=NonceCache()), bans=SimpleNamespace(),
        limiter=ConnectionLimiter(2, 2), audit=audit, http_limits=HttpLimits(),
        ssl_ctx=None, host="127.0.0.1", port=0,
        anchor_file=str(target), anchor_interval=60)
    asyncio.run(app._write_anchor())
    assert not target.exists()                 # seq = -1: якорей ещё нет


def test_config_anchor_defaults_off_and_validates(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("", encoding="utf-8")
    cfg = load_config(p)
    assert cfg.audit_anchor_file is None and cfg.audit_anchor_interval == 3600
    p.write_text('[audit]\nanchor_file = "/mnt/anchors/a"\nanchor_interval = 600\n',
                 encoding="utf-8")
    cfg = load_config(p)
    assert cfg.audit_anchor_file == "/mnt/anchors/a" and cfg.audit_anchor_interval == 600
    for bad in ('[audit]\nanchor_file = ""\n', '[audit]\nanchor_interval = 10\n',
                '[audit]\nanchor_interval = 99999999\n'):
        p.write_text(bad, encoding="utf-8")
        with pytest.raises(ConfigError):
            load_config(p)


def _init_cli(tmp_path, monkeypatch):
    cfg, data = tmp_path / "cfg", tmp_path / "data"
    cakey = tmp_path / "off" / "ca.key"
    cakey.parent.mkdir()
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(cakey)]) == 0
    return base, cfg, data


def test_status_counts_records_after_the_last_anchor(tmp_path, capsys):
    base, cfg, data = _init_cli(tmp_path, None)
    anchors_file = tmp_path / "anchors.jsonl"
    chain = AuditChain(FileSink(data / "audit" / "audit.log"))
    seq, digest = chain.head
    append_anchor(anchors_file, Anchor(seq, digest, 1))
    with (cfg / "config.toml").open("a", encoding="utf-8") as fh:
        fh.write(f"\n[audit]\nanchor_file = {str(anchors_file)!r}\n")
    chain.append(EventType.SERVER_STARTED, {"i": 1})
    chain.append(EventType.SERVER_STARTED, {"i": 2})
    capsys.readouterr()
    assert main([*base, "status"]) == 0
    out = capsys.readouterr()
    assert "2 record(s) after" in (out.out + out.err)


def test_status_says_nothing_after_a_fresh_anchor(tmp_path, capsys):
    base, cfg, data = _init_cli(tmp_path, None)
    anchors_file = tmp_path / "anchors.jsonl"
    seq, digest = AuditChain(FileSink(data / "audit" / "audit.log")).head
    append_anchor(anchors_file, Anchor(seq, digest, 1))
    with (cfg / "config.toml").open("a", encoding="utf-8") as fh:
        fh.write(f"\n[audit]\nanchor_file = {str(anchors_file)!r}\n")
    capsys.readouterr()
    assert main([*base, "status"]) == 0
    assert "nothing after it" in capsys.readouterr().out


def test_status_reports_an_anchor_ahead_of_the_log(tmp_path, capsys):
    """Якорь впереди журнала: хвост удалён, это должно быть видно, а не «всё хорошо»."""
    base, cfg, _data = _init_cli(tmp_path, None)
    anchors_file = tmp_path / "anchors.jsonl"
    append_anchor(anchors_file, Anchor(50, "a" * 64, 1))
    with (cfg / "config.toml").open("a", encoding="utf-8") as fh:
        fh.write(f"\n[audit]\nanchor_file = {str(anchors_file)!r}\n")
    capsys.readouterr()
    assert main([*base, "status"]) == 0
    out = capsys.readouterr()
    assert "ahead of the log" in (out.out + out.err)
