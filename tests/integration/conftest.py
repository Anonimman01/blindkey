"""Общие фикстуры интеграционных тестов.

Фикстура объявлена здесь, а помощники — в `support.py`: тест-модули не импортируют друг
друга, поэтому сбор работает и с `--import-mode=importlib`, и после переименования файлов.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest
from fake_telegram import FakeTelegram
from support import ALLOW, TOKEN, Server, free_port

from gatekeeper.cli.main import main
from gatekeeper.server.app import build_app
from gatekeeper.server.config import load_config
from gatekeeper.store.layout import Layout


@pytest.fixture()
def gw(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEKEEPER_UPSTREAM_TOKEN", TOKEN)
    fake = FakeTelegram(TOKEN)
    fake.start()
    cfgd, datad = tmp_path / "cfg", tmp_path / "data"
    cakey, bundle, decoy = tmp_path / "off" / "ca.key", tmp_path / "alice", tmp_path / "decoy"
    cakey.parent.mkdir()
    base = ["--config-dir", str(cfgd), "--data-dir", str(datad)]
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(cakey)]) == 0
    allow = [x for a in ALLOW for x in ("--allow", a)]
    assert main([*base, "add-client", "--id", "alice", "--ca-key", str(cakey),
                 "--out", str(bundle), *allow]) == 0
    port = free_port()
    (cfgd / "config.toml").write_text(
        f'[server]\nlisten_host="127.0.0.1"\nlisten_port={port}\n'
        f'[provider]\nname="telegram"\nupstream_host="127.0.0.1"\nupstream_port={fake.port}\n'
        f'upstream_tls=false\n[limits]\ndecoy_ban_seconds=2\nheader_timeout=1.0\nbody_timeout=1.0\n',
        encoding="utf-8")
    layout = Layout.from_args(str(cfgd), str(datad))
    server = Server(build_app(layout, load_config(layout.config_file)), port)
    server.start()
    yield SimpleNamespace(fake=fake, port=port, bundle=bundle, layout=layout, base=base,
                          cakey=cakey, decoy=decoy, tmp=tmp_path)
    server.stop()
    fake.stop()
