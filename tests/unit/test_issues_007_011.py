"""Issue #7-#11 внешнего ревью (0.3.9a1): целостность CLI-операций и расход подтверждения."""
import asyncio
import json
from pathlib import Path

import pytest
from test_pipeline import IP, call, make_env, make_req

from gatekeeper.cli import main as cli_main
from gatekeeper.cli.commands import renew_server as renew_server_cmd
from gatekeeper.cli.main import main
from gatekeeper.pki import ca
from gatekeeper.server.providers.base import ProviderError
from gatekeeper.store.approvals import Approvals
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry

assert cli_main  # модуль нужен monkeypatch-ам ниже


@pytest.fixture()
def cli(tmp_path):
    cfg, data = tmp_path / "cfg", tmp_path / "data"
    cakey = tmp_path / "off" / "ca.key"
    cakey.parent.mkdir()
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(cakey)]) == 0
    assert main([*base, "add-client", "--id", "bot", "--ca-key", str(cakey),
                 "--out", str(tmp_path / "bot"), "--allow", "GET:getMe"]) == 0
    other = tmp_path / "other.key"                       # ключ ДРУГОГО CA
    other.write_bytes(ca.key_to_pem(ca.create_ca()[1]))
    return base, Layout.from_args(str(cfg), str(data)), cakey, other


# ---- #7: ключ CA должен подходить к ca.pem ---------------------------------------------

def test_add_client_rejects_a_foreign_ca_key(cli, tmp_path, capsys):
    base, layout, _good, other = cli
    out = tmp_path / "new"
    assert main([*base, "add-client", "--id", "x", "--ca-key", str(other), "--out", str(out)]) == 1
    assert "does not match ca.pem" in capsys.readouterr().err
    assert "x" not in Registry(layout.clients_file).load() and not out.exists()


def test_renew_rejects_a_foreign_ca_key(cli, tmp_path):
    base, layout, _good, other = cli
    before = Registry(layout.clients_file).load()["bot"]
    out = tmp_path / "renewed"
    assert main([*base, "renew", "--id", "bot", "--ca-key", str(other), "--out", str(out)]) == 1
    assert Registry(layout.clients_file).load()["bot"] == before and not out.exists()


def test_decoy_create_and_renew_server_reject_a_foreign_ca_key(cli, tmp_path):
    base, layout, _good, other = cli
    assert main([*base, "decoy-create", "--name", "trap", "--ca-key", str(other),
                 "--out", str(tmp_path / "trap")]) == 1
    cert_before = layout.server_cert.read_bytes()
    assert main([*base, "renew-server", "--ca-key", str(other)]) == 1
    assert layout.server_cert.read_bytes() == cert_before


def test_init_completion_rejects_a_foreign_ca_key(tmp_path):
    cfg, data = tmp_path / "cfg", tmp_path / "data"
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    key = tmp_path / "off" / "ca.key"
    key.parent.mkdir()
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(key)]) == 0
    layout = Layout.from_args(str(cfg), str(data))
    layout.server_cert.unlink()
    layout.server_key.unlink()                            # «прерванный init»: нет серверного сертификата
    foreign = tmp_path / "foreign.key"
    foreign.write_bytes(ca.key_to_pem(ca.create_ca()[1]))
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(key),
                 "--ca-key", str(foreign)]) == 1
    assert not layout.server_cert.exists()
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(key)]) == 0
    assert layout.server_cert.exists()


# ---- #8: renew-server заменяет сертификат и ключ как пару ----------------------------------

def test_renew_server_restores_the_old_pair_when_the_second_write_fails(cli, monkeypatch):
    base, layout, good, _other = cli
    old_cert, old_key = layout.server_cert.read_bytes(), layout.server_key.read_bytes()
    real = renew_server_cmd.atomic_write_private
    calls = []

    def flaky(path, data):
        calls.append(Path(path).name)
        if Path(path) == layout.server_key and calls.count(Path(path).name) == 1:
            raise OSError("disk full")                    # сбой на записи ключа
        return real(path, data)
    monkeypatch.setattr(renew_server_cmd, "atomic_write_private", flaky)
    assert main([*base, "renew-server", "--ca-key", str(good)]) == 1
    assert layout.server_cert.read_bytes() == old_cert    # сертификат не остался новым
    assert layout.server_key.read_bytes() == old_key


def test_renew_server_success_writes_a_matching_pair(cli):
    base, layout, good, _other = cli
    old_cert = layout.server_cert.read_bytes()
    assert main([*base, "renew-server", "--ca-key", str(good)]) == 0
    new_cert = ca.load_cert_pem(layout.server_cert.read_bytes())
    assert layout.server_cert.read_bytes() != old_cert
    assert ca.key_matches_cert(ca.load_key_pem(layout.server_key.read_bytes()), new_cert)


def test_gateway_start_reports_a_mismatched_pair_clearly(cli):
    from gatekeeper.core.errors import GatekeeperError
    from gatekeeper.server.tls import build_server_context
    base, layout, good, _other = cli
    saved = layout.server_key.read_bytes()
    assert main([*base, "renew-server", "--ca-key", str(good)]) == 0
    layout.server_key.write_bytes(saved)                  # старый ключ к новому сертификату
    with pytest.raises(GatekeeperError, match="renew-server"):
        build_server_context(layout.ca_cert, layout.server_cert, layout.server_key)


# ---- #9: renew не трогает реестр, пока пакет не готов ---------------------------------------

def test_renew_keeps_registry_and_old_bundle_when_the_bundle_cannot_be_written(cli, tmp_path,
                                                                                monkeypatch):
    base, layout, good, _other = cli
    before = Registry(layout.clients_file).load()["bot"]
    old_bundle = (tmp_path / "bot" / "client.pem").read_bytes()

    def boom(out, files):
        raise OSError("disk full")
    monkeypatch.setattr("gatekeeper.cli.commands.renew.write_bundle", boom)
    assert main([*base, "renew", "--id", "bot", "--ca-key", str(good),
                 "--out", str(tmp_path / "renewed")]) == 1
    assert Registry(layout.clients_file).load()["bot"] == before     # реестр прежний
    assert (tmp_path / "bot" / "client.pem").read_bytes() == old_bundle


def test_renew_into_a_dir_with_an_old_bundle_keeps_it_and_the_registry(cli, tmp_path):
    base, layout, good, _other = cli
    old = tmp_path / "bot"                                           # здесь уже лежит пакет
    snapshot = {p.name: p.read_bytes() for p in old.iterdir()}
    before = Registry(layout.clients_file).load()["bot"]
    assert main([*base, "renew", "--id", "bot", "--ca-key", str(good), "--out", str(old)]) == 1
    assert {p.name: p.read_bytes() for p in old.iterdir()} == snapshot  # старые ключи целы
    assert Registry(layout.clients_file).load()["bot"] == before


def test_renew_removes_the_new_bundle_when_the_registry_refuses(cli, tmp_path, monkeypatch):
    base, _layout, good, _other = cli
    out = tmp_path / "renewed"

    def refuse(self, *a, **k):
        raise OSError("read-only file system")
    monkeypatch.setattr(Registry, "renew", refuse)
    assert main([*base, "renew", "--id", "bot", "--ca-key", str(good), "--out", str(out)]) == 1
    assert not out.exists() or not any(out.iterdir())


def test_renew_success_writes_bundle_then_registry(cli, tmp_path):
    base, layout, good, _other = cli
    before = Registry(layout.clients_file).load()["bot"]["fingerprint"]
    out = tmp_path / "renewed"
    assert main([*base, "renew", "--id", "bot", "--ca-key", str(good), "--out", str(out)]) == 0
    after = Registry(layout.clients_file).load()["bot"]["fingerprint"]
    assert after != before and sorted(p.name for p in out.iterdir()) == [
        "ca.pem", "client.key", "client.pem", "master.secret"]


# ---- #10: init не оставляет ca.pem без ключа CA ----------------------------------------------

def test_init_leaves_no_orphan_ca_when_ca_pem_cannot_be_written(tmp_path, monkeypatch):
    cfg, data = tmp_path / "cfg", tmp_path / "data"
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    key = tmp_path / "off" / "ca.key"
    key.parent.mkdir()
    layout = Layout.from_args(str(cfg), str(data))
    real = ca.write_private_file

    def fail_on_ca_pem(path, data_):
        if Path(path) == layout.ca_cert:
            raise OSError("no space left on device")
        return real(path, data_)
    monkeypatch.setattr(ca, "write_private_file", fail_on_ca_pem)
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(key)]) == 1
    assert not layout.ca_cert.exists() and not key.exists()          # ни сироты, ни ключа
    monkeypatch.setattr(ca, "write_private_file", real)
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(key)]) == 0
    assert layout.ca_cert.exists() and key.exists()


def test_init_leaves_no_orphan_ca_when_the_key_cannot_be_written(tmp_path, monkeypatch):
    # Сценарий из issue #10: ca.pem уже записан, а ключ записать не удалось.
    cfg, data = tmp_path / "cfg", tmp_path / "data"
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    key = tmp_path / "off" / "ca.key"
    key.parent.mkdir()
    layout = Layout.from_args(str(cfg), str(data))
    real = ca.write_private_file

    def fail_on_key(path, data_):
        if Path(path) == key:
            raise OSError("read-only file system")
        return real(path, data_)
    monkeypatch.setattr(ca, "write_private_file", fail_on_key)
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(key)]) == 1
    assert not layout.ca_cert.exists()                               # нет ca.pem без ключа
    monkeypatch.setattr(ca, "write_private_file", real)
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(key)]) == 0


def test_init_writes_the_ca_key_before_ca_pem(tmp_path, monkeypatch):
    cfg, data = tmp_path / "cfg", tmp_path / "data"
    key = tmp_path / "off" / "ca.key"
    key.parent.mkdir()
    layout = Layout.from_args(str(cfg), str(data))
    order = []
    real = ca.write_private_file

    def spy(path, data_):
        order.append(Path(path).name)
        return real(path, data_)
    monkeypatch.setattr(ca, "write_private_file", spy)
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(key)]) == 0
    assert order.index("ca.key") < order.index(layout.ca_cert.name)


# ---- #11: одноразовое подтверждение расходуется последним ----------------------------------------

def _armed(env, tmp_path):
    store = Approvals(tmp_path / "approvals.json", 300)
    env.p.approvals, env.p.confirm_apis = store, frozenset({"sendMessage"})
    assert call(env, make_req(env.fp))[0] == 403                    # заявка
    store.approve(store.list_items()[0][0])
    return store


def _approved(store):
    return [v for _r, v in store.list_items() if v["status"] == "approved"]


def test_approval_is_consumed_by_a_successful_request(tmp_path):
    env = make_env(tmp_path)
    store = _armed(env, tmp_path)
    assert call(env, make_req(env.fp))[0] == 200 and len(env.up.calls) == 1
    assert not _approved(store)
    assert call(env, make_req(env.fp))[0] == 403                    # второй раз нужно новое


def test_approval_survives_a_request_the_provider_cannot_build(tmp_path):
    env = make_env(tmp_path)
    store = _armed(env, tmp_path)
    real = env.p.provider.build_request

    def refuse(*a, **k):
        raise ProviderError("bad request")
    env.p.provider.build_request = refuse
    assert call(env, make_req(env.fp))[0] == 400 and not env.up.calls
    assert len(_approved(store)) == 1                               # не сгорело
    env.p.provider.build_request = real
    assert call(env, make_req(env.fp))[0] == 200


def test_approval_survives_a_busy_provider(tmp_path):
    env = make_env(tmp_path)
    store = _armed(env, tmp_path)
    saved = dict(env.p._inflight)
    for name in env.p._inflight:
        env.p._inflight[name] = asyncio.Semaphore(0)
    assert call(env, make_req(env.fp))[0] == 503 and not env.up.calls
    assert len(_approved(store)) == 1
    env.p._inflight.update(saved)
    assert call(env, make_req(env.fp))[0] == 200


def test_approval_survives_a_failed_intent_record(tmp_path):
    env = make_env(tmp_path)
    store = _armed(env, tmp_path)
    real_append = env.p.audit.append

    def flaky(etype, *a, **k):
        if getattr(etype, "value", etype) == "request_intent":
            raise OSError("disk full")
        return real_append(etype, *a, **k)
    env.p.audit.append = flaky
    assert call(env, make_req(env.fp))[0] == 500 and not env.up.calls
    assert len(_approved(store)) == 1                               # запись намерения не удалась: цело
    env.p.audit.append = real_append
    assert call(env, make_req(env.fp))[0] == 200


def test_one_approval_allows_exactly_one_of_two_concurrent_requests(tmp_path):
    env = make_env(tmp_path)
    _armed(env, tmp_path)

    async def both():
        return await asyncio.gather(
            env.p.handle(make_req(env.fp), IP, env.der), env.p.handle(make_req(env.fp), IP, env.der))
    statuses = sorted(int(r.split(b" ", 2)[1]) for r in asyncio.run(both()))
    assert statuses == [200, 403] and len(env.up.calls) == 1


def test_consume_api_is_one_shot_and_peek_does_not_spend(tmp_path):
    store = Approvals(tmp_path / "a.json", 300)
    args = ("alice", "POST", "sendMessage", b'{"a":1}', "preview", "203.0.113.1", "application/json")
    assert store.request(*args).state == "new"
    store.approve(store.list_items()[0][0])
    assert store.request(*args, consume=False).state == "approved"
    assert store.request(*args, consume=False).state == "approved"  # просмотр не тратит
    assert store.consume("alice", "POST", "sendMessage", b'{"a":1}', "application/json") is True
    assert store.consume("alice", "POST", "sendMessage", b'{"a":1}', "application/json") is False
    assert store.request(*args, consume=False).state == "new"
    assert json.loads(json.dumps(len(store.list_items()))) == 1
