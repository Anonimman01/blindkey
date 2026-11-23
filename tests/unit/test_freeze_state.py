"""Автозаморозка живёт в state.db (каталог данных), реестр — для ручных freeze/revoke."""
import posixpath
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.serialization import Encoding

from gatekeeper.cli.commands import list_clients, status
from gatekeeper.cli.commands.client_status import revoke, unfreeze
from gatekeeper.core.timeutil import unix_now
from gatekeeper.pki import ca
from gatekeeper.pki.fingerprint import cert_fingerprint
from gatekeeper.server.identity import IdentityStore
from gatekeeper.server.state import StateStore
from gatekeeper.store.layout import DEFAULT_CONFIG_DIR, DEFAULT_DATA_DIR, Layout
from gatekeeper.store.registry import Registry

MASTER = bytes.fromhex("22" * 32)
UNIT = Path(__file__).resolve().parents[2] / "deploy" / "gatekeeper.service"


def make_env(tmp_path):
    ca_cert, ca_key = ca.create_ca()
    cert, _ = ca.issue_client_cert(ca_cert, ca_key, "alice")
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    reg.add("alice", {"fingerprint": cert_fingerprint(cert), "master_secret": MASTER.hex(),
                      "status": "active", "created": 0, "expires": unix_now() + 10_000,
                      "allow": ["GET:getMe"]})
    return SimpleNamespace(reg=reg, ca=ca_cert, der=cert.public_bytes(Encoding.DER),
                           layout=Layout(config_dir=tmp_path, data_dir=tmp_path))


def identify(env, store):
    return IdentityStore(env.reg, env.ca, state_frozen=store.is_frozen).identify(env.der)


def test_autofreeze_persists_across_restart(tmp_path):
    env = make_env(tmp_path)
    s1 = StateStore(env.layout.state_db)
    assert identify(env, s1).reason == "ok"
    s1.set_freeze("alice", unix_now())
    s1.close()
    s2 = StateStore(env.layout.state_db)  # «systemctl restart»
    try:
        assert identify(env, s2).reason == "inactive"
        assert env.reg.load()["alice"]["status"] == "active"  # реестр не тронут
    finally:
        s2.close()


def test_unfreeze_clears_both_layers(tmp_path):
    env = make_env(tmp_path)
    store = StateStore(env.layout.state_db)
    store.set_freeze("alice", unix_now())
    store.close()
    env.reg.set_status("alice", "frozen")  # плюс ручная заморозка
    assert unfreeze(SimpleNamespace(id="alice"), env.layout) == 0
    store = StateStore(env.layout.state_db)
    try:
        assert not store.is_frozen("alice")
        assert identify(env, store).reason == "ok"
    finally:
        store.close()


def test_unfreeze_of_only_autofrozen_client_succeeds(tmp_path):
    env = make_env(tmp_path)
    store = StateStore(env.layout.state_db)
    store.set_freeze("alice", unix_now())
    store.close()
    assert unfreeze(SimpleNamespace(id="alice"), env.layout) == 0
    store = StateStore(env.layout.state_db)
    try:
        assert identify(env, store).reason == "ok"
    finally:
        store.close()


def test_revoke_wins_and_cannot_be_undone_by_unfreeze(tmp_path):
    env = make_env(tmp_path)
    store = StateStore(env.layout.state_db)
    try:
        env.reg.set_status("alice", "revoked")
        assert identify(env, store).reason == "inactive"
        store.set_freeze("alice", unix_now())
        assert identify(env, store).reason == "inactive"
        assert unfreeze(SimpleNamespace(id="alice"), env.layout) == 1
        assert identify(env, store).reason == "inactive"
    finally:
        store.close()


def test_revoke_clears_state_layer(tmp_path):
    env = make_env(tmp_path)
    store = StateStore(env.layout.state_db)
    store.set_freeze("alice", unix_now())
    store.close()
    assert revoke(SimpleNamespace(id="alice"), env.layout) == 0
    store = StateStore(env.layout.state_db)
    try:
        assert not store.is_frozen("alice")
        assert identify(env, store).reason == "inactive"
    finally:
        store.close()


def test_unfreeze_on_clean_directory_does_not_create_state_db(tmp_path):
    """CLI не должен создавать state.db: его может не быть (persist_state = false)."""
    env = make_env(tmp_path)
    assert not env.layout.state_db.exists()
    assert unfreeze(SimpleNamespace(id="alice"), env.layout) == 0
    assert not env.layout.state_db.exists()


def test_status_shows_autofrozen_client(tmp_path, capsys):
    env = make_env(tmp_path)
    store = StateStore(env.layout.state_db)
    store.set_freeze("alice", unix_now())
    store.close()
    assert status.run(SimpleNamespace(), env.layout) == 0
    out = capsys.readouterr().out
    assert "autofrozen" in out and "alice" in out
    assert env.reg.load()["alice"]["status"] == "active"  # реестр не менялся


def test_list_clients_marks_autofrozen(tmp_path, capsys):
    env = make_env(tmp_path)
    store = StateStore(env.layout.state_db)
    store.set_freeze("alice", unix_now())
    store.close()
    assert list_clients.run(SimpleNamespace(), env.layout) == 0
    out = capsys.readouterr().out
    assert "active+auto" in out


def test_list_clients_reads_state_db_only_if_present(tmp_path, capsys):
    env = make_env(tmp_path)
    assert list_clients.run(SimpleNamespace(), env.layout) == 0
    assert "+auto" not in capsys.readouterr().out
    assert not env.layout.state_db.exists()  # справка не создаёт базу


def test_freeze_directory_is_writable_under_systemd_unit():
    values: dict[str, list[str]] = {}
    for raw in UNIT.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        values.setdefault(key, []).extend(val.split())
    envs = dict(v.split("=", 1) for v in values.get("Environment", []) if "=" in v)
    assert envs["GATEKEEPER_DATA_DIR"] == DEFAULT_DATA_DIR
    assert envs["GATEKEEPER_CONFIG_DIR"] == DEFAULT_CONFIG_DIR
    # Каталог, куда шлюз пишет заморозку, — это каталог state.db.
    layout = Layout(config_dir=Path(DEFAULT_CONFIG_DIR), data_dir=Path(DEFAULT_DATA_DIR))
    state_dir = layout.state_db.parent.relative_to(layout.data_dir)
    data_dir = posixpath.join(DEFAULT_DATA_DIR, *state_dir.parts)
    writable = values.get("ReadWritePaths", []) + [
        "/var/lib/" + d for d in values.get("StateDirectory", [])]
    assert any(data_dir == p or data_dir.startswith(p.rstrip("/") + "/") for p in writable), writable
    assert data_dir not in values.get("ReadOnlyPaths", [])
    assert DEFAULT_CONFIG_DIR in values.get("ReadOnlyPaths", [])  # реестр шлюзу только на чтение
