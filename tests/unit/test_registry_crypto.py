"""B2: master_secret в clients.json шифруется на диске (по умолчанию — открытый текст).

Защищает копию файла (бэкап, snapshot): без ключа шифротекст бесполезен. От взломанного
процесса шлюза не защищает — ключ лежит в памяти процесса, это честно написано в SECURITY.md.
"""
import json
import os
import stat

import pytest

from gatekeeper.cli.main import main
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.store.registry import Registry, RegistryError, RegistryLockedError
from gatekeeper.store.registry_key import (
    ENV_KEY_FILE,
    RegistryKeyError,
    load_key_file,
    seal,
    unseal,
)

KEY = bytes(range(32))
SECRET = "ab" * 32


def write_key(tmp_path, data=None, mode=0o600):
    path = tmp_path / "registry.key"
    path.write_bytes(KEY if data is None else data)
    os.chmod(path, mode)
    return path


def test_seal_roundtrip_and_binding(tmp_path):
    blob = seal(KEY, SECRET, "alice")
    assert blob != SECRET and SECRET not in blob
    assert unseal(KEY, blob, "alice") == SECRET
    with pytest.raises(RegistryKeyError):
        unseal(bytes(32), blob, "alice")          # чужой ключ
    with pytest.raises(RegistryKeyError):
        unseal(KEY, blob, "bob")                  # запись нельзя переставить клиенту


def test_key_file_formats_and_permissions(tmp_path):
    raw = write_key(tmp_path)
    assert load_key_file(raw) == KEY
    hexfile = tmp_path / "hex.key"
    hexfile.write_text(KEY.hex(), encoding="ascii")
    os.chmod(hexfile, 0o600)
    assert load_key_file(hexfile) == KEY
    bad = write_key(tmp_path, b"short")
    with pytest.raises(RegistryKeyError):
        load_key_file(bad)
    if os.name != "nt":
        loose = write_key(tmp_path, mode=0o644)
        with pytest.raises(RegistryKeyError):
            load_key_file(loose)


def test_registry_encrypts_on_write_and_decrypts_on_read(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_KEY_FILE, str(write_key(tmp_path)))
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    reg.add("alice", {"fingerprint": "f" * 64, "master_secret": SECRET, "status": "active",
                      "created": 0, "expires": 10, "allow": ["POST:sendMessage"]})
    stored = json.loads((tmp_path / "clients.json").read_text())["clients"]["alice"]
    assert "master_secret" not in stored and stored["master_secret_enc"]
    assert SECRET not in (tmp_path / "clients.json").read_text()
    assert reg.load()["alice"]["master_secret"] == SECRET


def test_encrypted_file_without_the_key_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_KEY_FILE, str(write_key(tmp_path)))
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    reg.add("alice", {"fingerprint": "f" * 64, "master_secret": SECRET, "status": "active",
                      "created": 0, "expires": 10, "allow": []})
    monkeypatch.delenv(ENV_KEY_FILE)
    with pytest.raises(RegistryError):
        Registry(tmp_path / "clients.json").load()


def test_metadata_access_without_the_key_keeps_the_ciphertext(tmp_path, monkeypatch):
    """freeze/revoke не нужен master_secret: реестр читается и меняется без ключа."""
    monkeypatch.setenv(ENV_KEY_FILE, str(write_key(tmp_path)))
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    reg.add("alice", {"fingerprint": "f" * 64, "master_secret": SECRET, "status": "active",
                      "created": 0, "expires": 10, "allow": []})
    monkeypatch.delenv(ENV_KEY_FILE)
    metadata = Registry(tmp_path / "clients.json")
    clients = metadata.load(decrypt=False)
    assert "master_secret" not in clients["alice"] and clients["alice"]["master_secret_enc"]
    with pytest.raises(RegistryLockedError):
        metadata.load()
    metadata.set_status("alice", "frozen", decrypt=False)
    stored = json.loads((tmp_path / "clients.json").read_text())["clients"]["alice"]
    assert stored["status"] == "frozen" and stored["master_secret_enc"]
    monkeypatch.setenv(ENV_KEY_FILE, str(write_key(tmp_path)))
    assert Registry(tmp_path / "clients.json").load()["alice"]["master_secret"] == SECRET


def test_cli_freeze_revoke_and_status_work_without_the_key(tmp_path, monkeypatch, capsys):
    """Инцидент: ключ шифрования недоступен, а заморозить и отозвать клиента нужно."""
    cfg, data, cakey = tmp_path / "cfg", tmp_path / "data", tmp_path / "off" / "ca.key"
    cakey.parent.mkdir()
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(cakey)]) == 0
    assert main([*base, "add-client", "--id", "b1", "--ca-key", str(cakey),
                 "--out", str(tmp_path / "b1")]) == 0
    monkeypatch.setenv(ENV_KEY_FILE, str(write_key(tmp_path)))
    assert main([*base, "encrypt-registry"]) == 0
    clients = cfg / "clients.json"
    assert "master_secret_enc" in json.loads(clients.read_text())["clients"]["b1"]
    monkeypatch.delenv(ENV_KEY_FILE)
    capsys.readouterr()
    assert main([*base, "status"]) == 0
    assert "metadata only" in capsys.readouterr().err
    assert main([*base, "freeze", "--id", "b1"]) == 0
    assert main([*base, "revoke", "--id", "b1"]) == 0
    stored = json.loads(clients.read_text())["clients"]["b1"]
    assert stored["status"] == "revoked" and stored["master_secret_enc"]
    # Шифротекст уцелел: с ключом шлюз по-прежнему расшифровывает секрет.
    monkeypatch.setenv(ENV_KEY_FILE, str(write_key(tmp_path)))
    assert Registry(clients).load()["b1"]["master_secret"]


def test_renew_keeps_the_secret_encrypted(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_KEY_FILE, str(write_key(tmp_path)))
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    reg.add("alice", {"fingerprint": "f" * 64, "master_secret": SECRET, "status": "active",
                      "created": 0, "expires": 10, "allow": []})
    new_secret = "cd" * 32
    reg.renew("alice", fingerprint="e" * 64, master_secret=new_secret, expires=20)
    assert reg.load()["alice"]["master_secret"] == new_secret
    assert new_secret not in (tmp_path / "clients.json").read_text()


def test_plain_text_registry_still_readable_with_a_key(tmp_path, monkeypatch):
    """Ключ задан, а файл ещё открытый: чтение не ломается (нужно для миграции)."""
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    reg.add("alice", {"fingerprint": "f" * 64, "master_secret": SECRET, "status": "active",
                      "created": 0, "expires": 10, "allow": []})
    monkeypatch.setenv(ENV_KEY_FILE, str(write_key(tmp_path)))
    assert Registry(tmp_path / "clients.json").load()["alice"]["master_secret"] == SECRET


def test_rekey_moves_both_ways(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_KEY_FILE, str(write_key(tmp_path)))
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    reg.add("alice", {"fingerprint": "f" * 64, "master_secret": SECRET, "status": "active",
                      "created": 0, "expires": 10, "allow": []})
    reg.rekey(None)
    assert json.loads((tmp_path / "clients.json").read_text())[
        "clients"]["alice"]["master_secret"] == SECRET
    reg.rekey(KEY)
    assert "master_secret" not in json.loads((tmp_path / "clients.json").read_text())[
        "clients"]["alice"]


def test_cli_encrypt_registry_roundtrip(tmp_path, monkeypatch, capsys):
    cfg, data, cakey = tmp_path / "cfg", tmp_path / "data", tmp_path / "off" / "ca.key"
    cakey.parent.mkdir()
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(cakey)]) == 0
    assert main([*base, "add-client", "--id", "b1", "--ca-key", str(cakey),
                 "--out", str(tmp_path / "b1")]) == 0
    clients = cfg / "clients.json"
    assert "master_secret" in json.loads(clients.read_text())["clients"]["b1"]
    monkeypatch.setenv(ENV_KEY_FILE, str(write_key(tmp_path)))
    capsys.readouterr()
    assert main([*base, "encrypt-registry"]) == 0
    stored = json.loads(clients.read_text())["clients"]["b1"]
    assert "master_secret" not in stored and stored["master_secret_enc"]
    assert "registry_rekeyed" in (data / "audit" / "audit.log").read_text()
    # Шлюз и list-clients читают зашифрованный реестр с ключом из окружения.
    assert main([*base, "list-clients"]) == 0
    assert main([*base, "encrypt-registry", "--decrypt"]) == 0
    assert "master_secret" in json.loads(clients.read_text())["clients"]["b1"]


def test_cli_encrypt_registry_needs_the_key(tmp_path, capsys):
    cfg, data, cakey = tmp_path / "cfg", tmp_path / "data", tmp_path / "off" / "ca.key"
    cakey.parent.mkdir()
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(cakey)]) == 0
    capsys.readouterr()
    assert main([*base, "encrypt-registry"]) == 1
    assert ENV_KEY_FILE in capsys.readouterr().err


def test_cli_encrypt_registry_refuses_without_the_journal(tmp_path, monkeypatch, capsys):
    cfg, data, cakey = tmp_path / "cfg", tmp_path / "data", tmp_path / "off" / "ca.key"
    cakey.parent.mkdir()
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(cakey)]) == 0
    assert main([*base, "add-client", "--id", "b1", "--ca-key", str(cakey),
                 "--out", str(tmp_path / "b1")]) == 0
    monkeypatch.setenv(ENV_KEY_FILE, str(write_key(tmp_path)))
    (data / "audit" / "audit.log").write_bytes(b"garbage\n")
    before = (cfg / "clients.json").read_bytes()
    capsys.readouterr()
    assert main([*base, "encrypt-registry"]) == 1
    assert (cfg / "clients.json").read_bytes() == before
    assert "was not changed" in capsys.readouterr().err


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_clients_file_stays_0600(tmp_path, monkeypatch):
    monkeypatch.setenv(ENV_KEY_FILE, str(write_key(tmp_path)))
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    reg.add("alice", {"fingerprint": "f" * 64, "master_secret": SECRET, "status": "active",
                      "created": 0, "expires": 10, "allow": []})
    assert stat.S_IMODE(os.stat(tmp_path / "clients.json").st_mode) == 0o600


def test_gatekeeper_error_hierarchy():
    """Ошибки ключа — обычные GatekeeperError: CLI печатает их без трейсбека."""
    assert issubclass(RegistryKeyError, GatekeeperError)
