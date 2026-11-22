"""Регрессионные тесты по аудиту 0.3.1: B-03 (правила CLI), B-05 (fsync каталога), B-11 (права)."""
import os

import pytest

from gatekeeper.cli.commands.add_client import _valid_rule
from gatekeeper.server.honey.decoys import DecoyStore
from gatekeeper.store import atomic
from gatekeeper.store.registry import Registry, RegistryError


@pytest.mark.parametrize("rule", ["GET:getMe", "POST:sendMessage", "POST:a_b1"])
def test_valid_rules_accepted(rule):
    assert _valid_rule(rule)


@pytest.mark.parametrize("rule", [
    "DELETE:deleteMessage", "PATCH:foo", "POST:123abc", "POST:", "POST:a/b", "POST:a b",
    "get:getMe", "sendMessage", ":getMe",
])
def test_rules_rejected_like_gateway(rule):
    assert not _valid_rule(rule)


def test_atomic_write_fsyncs_directory(tmp_path, monkeypatch):
    synced = []
    monkeypatch.setattr(atomic, "_fsync_dir", lambda p: synced.append(p))
    target = tmp_path / "sub" / "f.json"
    atomic.atomic_write_private(target, b"{}")
    assert target.read_bytes() == b"{}"
    assert synced == [target.parent]


def test_registry_and_decoys_use_atomic_write(tmp_path, monkeypatch):
    synced = []
    monkeypatch.setattr(atomic, "_fsync_dir", lambda p: synced.append(p))
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    DecoyStore(tmp_path / "decoys.json").add("d1", "a" * 64, 0)
    assert synced.count(tmp_path) == 2


@pytest.mark.skipif(os.name == "nt", reason="права POSIX")
def test_registry_permissions_checked(tmp_path):
    reg = Registry(tmp_path / "clients.json")
    reg.check_permissions()                      # файла нет: не ошибка
    reg.init_empty()
    reg.check_permissions()                      # 0600: ок
    os.chmod(reg.path, 0o640)
    with pytest.raises(RegistryError):
        reg.check_permissions()
    os.chmod(reg.path, 0o604)
    with pytest.raises(RegistryError):
        reg.check_permissions()
