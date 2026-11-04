import pytest

from gatekeeper.store.registry import Registry, RegistryError


def entry(fp="a" * 64):
    return {"fingerprint": fp, "master_secret": "b" * 64, "status": "active",
            "created": 0, "expires": 10, "allow": ["GET:getMe"]}


@pytest.fixture()
def reg(tmp_path):
    r = Registry(tmp_path / "clients.json")
    r.init_empty()
    r.add("alice", entry())
    return r


def test_status_transitions(reg):
    reg.set_status("alice", "frozen")
    reg.set_status("alice", "active")
    reg.set_status("alice", "frozen")
    reg.set_status("alice", "revoked")
    assert reg.load()["alice"]["status"] == "revoked"


@pytest.mark.parametrize("target", ["active", "frozen", "revoked"])
def test_revoked_is_final(reg, target):
    reg.set_status("alice", "revoked")
    with pytest.raises(RegistryError):
        reg.set_status("alice", target)


def test_same_status_and_unknown_rejected(reg):
    with pytest.raises(RegistryError):
        reg.set_status("alice", "active")
    with pytest.raises(RegistryError):
        reg.set_status("nobody", "frozen")
    with pytest.raises(RegistryError):
        reg.set_status("alice", "bogus")


def test_renew_keeps_status_and_allow(reg):
    reg.set_status("alice", "frozen")
    reg.renew("alice", fingerprint="c" * 64, master_secret="d" * 64, expires=99)
    e = reg.load()["alice"]
    assert (e["fingerprint"], e["master_secret"], e["expires"]) == ("c" * 64, "d" * 64, 99)
    assert e["status"] == "frozen" and e["allow"] == ["GET:getMe"]


def test_renew_rejects_revoked_unknown_and_duplicate_fingerprint(reg):
    reg.add("bob", entry("e" * 64))
    with pytest.raises(RegistryError):
        reg.renew("alice", fingerprint="e" * 64, master_secret="d" * 64, expires=1)
    with pytest.raises(RegistryError):
        reg.renew("nobody", fingerprint="f" * 64, master_secret="d" * 64, expires=1)
    reg.set_status("bob", "revoked")
    with pytest.raises(RegistryError):
        reg.renew("bob", fingerprint="f" * 64, master_secret="d" * 64, expires=1)


def test_lock_timeout(reg):
    with reg._locked():
        with pytest.raises(RegistryError, match="lock timeout"):
            with reg._locked(timeout=0.05):
                pass


def test_concurrent_adds_do_not_lose_updates(reg):
    import threading

    errors = []

    def worker(i):
        try:
            reg.add(f"c{i}", entry(fp=f"{i:064x}"))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i + 1,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert set(reg.load()) == {"alice"} | {f"c{i + 1}" for i in range(8)}
