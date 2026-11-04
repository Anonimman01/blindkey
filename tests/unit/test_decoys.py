import pytest

from gatekeeper.server.honey.decoys import DecoyError, DecoyStore

FP1, FP2 = "a" * 64, "b" * 64


def test_add_and_lookup(tmp_path):
    s = DecoyStore(tmp_path / "decoys.json")
    assert not s.is_decoy(FP1)
    s.add("old-backup", FP1, 1, "~/old")
    assert s.is_decoy(FP1) and not s.is_decoy(FP2)


def test_persisted_and_seen_by_other_instance(tmp_path):
    p = tmp_path / "decoys.json"
    a, b = DecoyStore(p), DecoyStore(p)
    a.add("one", FP1, 1)
    assert b.is_decoy(FP1)  # перечитывается при изменении файла


def test_duplicate_name_and_bad_fingerprint(tmp_path):
    s = DecoyStore(tmp_path / "decoys.json")
    s.add("one", FP1, 1)
    with pytest.raises(DecoyError):
        s.add("one", FP2, 1)
    with pytest.raises(DecoyError):
        s.add("two", "xyz", 1)


def test_malformed_file_fails_startup_but_not_later(tmp_path):
    p = tmp_path / "decoys.json"
    p.write_text("{not json")
    with pytest.raises(DecoyError):
        DecoyStore(p)
    p.unlink()
    s = DecoyStore(p)
    s.add("one", FP1, 1)
    p.write_text("{broken")
    assert s.is_decoy(FP1)  # прежний набор приманок сохраняется
