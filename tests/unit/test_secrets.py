"""store/secrets.py: переменная окружения, файл, права и ошибки."""
import os

import pytest

from gatekeeper.store.secrets import SecretError, load_secret

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")


def test_env_value_wins_and_is_stripped(monkeypatch):
    monkeypatch.setenv("GK_TEST_TOKEN", "  from-env\n")
    assert load_secret("GK_TEST_TOKEN", None) == "from-env"


def test_file_used_when_env_is_empty(tmp_path, monkeypatch):
    monkeypatch.delenv("GK_TEST_TOKEN", raising=False)
    path = tmp_path / "token"
    path.write_text("  from-file \n", encoding="utf-8")
    path.chmod(0o600)
    assert load_secret("GK_TEST_TOKEN", str(path)) == "from-file"


@posix_only
def test_file_with_group_or_other_permissions_is_rejected(tmp_path):
    path = tmp_path / "token"
    path.write_text("secret", encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(SecretError, match="chmod 0400"):
        load_secret(None, str(path))


def test_missing_secret_raises(monkeypatch):
    monkeypatch.delenv("GK_TEST_TOKEN", raising=False)
    with pytest.raises(SecretError, match="not found"):
        load_secret("GK_TEST_TOKEN", None)


def test_missing_file_raises(tmp_path):
    with pytest.raises(SecretError, match="cannot read"):
        load_secret(None, str(tmp_path / "absent"))


def test_empty_file_raises(tmp_path):
    path = tmp_path / "token"
    path.write_text("   \n", encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(SecretError, match="not found"):
        load_secret(None, str(path))
