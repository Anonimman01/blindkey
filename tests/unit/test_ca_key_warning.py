"""B3: незашифрованный ca.key виден в init и в gatekeeper status --ca-key.

Формат ключа не меняется: это только предупреждение и подсказка про --ca-key-pass-file.
"""
from gatekeeper.cli.main import main
from gatekeeper.pki import ca


def test_key_is_encrypted_detects_both_forms():
    _cert, key = ca.create_ca()
    plain = ca.key_to_pem(key)
    sealed = ca.key_to_pem(key, b"passphrase")
    assert ca.key_is_encrypted(plain) is False
    assert ca.key_is_encrypted(sealed) is True


def _env(tmp_path, *extra):
    cfg, data, cakey = tmp_path / "cfg", tmp_path / "data", tmp_path / "off" / "ca.key"
    cakey.parent.mkdir()
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(cakey), *extra]) == 0
    return base, cakey


def test_init_mentions_the_passphrase_option(tmp_path, capsys):
    _env(tmp_path)
    out = capsys.readouterr()
    assert "WITHOUT a passphrase" in (out.out + out.err)
    assert "--ca-key-pass-file" in (out.out + out.err)


def test_status_warns_about_an_unencrypted_ca_key(tmp_path, capsys):
    base, cakey = _env(tmp_path)
    capsys.readouterr()
    assert main([*base, "status", "--ca-key", str(cakey)]) == 0
    out = capsys.readouterr()
    text = out.out + out.err
    assert "ca.key is NOT encrypted" in text and "--ca-key-pass-file" in text


def test_status_is_quiet_for_an_encrypted_ca_key(tmp_path, capsys):
    passfile = tmp_path / "pass"
    passfile.write_text("secret-phrase", encoding="utf-8")
    passfile.chmod(0o400)
    base, cakey = _env(tmp_path, "--ca-key-pass-file", str(passfile))
    capsys.readouterr()
    assert main([*base, "status", "--ca-key", str(cakey)]) == 0
    text = "".join(capsys.readouterr()[:2])
    assert "encrypted with a passphrase" in text and "NOT encrypted" not in text


def test_status_reports_a_missing_ca_key(tmp_path, capsys):
    base, _cakey = _env(tmp_path)
    capsys.readouterr()
    assert main([*base, "status", "--ca-key", str(tmp_path / "absent.key")]) == 0
    assert "cannot read" in "".join(capsys.readouterr()[:2])
