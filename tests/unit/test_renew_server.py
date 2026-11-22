"""C-03: продление серверного сертификата и предупреждение в status."""
from types import SimpleNamespace

import pytest

from gatekeeper.cli.main import main
from gatekeeper.pki import ca
from gatekeeper.pki.fingerprint import cert_fingerprint


@pytest.fixture()
def env(tmp_path):
    cfg, data, off = tmp_path / "cfg", tmp_path / "data", tmp_path / "off"
    off.mkdir()
    cakey = off / "ca.key"
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main([*base, "init", "--host", "127.0.0.1", "--host", "gw.example",
                 "--ca-key-out", str(cakey)]) == 0
    return SimpleNamespace(base=base, cfg=cfg, data=data, cakey=cakey, tmp=tmp_path)


def _server_cert(env):
    return ca.load_cert_pem((env.data / "pki" / "server.pem").read_bytes())


def test_renew_server_replaces_certificate_and_logs(env):
    old_fp = cert_fingerprint(_server_cert(env))
    assert main([*env.base, "renew-server", "--ca-key", str(env.cakey), "--days", "30"]) == 0
    cert = _server_cert(env)
    assert cert_fingerprint(cert) != old_fp
    assert ca.cert_hosts(cert) == ["127.0.0.1", "gw.example"]  # SAN переиспользованы
    assert 27 <= ca.cert_expires_in_days(cert) <= 30
    key = ca.load_key_pem((env.data / "pki" / "server.key").read_bytes())
    assert ca.key_matches_cert(key, cert)
    assert "server_cert_renewed" in (env.data / "audit" / "audit.log").read_text()


def test_renew_server_accepts_new_hosts(env):
    assert main([*env.base, "renew-server", "--ca-key", str(env.cakey),
                 "--host", "new.example", "--days", "10"]) == 0
    assert ca.cert_hosts(_server_cert(env)) == ["new.example"]


def test_renew_server_refuses_a_foreign_ca_key(env):
    _other_cert, other_key = ca.create_ca()
    bad = env.tmp / "bad.key"
    ca.write_private_file(bad, ca.key_to_pem(other_key))
    before = (env.data / "pki" / "server.pem").read_bytes()
    assert main([*env.base, "renew-server", "--ca-key", str(bad)]) == 1
    assert (env.data / "pki" / "server.pem").read_bytes() == before


def test_status_warns_when_the_certificate_expires_soon(env, capsys):
    ca_cert = ca.load_cert_pem((env.data / "pki" / "ca.pem").read_bytes())
    ca_key = ca.load_key_pem(env.cakey.read_bytes())
    cert, key = ca.issue_server_cert(ca_cert, ca_key, ["127.0.0.1"], days=5)
    (env.data / "pki" / "server.pem").write_bytes(ca.cert_to_pem(cert))
    (env.data / "pki" / "server.key").write_bytes(ca.key_to_pem(key))
    capsys.readouterr()
    assert main([*env.base, "status"]) == 0
    err = capsys.readouterr().err
    assert "expires in" in err and "renew-server" in err


def test_status_warns_for_a_certificate_expiring_today(env, capsys):
    ca_cert = ca.load_cert_pem((env.data / "pki" / "ca.pem").read_bytes())
    ca_key = ca.load_key_pem(env.cakey.read_bytes())
    cert, key = ca.issue_server_cert(ca_cert, ca_key, ["127.0.0.1"], days=1)
    (env.data / "pki" / "server.pem").write_bytes(ca.cert_to_pem(cert))
    (env.data / "pki" / "server.key").write_bytes(ca.key_to_pem(key))
    capsys.readouterr()
    assert main([*env.base, "status"]) == 0
    assert "expires in 0 day" in capsys.readouterr().err


def test_status_is_quiet_for_a_fresh_certificate(env, capsys):
    capsys.readouterr()
    assert main([*env.base, "status"]) == 0
    out = capsys.readouterr()
    assert "days left" in out.out and "expires in" not in out.err
