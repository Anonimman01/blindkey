import json
import os
import stat
import sys

import pytest

from gatekeeper.cli.main import main
from gatekeeper.core.redact import MASK
from gatekeeper.pki import ca
from gatekeeper.pki.fingerprint import cert_fingerprint
from gatekeeper.server.audit.verify import verify_file


@pytest.fixture()
def env(tmp_path):
    cfg, data, cakey = tmp_path / "cfg", tmp_path / "data", tmp_path / "off" / "ca.key"
    cakey.parent.mkdir()
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main(base + ["init", "--host", "127.0.0.1", "--host", "gw.example", "--ca-key-out", str(cakey)]) == 0
    return base, cfg, data, cakey, tmp_path


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def test_init_layout_and_perms(env):
    base, cfg, data, cakey, _ = env
    if sys.platform != "win32":
        assert mode(data) == 0o700 and mode(data / "pki") == 0o700 and mode(data / "audit") == 0o700
        assert mode(data / "pki" / "server.key") == 0o600 and mode(cakey) == 0o600
        assert mode(cfg / "clients.json") == 0o600 and mode(cfg / "config.toml") == 0o640
    assert not (data / "pki" / "ca.key").exists()  # корневой ключ не остаётся на шлюзе
    assert verify_file(data / "audit" / "audit.log").ok


def test_init_twice_refused(env):
    base, _, _, cakey, tmp = env
    assert main(base + ["init", "--host", "x", "--ca-key-out", str(tmp / "other.key")]) == 1


def test_add_client_bundle_and_registry(env, capsys):
    base, cfg, data, cakey, tmp = env
    out = tmp / "bundle"
    assert main(base + ["add-client", "--id", "bot-1", "--ca-key", str(cakey), "--out", str(out),
                        "--allow", "POST:sendMessage"]) == 0
    cert = ca.load_cert_pem((out / "client.pem").read_bytes())
    ca_cert = ca.load_cert_pem((out / "ca.pem").read_bytes())
    assert ca.validate_client_cert(cert, ca_cert)
    reg = json.loads((cfg / "clients.json").read_text())["clients"]["bot-1"]
    assert reg["fingerprint"] == cert_fingerprint(cert)
    master = (out / "master.secret").read_text()
    assert reg["master_secret"] == master and len(bytes.fromhex(master)) == 32
    assert reg["allow"] == ["POST:sendMessage"] and reg["status"] == "active"
    if sys.platform != "win32":
        assert mode(out / "client.key") == 0o600 and mode(out / "master.secret") == 0o600
    # журнал цел и не содержит мастер-секрет
    log = data / "audit" / "audit.log"
    assert verify_file(log).ok and master.encode() not in log.read_bytes()
    capsys.readouterr()
    assert main(base + ["list-clients"]) == 0
    listing = capsys.readouterr().out
    assert "bot-1" in listing and master not in listing


def test_add_client_duplicate_and_invalid(env):
    base, _, _, cakey, tmp = env
    args = lambda cid, out, *x: base + ["add-client", "--id", cid, "--ca-key", str(cakey), "--out", str(tmp / out), *x]
    assert main(args("a", "o1")) == 0
    assert main(args("a", "o2")) == 1            # повтор id
    assert main(args("..", "o3")) == 1           # плохой id
    assert main(args("b", "o4", "--allow", "bad rule")) == 1
    assert not (tmp / "o2").exists() and not (tmp / "o3").exists()


def test_add_client_wrong_ca_key(env):
    base, _, _, _, tmp = env
    _, other = ca.create_ca()
    bad = tmp / "bad.key"
    ca.write_private_file(bad, ca.key_to_pem(other))
    # ключ чужого CA: сертификат формально выпустится, но validate_client_cert его отвергнет
    out = tmp / "bundle"
    main(base + ["add-client", "--id", "c", "--ca-key", str(bad), "--out", str(out)])
    if out.exists():
        cert = ca.load_cert_pem((out / "client.pem").read_bytes())
        assert not ca.validate_client_cert(cert, ca.load_cert_pem((out / "ca.pem").read_bytes()))


def test_audit_verify_detects_tamper(env, capsys):
    base, _, data, _, _ = env
    assert main(base + ["audit-verify"]) == 0
    log = data / "audit" / "audit.log"
    log.write_bytes(log.read_bytes().replace(b"init", b"hack"))
    assert main(base + ["audit-verify"]) == 2


def test_audit_masks_secret_values():
    from gatekeeper.server.audit.chain import AuditChain
    from gatekeeper.server.audit.sink import FileSink
    import tempfile, pathlib
    d = pathlib.Path(tempfile.mkdtemp())
    c = AuditChain(FileSink(d / "a.log"), secrets=("supersecretvalue",))
    c.append("x", {"note": "has supersecretvalue inside", "token": "t"})
    raw = (d / "a.log").read_text()
    assert "supersecretvalue" not in raw and MASK in raw
    assert AuditChain(FileSink(d / "a.log")).append("y")["seq"] == 1


def test_client_id_rules_and_cn_limit():
    from gatekeeper.core.signing import is_valid_client_id as v
    from gatekeeper.core.errors import PkiError
    assert v("bot-1") and v("a.b_c") and not v(".") and not v("..") and not v("-x")
    c, k = ca.create_ca()
    with pytest.raises(PkiError):
        ca.issue_server_cert(c, k, ["a" * 70 + ".example.com"])
