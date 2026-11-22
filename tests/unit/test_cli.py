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
    assert main([*base, "init", "--host", "127.0.0.1", "--host", "gw.example", "--ca-key-out", str(cakey)]) == 0
    return base, cfg, data, cakey, tmp_path


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def test_init_layout_and_perms(env):
    _base, cfg, data, cakey, _ = env
    if sys.platform != "win32":
        assert mode(data) == 0o700 and mode(data / "pki") == 0o700 and mode(data / "audit") == 0o700
        assert mode(data / "pki" / "server.key") == 0o600 and mode(cakey) == 0o600
        assert mode(cfg / "clients.json") == 0o600 and mode(cfg / "config.toml") == 0o640
    assert not (data / "pki" / "ca.key").exists()  # корневой ключ не остаётся на шлюзе
    assert verify_file(data / "audit" / "audit.log").ok


def test_init_twice_is_idempotent(env):
    base, _cfg, data, _cakey, tmp = env
    before = (data / "pki" / "server.pem").read_bytes()
    other = tmp / "other.key"
    # Повторный init ничего не пересоздаёт и не перезаписывает (B-12).
    assert main([*base, "init", "--host", "x", "--ca-key-out", str(other)]) == 0
    assert not other.exists()
    assert (data / "pki" / "server.pem").read_bytes() == before


def test_init_resumes_after_partial_failure(env):
    base, _cfg, data, cakey, _tmp = env
    # Имитируем сбой посередине: серверная пара потеряна, CA и реестр на месте.
    (data / "pki" / "server.pem").unlink()
    (data / "pki" / "server.key").unlink()
    assert main([*base, "init", "--host", "gw.example", "--ca-key", str(cakey),
                 "--ca-key-out", str(cakey)]) == 0
    assert (data / "pki" / "server.pem").exists() and (data / "pki" / "server.key").exists()
    cert = ca.load_cert_pem((data / "pki" / "server.pem").read_bytes())
    assert ca.cert_hosts(cert) == ["gw.example"]  # SAN переданного --host
    assert verify_file(data / "audit" / "audit.log").ok


def test_add_client_bundle_and_registry(env, capsys):
    base, cfg, data, cakey, tmp = env
    out = tmp / "bundle"
    assert main([*base, "add-client", "--id", "bot-1", "--ca-key", str(cakey), "--out", str(out), "--allow", "POST:sendMessage"]) == 0
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
    assert main([*base, "list-clients"]) == 0
    listing = capsys.readouterr().out
    assert "bot-1" in listing and master not in listing


def test_add_client_duplicate_and_invalid(env):
    base, _, _, cakey, tmp = env
    def args(cid, out, *x):
        return [*base, "add-client", "--id", cid, "--ca-key", str(cakey), "--out", str(tmp / out), *x]
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
    main([*base, "add-client", "--id", "c", "--ca-key", str(bad), "--out", str(out)])
    if out.exists():
        cert = ca.load_cert_pem((out / "client.pem").read_bytes())
        assert not ca.validate_client_cert(cert, ca.load_cert_pem((out / "ca.pem").read_bytes()))


def test_audit_verify_detects_tamper(env, capsys):
    base, _, data, _, _ = env
    assert main([*base, "audit-verify"]) == 0
    log = data / "audit" / "audit.log"
    log.write_bytes(log.read_bytes().replace(b"init", b"hack"))
    assert main([*base, "audit-verify"]) == 2


def test_audit_masks_secret_values():
    import pathlib
    import tempfile

    from gatekeeper.server.audit.chain import AuditChain
    from gatekeeper.server.audit.sink import FileSink
    d = pathlib.Path(tempfile.mkdtemp())
    c = AuditChain(FileSink(d / "a.log"), secrets=("supersecretvalue",))
    c.append("x", {"note": "has supersecretvalue inside", "token": "t"})
    raw = (d / "a.log").read_text()
    assert "supersecretvalue" not in raw and MASK in raw
    assert AuditChain(FileSink(d / "a.log")).append("y")["seq"] == 1


def test_client_id_rules_and_cn_limit():
    from gatekeeper.core.errors import PkiError
    from gatekeeper.core.signing import is_valid_client_id as v
    assert v("bot-1") and v("a.b_c") and not v(".") and not v("..") and not v("-x")
    c, k = ca.create_ca()
    with pytest.raises(PkiError):
        ca.issue_server_cert(c, k, ["a" * 70 + ".example.com"])


def test_status_reports_ok_and_detects_broken_journal(env):
    base, _cfg, data, _cakey, _ = env
    assert main([*base, "status"]) == 0
    log = data / "audit" / "audit.log"
    log.write_bytes(log.read_bytes().replace(b'"type":"', b'"type":"x', 1))
    assert main([*base, "status"]) == 2


def test_list_clients_survives_a_non_numeric_expiry(env, capsys):
    """B-15: испорченный expires не скрывает весь список."""
    base, cfg, _data, cakey, tmp = env
    assert main([*base, "add-client", "--id", "b1", "--ca-key", str(cakey),
                 "--out", str(tmp / "b1")]) == 0
    doc = json.loads((cfg / "clients.json").read_text())
    doc["clients"]["b1"]["expires"] = "soon"
    doc["clients"]["broken"] = "not an object"
    (cfg / "clients.json").write_text(json.dumps(doc), encoding="utf-8")
    capsys.readouterr()
    assert main([*base, "list-clients"]) == 0
    listing = capsys.readouterr().out
    assert "b1" in listing and "expires invalid" in listing and "broken" in listing


def test_freeze_applies_even_when_the_journal_is_broken(env, capsys):
    """C-05: состояние меняется первым, оператор видит явное предупреждение."""
    base, cfg, data, cakey, tmp = env
    assert main([*base, "add-client", "--id", "b1", "--ca-key", str(cakey),
                 "--out", str(tmp / "b1")]) == 0
    (data / "audit" / "audit.log").write_bytes(b"garbage\n")
    assert main([*base, "freeze", "--id", "b1"]) == 0
    assert json.loads((cfg / "clients.json").read_text())["clients"]["b1"]["status"] == "frozen"
    out = capsys.readouterr()
    assert "not updated" in (out.out + out.err)


def test_approve_writes_the_journal_first(env):
    """C-05: без журнала подтверждение не выдаётся."""
    from gatekeeper.store.approvals import APPROVED, Approvals

    base, _cfg, data, _cakey, _tmp = env
    store = Approvals(data / "approvals.json", 300)
    rid = store.request("b1", "POST", "sendMessage", b"{}", "params", "203.0.113.7").id
    (data / "audit" / "audit.log").write_bytes(b"garbage\n")
    assert main([*base, "approve", "--id", rid]) == 1
    (_rid, entry), = store.list_items()
    assert entry["status"] != APPROVED


def test_pending_survives_a_damaged_record(env, capsys):
    """B-10: повреждённая запись не ломает pending."""
    from gatekeeper.store.approvals import Approvals

    base, _cfg, data, _cakey, _tmp = env
    store = Approvals(data / "approvals.json", 300)
    assert store.request("b1", "POST", "sendMessage", b"{}", "params", "1.2.3.4").state == "new"
    doc = json.loads((data / "approvals.json").read_text())
    doc["items"]["a" * 64] = {"status": "approved"}
    (data / "approvals.json").write_text(json.dumps(doc), encoding="utf-8")
    capsys.readouterr()
    assert main([*base, "pending"]) == 0
    out = capsys.readouterr()
    assert "damaged" in (out.out + out.err)


def test_ca_key_can_be_encrypted(tmp_path, monkeypatch):
    """C-09: ca.key шифруется фразой; без неё операции выпуска не работают."""
    from gatekeeper.core.errors import PkiError

    cfg, data = tmp_path / "cfg", tmp_path / "data"
    off = tmp_path / "off"
    off.mkdir()
    cakey, passfile = off / "ca.key", off / "pass"
    passfile.write_text("hunter2\n", encoding="utf-8")
    passfile.chmod(0o600)
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(cakey),
                 "--ca-key-pass-file", str(passfile)]) == 0
    assert b"ENCRYPTED" in cakey.read_bytes()
    with pytest.raises(PkiError):
        ca.load_key_pem(cakey.read_bytes())
    assert main([*base, "add-client", "--id", "a1", "--ca-key", str(cakey),
                 "--out", str(tmp_path / "b1")]) == 1
    assert main([*base, "add-client", "--id", "a1", "--ca-key", str(cakey),
                 "--ca-key-pass-file", str(passfile), "--out", str(tmp_path / "b1")]) == 0
    # фразу можно передать переменной окружения
    monkeypatch.setenv("GATEKEEPER_CA_KEY_PASSPHRASE", "hunter2")
    assert main([*base, "add-client", "--id", "a2", "--ca-key", str(cakey),
                 "--out", str(tmp_path / "b2")]) == 0
