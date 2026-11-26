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


def _client(env, cid="b1"):
    base, _cfg, _data, cakey, tmp = env
    assert main([*base, "add-client", "--id", cid, "--ca-key", str(cakey),
                 "--out", str(tmp / cid)]) == 0
    return base


def _status(cfg, cid="b1"):
    return json.loads((cfg / "clients.json").read_text())["clients"][cid]["status"]


def test_state_commands_do_not_change_state_without_the_journal(env, capsys):
    """A3: сначала журнал, потом состояние. Без журнала команда только сообщает об ошибке."""
    base = _client(env)
    _base, cfg, data, _cakey, _tmp = env
    (data / "audit" / "audit.log").write_bytes(b"garbage\n")
    capsys.readouterr()
    assert main([*base, "freeze", "--id", "b1"]) == 1
    assert _status(cfg) == "active"
    err = capsys.readouterr().err
    assert "audit log is unavailable" in err and "was not changed" in err


def test_unfreeze_does_not_change_state_without_the_journal(env, capsys):
    base = _client(env)
    _base, cfg, data, _cakey, _tmp = env
    assert main([*base, "freeze", "--id", "b1"]) == 0
    (data / "audit" / "audit.log").write_bytes(b"garbage\n")
    capsys.readouterr()
    assert main([*base, "unfreeze", "--id", "b1"]) == 1
    assert _status(cfg) == "frozen"


def test_revoke_does_not_change_state_without_the_journal(env, capsys):
    base = _client(env)
    _base, cfg, data, _cakey, _tmp = env
    (data / "audit" / "audit.log").write_bytes(b"garbage\n")
    capsys.readouterr()
    assert main([*base, "revoke", "--id", "b1"]) == 1
    assert _status(cfg) == "active"
    assert "--force-no-audit" in capsys.readouterr().out  # подсказка про аварийный режим


def test_state_change_is_recorded_in_the_journal(env):
    """A3: успешная команда оставляет запись, журнал остаётся целым."""
    base = _client(env)
    _base, cfg, data, _cakey, _tmp = env
    assert main([*base, "freeze", "--id", "b1"]) == 0
    assert _status(cfg) == "frozen"
    log = (data / "audit" / "audit.log").read_text()
    assert "client_frozen" in log and verify_file(data / "audit" / "audit.log").ok


def test_unknown_client_writes_no_state_event(env, capsys):
    """Неизвестный id не меняет состояние и не оставляет в журнале ложный client_frozen."""
    base = _client(env)
    _base, _cfg, data, _cakey, _tmp = env
    log = data / "audit" / "audit.log"
    before = log.read_text(encoding="utf-8")
    capsys.readouterr()
    assert main([*base, "freeze", "--id", "nope"]) == 1
    assert "unknown client" in capsys.readouterr().err
    assert log.read_text(encoding="utf-8") == before


def test_revoke_force_no_audit_works_with_a_broken_journal(env, capsys):
    """A3: аварийный отзыв проходит без журнала и громко об этом предупреждает."""
    base = _client(env)
    _base, cfg, data, _cakey, _tmp = env
    (data / "audit" / "audit.log").write_bytes(b"garbage\n")
    capsys.readouterr()
    assert main([*base, "revoke", "--id", "b1", "--force-no-audit"]) == 0
    assert _status(cfg) == "revoked"
    out = capsys.readouterr()
    assert "WITHOUT an audit record" in out.err and "WARNING" in out.err


def test_revoke_force_no_audit_still_writes_the_journal_when_it_works(env):
    base = _client(env)
    _base, cfg, data, _cakey, _tmp = env
    assert main([*base, "revoke", "--id", "b1", "--force-no-audit"]) == 0
    assert _status(cfg) == "revoked"
    assert "client_revoked" in (data / "audit" / "audit.log").read_text()


def test_force_no_audit_exists_only_for_revoke(env):
    base = _client(env)
    with pytest.raises(SystemExit):
        main([*base, "freeze", "--id", "b1", "--force-no-audit"])


def test_failed_state_change_after_the_journal_is_an_explicit_abort(env, capsys):
    """A3: журнал записан, изменение состояния не удалось — явный итог «не выполнено»."""
    base = _client(env)
    _base, _cfg, data, _cakey, _tmp = env
    assert main([*base, "freeze", "--id", "b1"]) == 0
    capsys.readouterr()
    assert main([*base, "freeze", "--id", "b1"]) == 1        # frozen -> frozen невозможно
    log = (data / "audit" / "audit.log").read_text()
    assert "request_aborted" in log and "state_change_failed" in log
    assert "the state was not changed" in capsys.readouterr().err


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
