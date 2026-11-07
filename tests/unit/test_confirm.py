"""Подтверждение опасных действий: хранилище, конвейер, CLI, конфиг."""
import json
import os
import stat
import sys
import threading

import pytest

from gatekeeper.cli.main import main
from gatekeeper.core.redact import MASK
from gatekeeper.server.audit.verify import verify_file
from gatekeeper.server.config import ConfigError, load_config
from gatekeeper.server.http_io import ParsedRequest
from gatekeeper.store.approvals import (
    MAX_PER_CLIENT, MAX_PENDING, ApprovalError, Approvals, make_preview, request_key,
)

from test_pipeline import TOKEN, audit_text, call, make_env, make_req


class Clock:
    def __init__(self):
        self.t = 1_000_000

    def __call__(self):
        return self.t


BODY = b'{"chat_id":1,"text":"hi"}'


def store(tmp_path, ttl=300, clock=None):
    return Approvals(tmp_path / "approvals.json", ttl, clock or Clock())


def req(st, body=BODY, client="alice", method="POST", api="sendMessage"):
    return st.request(client, method, api, body, "preview", "203.0.113.7")


# ---- хранилище ----

def test_first_request_creates_pending_then_repeats_stay_pending(tmp_path):
    st = store(tmp_path)
    r1, r2 = req(st), req(st)
    assert (r1.state, r2.state) == ("new", "pending") and r1.id == r2.id
    assert len(st.list_items()) == 1


def test_approve_then_request_passes_once(tmp_path):
    st = store(tmp_path)
    rid = req(st).id
    assert st.approve(rid)["status"] == "approved"
    assert req(st).state == "approved"       # одноразово
    assert req(st).state == "new"            # дальше снова нужна заявка


def test_approval_is_bound_to_client_method_api_and_body(tmp_path):
    st = store(tmp_path)
    rid = req(st).id
    st.approve(rid)
    assert req(st, body=b'{"chat_id":2,"text":"evil"}').state == "new"
    assert req(st, client="bob").state == "new"
    assert req(st, method="GET").state == "new"
    assert req(st, api="deleteMessage").state == "new"
    assert req(st).state == "approved"       # исходное подтверждение не потрачено чужими


def test_pending_and_approval_expire(tmp_path):
    clk = Clock()
    st = store(tmp_path, ttl=60, clock=clk)
    rid = req(st).id
    clk.t += 60
    with pytest.raises(ApprovalError):
        st.approve(rid)                      # заявка протухла
    rid = req(st).id
    st.approve(rid)
    clk.t += 60
    assert req(st).state == "new"            # подтверждение протухло


def test_approval_ttl_counts_from_approval_moment(tmp_path):
    clk = Clock()
    st = store(tmp_path, ttl=60, clock=clk)
    rid = req(st).id
    clk.t += 50
    st.approve(rid)
    clk.t += 50                              # 100 с с заявки, но 50 с с подтверждения
    assert req(st).state == "approved"


def test_reject_removes_pending_and_unused_approval(tmp_path):
    st = store(tmp_path)
    rid = req(st).id
    st.reject(rid)
    assert req(st).state == "new"
    rid = req(st).id
    st.approve(rid)
    st.reject(rid)
    assert req(st).state == "new"


def test_id_prefix_rules(tmp_path):
    st = store(tmp_path)
    rid = req(st).id
    for bad in ("", "abc", "zzzzzzzz"):
        with pytest.raises(ApprovalError):
            st.approve(bad)
    assert st.approve(rid[:6].upper())["id"] == rid   # префикс, регистр не важен
    with pytest.raises(ApprovalError):
        st.approve(rid)                               # уже подтверждена


def test_queue_limits(tmp_path):
    st = store(tmp_path)
    for i in range(MAX_PER_CLIENT):
        assert req(st, body=str(i).encode()).state == "new"
    assert req(st, body=b"one-more").state == "full"
    assert req(st, body=b"other", client="bob").state == "new"   # чужая очередь не пострадала
    assert MAX_PER_CLIENT < MAX_PENDING


def test_key_differs_per_field():
    base = request_key("a", "POST", "x", b"1")
    assert len({base, request_key("b", "POST", "x", b"1"), request_key("a", "GET", "x", b"1"),
                request_key("a", "POST", "y", b"1"), request_key("a", "POST", "x", b"2")}) == 5


def test_preview_strips_control_chars_and_truncates():
    p = make_preview("a\x1b[31mred\x00\n" + "x" * 500)
    assert "\x1b" not in p and "\n" not in p and "\x00" not in p
    assert p.endswith("…") and len(p) <= 201


def test_malformed_file_fails_closed(tmp_path):
    st = store(tmp_path)
    (tmp_path / "approvals.json").write_text("{not json", "utf-8")
    with pytest.raises(ApprovalError):
        req(st)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_file_perms_0600(tmp_path):
    st = store(tmp_path)
    req(st)
    assert stat.S_IMODE(os.stat(tmp_path / "approvals.json").st_mode) == 0o600


def test_concurrent_requests_create_one_pending_and_one_pass(tmp_path):
    st = store(tmp_path)
    rid = req(st).id
    st.approve(rid)
    results = []

    def worker():
        results.append(req(st).state)

    ts = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert results.count("approved") == 1          # подтверждение израсходовано ровно одним


# ---- конвейер ----

def arm(env, tmp_path, apis=("sendMessage",), ttl=300):
    env.p.approvals = Approvals(tmp_path / "approvals.json", ttl)
    env.p.confirm_apis = frozenset(apis)
    return env.p.approvals


def test_confirm_flow_in_pipeline(tmp_path):
    env = make_env(tmp_path)
    st = arm(env, tmp_path)
    assert call(env, make_req(env.fp))[0] == 403 and not env.up.calls
    log = audit_text(env)
    assert "deny_confirm_required" in log and "confirm_new:" in log
    (rid, _), = st.list_items()
    st.approve(rid)
    assert call(env, make_req(env.fp))[0] == 200 and len(env.up.calls) == 1
    assert f'"confirmed":"{rid}"' in audit_text(env).replace(" ", "")
    assert call(env, make_req(env.fp))[0] == 403 and len(env.up.calls) == 1   # одноразово


def test_unlisted_api_is_not_affected(tmp_path):
    env = make_env(tmp_path)
    arm(env, tmp_path)
    assert call(env, make_req(env.fp, method="GET", target="/getMe", body=b""))[0] == 200


def test_changed_body_needs_new_approval(tmp_path):
    env = make_env(tmp_path)
    st = arm(env, tmp_path)
    call(env, make_req(env.fp))
    st.approve(st.list_items()[0][0])
    assert call(env, make_req(env.fp, body=b'{"chat_id":9,"text":"other"}'))[0] == 403
    assert not env.up.calls


def test_pending_request_is_not_counted_by_autofreeze(tmp_path):
    from gatekeeper.server.anomaly import AnomalyMonitor
    env = make_env(tmp_path)
    arm(env, tmp_path)
    env.p.anomalies = AnomalyMonitor(2, 60)
    froze = []
    env.p.freeze_client = froze.append
    for _ in range(5):
        call(env, make_req(env.fp))
    assert not froze


def test_unsigned_or_unknown_client_cannot_create_pending(tmp_path):
    env = make_env(tmp_path)
    st = arm(env, tmp_path)
    call(env, make_req(env.fp, key=bytes(32)))
    call(env, make_req(env.fp), der=b"junk")
    assert st.list_items() == []


def test_confirm_does_not_bypass_policy(tmp_path):
    env = make_env(tmp_path)
    st = arm(env, tmp_path, apis=("deleteMessage",))
    assert call(env, make_req(env.fp, target="/deleteMessage"))[0] == 403
    assert st.list_items() == [] and "deny_policy" in audit_text(env)


def test_preview_is_redacted_and_body_not_in_audit(tmp_path):
    env = make_env(tmp_path)
    st = arm(env, tmp_path)
    body = json.dumps({"chat_id": 1, "text": f"my token {TOKEN}"}).encode()
    call(env, make_req(env.fp, body=body))
    (_, e), = st.list_items()
    assert TOKEN not in e["preview"] and MASK in e["preview"]
    assert TOKEN not in audit_text(env) and "my token" not in audit_text(env)


def test_queue_full_is_alert_and_denied(tmp_path):
    env = make_env(tmp_path, burst=100, budget=1000)
    arm(env, tmp_path)
    for i in range(MAX_PER_CLIENT + 1):
        assert call(env, make_req(env.fp, body=json.dumps({"i": i}).encode()))[0] == 403
    assert "confirm_queue_full" in audit_text(env)


def test_budget_checked_after_approval(tmp_path):
    env = make_env(tmp_path, budget=1)
    st = arm(env, tmp_path)
    assert call(env, make_req(env.fp, method="GET", target="/getMe", body=b""))[0] == 200  # бюджет израсходован
    call(env, make_req(env.fp))
    st.approve(st.list_items()[0][0])
    assert call(env, make_req(env.fp))[0] == 429 and not env.up.calls[1:]


def test_approvals_store_failure_fails_closed(tmp_path):
    env = make_env(tmp_path)
    arm(env, tmp_path)
    (tmp_path / "approvals.json").write_text("garbage", "utf-8")
    assert call(env, make_req(env.fp))[0] == 500 and not env.up.calls


# ---- конфиг ----

def _cfg(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_text(text, "utf-8")
    return load_config(p)


def test_config_confirm_defaults_off(tmp_path):
    c = _cfg(tmp_path, "")
    assert c.confirm_apis == () and c.confirm_ttl == 300


def test_config_confirm_section(tmp_path):
    c = _cfg(tmp_path, '[confirm]\napis = ["deleteMessage", "banChatMember"]\nttl = 120\n')
    assert c.confirm_apis == ("deleteMessage", "banChatMember") and c.confirm_ttl == 120


@pytest.mark.parametrize("body", [
    '[confirm]\napis = "deleteMessage"\n', '[confirm]\napis = [1]\n', '[confirm]\napis = ["a/b"]\n',
    '[confirm]\napis = ["1abc"]\n', '[confirm]\nttl = 0\n', '[confirm]\nttl = 100000\n',
    '[confirm]\nbogus = 1\n'])
def test_config_confirm_rejects_bad(tmp_path, body):
    with pytest.raises(ConfigError):
        _cfg(tmp_path, body)


# ---- CLI ----

@pytest.fixture()
def cli(tmp_path):
    cfg, data = tmp_path / "cfg", tmp_path / "data"
    cakey = tmp_path / "off" / "ca.key"
    cakey.parent.mkdir()
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main(base + ["init", "--host", "127.0.0.1", "--ca-key-out", str(cakey)]) == 0
    return base, data


def test_cli_pending_approve_reject_and_audit(cli, capsys):
    base, data = cli
    st = Approvals(data / "approvals.json", 300)
    rid = req(st).id
    other = req(st, body=b"zzz").id
    capsys.readouterr()
    assert main(base + ["pending"]) == 0
    out = capsys.readouterr().out
    assert rid in out and "alice" in out and "POST:sendMessage" in out and "pending" in out
    assert main(base + ["approve", "--id", rid[:8]]) == 0
    assert main(base + ["reject", "--id", other]) == 0
    assert main(base + ["approve", "--id", rid]) == 1       # уже подтверждена
    assert main(base + ["reject", "--id", "ffffffffffff"]) == 1
    assert req(st).state == "approved"
    log = (data / "audit" / "audit.log").read_text()
    assert "confirm_approved" in log and "confirm_rejected" in log
    assert verify_file(data / "audit" / "audit.log").ok


def test_cli_pending_empty(cli, capsys):
    base, _ = cli
    capsys.readouterr()
    assert main(base + ["pending"]) == 0
    assert "no pending" in capsys.readouterr().out


def test_cli_pending_sanitizes_tampered_preview(cli, capsys):
    base, data = cli
    st = Approvals(data / "approvals.json", 300)
    st.request("alice", "POST", "sendMessage", b"x", "ok\x1b[2Jevil", "1.2.3.4")
    capsys.readouterr()
    assert main(base + ["pending"]) == 0
    assert "\x1b" not in capsys.readouterr().out
