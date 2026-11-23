"""Подтверждаемые методы: только JSON, тело пересобирается канонически (C-04, X-03)."""
import hashlib
import json

from test_pipeline import audit_text, call, make_env, make_req

from gatekeeper.store.approvals import Approvals, request_key


def confirm_env(tmp_path):
    env = make_env(tmp_path)
    env.p.approvals = Approvals(tmp_path / "approvals.json", ttl=300)
    env.p.confirm_apis = frozenset({"sendmessage"})
    return env


def test_request_key_includes_content_type():
    a = request_key("alice", "POST", "sendMessage", b"{}", "application/json")
    b = request_key("alice", "POST", "sendMessage", b"{}", "application/x-www-form-urlencoded")
    assert a != b
    assert a == request_key("alice", "POST", "sendMessage", b"{}", "application/json")


def test_old_format_record_is_dropped_not_fatal(tmp_path):
    path = tmp_path / "approvals.json"
    body = b'{"chat_id":1}'
    digest = hashlib.sha256(body).hexdigest()
    old_raw = "\n".join(("alice", "POST", "sendMessage", digest))  # ключ старого формата
    key = hashlib.sha256(old_raw.encode("utf-8")).hexdigest()
    path.write_text(json.dumps({"version": 1, "items": {key: {
        "client": "alice", "method": "POST", "api": "sendMessage",
        "body_sha256": digest, "body_len": len(body), "preview": "x", "ip": "1.2.3.4",
        "status": "approved", "created": 0, "expires": 9_999_999_999}}}), encoding="utf-8")
    path.chmod(0o600)
    ap = Approvals(path, ttl=300)
    assert ap.list_items() == []          # старая запись проигнорирована, а не уронила чтение
    assert ap.last_dropped == 1
    assert "body_sha256" not in path.read_text(encoding="utf-8")  # и вычищена из файла
    res = ap.request("alice", "POST", "sendMessage", body, "x", "1.2.3.4", "application/json")
    assert res.state == "new"             # старое «approved» не выдаёт подтверждение


def test_form_and_multipart_confirm_get_400(tmp_path):
    env = confirm_env(tmp_path)
    for ct in ("application/x-www-form-urlencoded", "multipart/form-data; boundary=x",
               "text/plain", ""):
        req = make_req(env.fp, body=b"chat_id=1&text=hi")
        req.headers["content-type"] = ct
        status, _ = call(env, req)
        assert status == 400, ct
    assert not env.up.calls


def test_empty_body_passes_without_content_type(tmp_path):
    """Пустое тело пересобирать не из чего: подтверждение работает как раньше (X-03)."""
    env = confirm_env(tmp_path)
    req = make_req(env.fp, body=b"")
    req.headers.pop("content-type")
    status, _ = call(env, req)
    assert status == 403 and "confirm_new" in audit_text(env)
    assert len(env.p.approvals.list_items()) == 1


def test_json_confirm_forwards_canonical_body(tmp_path):
    env = confirm_env(tmp_path)
    body = b'{ "text" : "hi", "chat_id" : 1 }'
    status, _ = call(env, make_req(env.fp, body=body))
    assert status == 403 and "confirm_new" in audit_text(env)
    items = env.p.approvals.list_items()
    assert len(items) == 1
    assert items[0][1]["content_type"] == "application/json"
    env.p.approvals.approve(items[0][0])
    status, _ = call(env, make_req(env.fp, body=body))
    assert status == 200
    sent = env.up.calls[-1]
    assert sent.body == b'{"chat_id":1,"text":"hi"}'   # ровно то, что видел оператор
    assert any(k.lower() == "content-type" and v == "application/json" for k, v in sent.headers)
