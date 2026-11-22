"""C-04: подтверждаемый запрос разбирается как строгое JSON, оператор видит параметры."""
import pytest
from test_pipeline import call, make_env, make_req

from gatekeeper.core.redact import MASK
from gatekeeper.server.confirm_body import (
    ConfirmBodyError,
    describe_params,
    parse_confirm_params,
)
from gatekeeper.store.approvals import Approvals


def test_parameters_are_parsed_as_json():
    assert parse_confirm_params(b'{"chat_id":1,"text":"hi"}') == {"chat_id": 1, "text": "hi"}
    assert parse_confirm_params(b"") is None
    assert parse_confirm_params(b"   \n") is None


def test_duplicate_key_in_tail_is_rejected():
    # Именно этот приём обходил предпросмотр: Telegram применяет последнее значение.
    with pytest.raises(ConfirmBodyError, match="duplicate"):
        parse_confirm_params(b'{"user_id":1,"text":"x","user_id":2}')


def test_duplicate_key_at_any_depth_is_rejected():
    with pytest.raises(ConfirmBodyError, match="duplicate"):
        parse_confirm_params(b'{"a":{"user_id":1,"user_id":2}}')


@pytest.mark.parametrize("body", [
    b"not json", b"\xff\xfe", b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
])
def test_non_strict_json_is_rejected(body):
    with pytest.raises(ConfirmBodyError):
        parse_confirm_params(body)


def test_too_deep_json_is_rejected():
    with pytest.raises(ConfirmBodyError, match="deep"):
        parse_confirm_params(b"[" * 5000 + b"]" * 5000)


def test_preview_shows_parameters_not_the_raw_prefix():
    params = parse_confirm_params(b'{"chat_id":1,"text":"hi"}')
    assert describe_params(params) == '{"chat_id":1,"text":"hi"}'
    assert describe_params(None) == "(no parameters)"


def test_preview_masks_secrets_and_control_chars():
    text = describe_params({"token": "supersecretvalue", "text": "a\x1b\nb"},
                           ("supersecretvalue",))
    assert "supersecretvalue" not in text and MASK in text
    assert "\x1b" not in text and "\n" not in text


def test_pipeline_denies_duplicate_keys_before_upstream(tmp_path):
    env = make_env(tmp_path)
    env.p.approvals = Approvals(tmp_path / "approvals.json", 300)
    env.p.confirm_apis = frozenset({"sendMessage"})
    body = b'{"chat_id":1,"text":"hi","chat_id":2}'
    status, _ = call(env, make_req(env.fp, body=body))
    assert status == 400 and not env.up.calls
    assert "duplicate JSON key" in env.audit_path.read_text()


def test_pipeline_stores_parameters_for_the_operator(tmp_path):
    env = make_env(tmp_path)
    store = Approvals(tmp_path / "approvals.json", 300)
    env.p.approvals = store
    env.p.confirm_apis = frozenset({"sendMessage"})
    assert call(env, make_req(env.fp))[0] == 403
    (_rid, entry), = store.list_items()
    assert entry["preview"] == '{"chat_id":1,"text":"hi"}'
