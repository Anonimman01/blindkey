"""Регрессионные тесты 0.3.3: H1, H2, M7, L2, L3, L4, L9 из углублённого аудита 0.3.2."""
import os
import socket
import sys
import time

import pytest
from test_pipeline import audit_text, call, make_env, make_req
from test_telegram_provider import TOKEN as TG_TOKEN

from gatekeeper.core.redact import MASK, redact_text
from gatekeeper.core.signing import is_valid_client_id
from gatekeeper.server.app import _unlink_if_socket
from gatekeeper.server.config import ConfigError, load_config
from gatekeeper.server.honey.decoys import DecoyError, DecoyStore
from gatekeeper.server.providers.base import UpstreamResponse
from gatekeeper.server.providers.github import GitHubProvider
from gatekeeper.server.providers.telegram import TelegramProvider
from gatekeeper.store.approvals import Approvals

JSON = "application/json"
GH_TOKEN = "ghp_" + "A1b2C3d4E5" * 4
LOOKALIKE = "123456789:" + "Q" * 35  # по форме токен Telegram, но не наш


# ---- H1: токеноподобная строка в чужом сообщении не блокирует ответ ----

def test_tokenlike_message_does_not_poison_get_updates():
    body = ('{"ok":true,"result":[{"update_id":1,"message":{"text":"' + LOOKALIKE + '"}}]}').encode()
    resp = UpstreamResponse(200, JSON, body)
    assert TelegramProvider(TG_TOKEN).filter_response(resp) is resp


def test_github_tokenlike_text_not_blocked_but_exact_token_is():
    other = "ghp_" + "Z9y8X7w6V5" * 4
    p = GitHubProvider(GH_TOKEN)
    ok = UpstreamResponse(200, JSON, ('{"bio":"' + other + '"}').encode())
    assert p.filter_response(ok) is ok
    bad = UpstreamResponse(200, JSON, ('{"bio":"' + GH_TOKEN + '"}').encode())
    assert p.filter_response(bad) is None


def test_exact_secret_parts_still_blocked():
    p = TelegramProvider(TG_TOKEN)
    secret_part = TG_TOKEN.split(":", 1)[1]
    for text in (TG_TOKEN, secret_part):
        assert p.filter_response(UpstreamResponse(200, "text/plain", text.encode())) is None


def test_pipeline_passes_tokenlike_response(tmp_path):
    env = make_env(tmp_path)
    env.up.response = UpstreamResponse(200, JSON, ('{"text":"' + LOOKALIKE + '"}').encode())
    status, _ = call(env, make_req(env.fp))
    assert status == 200
    assert "response_secret_blocked" not in audit_text(env)


# ---- H2: длинные цифровые строки обрабатываются быстро ----

@pytest.mark.parametrize("provider", [TelegramProvider(TG_TOKEN), GitHubProvider(GH_TOKEN)])
def test_long_digit_string_is_fast(provider):
    body = ('{"text":"' + "1" * 20_000 + '"}').encode()
    started = time.monotonic()
    resp = UpstreamResponse(200, JSON, body)
    assert provider.filter_response(resp) is resp
    assert time.monotonic() - started < 1.0


def test_many_long_digit_messages_are_fast():
    p = TelegramProvider(TG_TOKEN)
    msgs = ",".join('{"text":"' + "7" * 4096 + '"}' for _ in range(100))
    resp = UpstreamResponse(200, JSON, ("[" + msgs + "]").encode())
    started = time.monotonic()
    assert p.filter_response(resp) is resp
    assert time.monotonic() - started < 2.0


# ---- M7: маскирование и предпросмотр не квадратичны ----

def test_redact_text_many_begin_markers_is_fast():
    text = "-----BEGIN PRIVATE KEY-----" * 20_000  # без END
    started = time.monotonic()
    redact_text(text)
    assert time.monotonic() - started < 3.0


def test_redact_still_masks_normal_pem():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBabc+/=\n-----END RSA PRIVATE KEY-----"
    assert redact_text("x " + pem + " y") == f"x {MASK} y"


def test_confirm_preview_of_huge_body_is_fast(tmp_path):
    env = make_env(tmp_path)
    env.p.approvals = Approvals(tmp_path / "approvals.json", 300)
    env.p.confirm_apis = frozenset({"sendMessage"})
    body = b"-----BEGIN PRIVATE KEY-----" * 30_000
    started = time.monotonic()
    status, _ = call(env, make_req(env.fp, body=body))
    assert status == 403  # ждёт подтверждения
    assert time.monotonic() - started < 3.0


# ---- L2: [confirm] без учёта регистра ----

def test_confirm_matches_api_name_case_insensitively(tmp_path):
    env = make_env(tmp_path)
    env.p.approvals = Approvals(tmp_path / "approvals.json", 300)
    env.p.confirm_apis = frozenset({"sendmessage"})  # в политике клиента: sendMessage
    assert call(env, make_req(env.fp))[0] == 403
    assert not env.up.calls


# ---- L3: fullmatch вместо match с «$» ----

def test_trailing_newline_rejected_everywhere(tmp_path):
    assert is_valid_client_id("alice")
    assert not is_valid_client_id("alice\n")
    with pytest.raises(DecoyError):
        DecoyStore(tmp_path / "d.json").add("x", "a" * 64 + "\n", 1)


def test_providers_reject_token_with_trailing_newline():
    from gatekeeper.server.providers.base import ProviderError
    with pytest.raises(ProviderError):
        TelegramProvider(TG_TOKEN + "\n")
    with pytest.raises(ProviderError):
        GitHubProvider(GH_TOKEN + "\n")


def test_downloadfile_path_with_newline_rejected():
    from gatekeeper.server.providers.base import ProviderError
    with pytest.raises(ProviderError):
        TelegramProvider(TG_TOKEN).build_request(
            "downloadFile", "POST", b'{"file_path":"photos/a.jpg\\n"}', JSON)


# ---- L4: upstream_tls=false только для loopback ----

def _cfg(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_text(text, "utf-8")
    return load_config(p)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_plain_upstream_allowed_on_loopback(tmp_path, host):
    c = _cfg(tmp_path, f'[provider]\nupstream_host = "{host}"\nupstream_tls = false\n')
    assert c.upstream_tls is False


@pytest.mark.parametrize("body", [
    "[provider]\nupstream_tls = false\n",
    '[provider]\nupstream_host = "api.telegram.org"\nupstream_tls = false\n',
    '[provider]\nupstream_host = "10.0.0.5"\nupstream_tls = false\n',
])
def test_plain_upstream_rejected_off_loopback(tmp_path, body):
    with pytest.raises(ConfigError):
        _cfg(tmp_path, body)


def test_tls_upstream_default_still_valid(tmp_path):
    assert _cfg(tmp_path, "").upstream_tls is True


# ---- L9: сокет метрик удаляется, только если это сокет ----

def test_unlink_if_socket_leaves_regular_file(tmp_path):
    f = tmp_path / "important.txt"
    f.write_text("data", "utf-8")
    assert _unlink_if_socket(str(f)) is False
    assert f.read_text("utf-8") == "data"


def test_unlink_if_socket_missing_path_is_ok(tmp_path):
    assert _unlink_if_socket(str(tmp_path / "none.sock")) is True


@pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets")
def test_unlink_if_socket_removes_stale_socket(tmp_path):
    path = str(tmp_path / "ops.sock")
    s = socket.socket(socket.AF_UNIX)
    s.bind(path)
    s.close()
    assert os.path.exists(path)
    assert _unlink_if_socket(path) is True
    assert not os.path.exists(path)


@pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets")
def test_ops_socket_start_refuses_regular_file(tmp_path):
    import asyncio

    from test_ops_socket import make_app

    f = tmp_path / "ops.sock"
    f.write_text("not a socket", "utf-8")
    app = make_app(f)
    with pytest.raises(ConfigError):
        asyncio.run(app._start_ops_socket())
    assert f.read_text("utf-8") == "not a socket"
