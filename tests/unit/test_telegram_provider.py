import pytest

from gatekeeper.server.providers.base import ProviderError, UpstreamResponse
from gatekeeper.server.providers.telegram import TelegramProvider

TOKEN = "123456789:AAH-fakeFAKEfakeFAKEfakeFAKEfake12345"


def prov():
    return TelegramProvider(TOKEN)


def test_token_goes_only_into_path():
    r = prov().build_request("sendMessage", "POST", b'{"a":1}', "application/json")
    assert r.path == f"/bot{TOKEN}/sendMessage" and r.method == "POST"
    assert TOKEN not in repr(r.headers)


def test_invalid_token_rejected():
    with pytest.raises(ProviderError):
        TelegramProvider("bad token/with space")


def test_bad_content_type_rejected():
    for ct in (None, "text/html", "application/json\r\nX: y", "application/xml"):
        with pytest.raises(ProviderError):
            prov().build_request("sendMessage", "POST", b"x", ct)


def test_get_without_body_needs_no_content_type():
    r = prov().build_request("getMe", "GET", b"", None)
    assert r.path.endswith("/getMe") and r.body == b""


def test_download_file_builds_get_to_file_path():
    r = prov().build_request("downloadFile", "POST", b'{"file_path":"photos/file_1.jpg"}', "application/json")
    assert r.method == "GET" and r.path == f"/file/bot{TOKEN}/photos/file_1.jpg"


@pytest.mark.parametrize("fp", ["../x", "a/../b", "/etc/passwd", "a//b", "a b", "a?x=1", "", 5, None])
def test_download_file_bad_paths(fp):
    import json
    with pytest.raises(ProviderError):
        prov().build_request("downloadFile", "POST", json.dumps({"file_path": fp}).encode(), "application/json")


def test_download_file_requires_post_and_json():
    with pytest.raises(ProviderError):
        prov().build_request("downloadFile", "GET", b"", None)
    with pytest.raises(ProviderError):
        prov().build_request("downloadFile", "POST", b"not json", "application/json")


def test_response_with_token_blocked():
    for body in (TOKEN.encode(), TOKEN.split(":")[1].encode(), b'{"u":"/bot' + TOKEN.encode() + b'/x"}'):
        assert prov().filter_response(UpstreamResponse(200, "application/json", body)) is None


def test_normal_response_passes():
    r = UpstreamResponse(200, "application/json", b'{"ok":true,"result":{"id":1}}')
    assert prov().filter_response(r) is r
    img = UpstreamResponse(200, "image/jpeg", b"\xff\xd8\xff\x00binary")
    assert prov().filter_response(img) is img


def _json(body: bytes) -> UpstreamResponse:
    return UpstreamResponse(200, "application/json", body)


@pytest.mark.parametrize("text", [
    "/bothelp", "/bot", "use /botfather", "Bearer authentication", "bearer tokens are fine",
    "-----BEGIN PRIVATE KEY----- в тексте письма",
])
def test_innocent_text_not_blocked(text):
    import json
    body = json.dumps({"ok": True, "result": {"text": text}}, ensure_ascii=False).encode()
    r = _json(body)
    assert prov().filter_response(r) is r


def test_token_in_body_blocked_plain_and_escaped():
    import json
    for body in (
        json.dumps({"text": f"x {TOKEN} y"}).encode(),
        json.dumps({"text": TOKEN}, ensure_ascii=True).encode(),
        # JSON-экранирование: каждая буква секрета как \uXXXX
        ('{"text":"' + "".join(f"\\u{ord(c):04x}" for c in TOKEN) + '"}').encode(),
        json.dumps({TOKEN: 1}).encode(),
        json.dumps({"a": [{"b": TOKEN.split(":")[1]}]}).encode(),
    ):
        assert prov().filter_response(_json(body)) is None


def test_foreign_full_token_pattern_blocked():
    other = "987654321:BBH-otherOTHERotherOTHERotherOTHER99"
    assert prov().filter_response(_json(f'{{"text":"{other}"}}'.encode())) is None
    plain = UpstreamResponse(200, "text/plain", other.encode())
    assert prov().filter_response(plain) is None


def test_non_json_body_with_json_content_type_checked_raw():
    r = _json(b"not json at all /bothelp")
    assert prov().filter_response(r) is r
    assert prov().filter_response(_json(b"not json " + TOKEN.encode())) is None


def test_deeply_nested_json_fails_closed():
    assert prov().filter_response(_json(b"[" * 100000 + b"]" * 100000)) is None


def test_upstream_timeout_default_for_ordinary_methods():
    assert prov().upstream_timeout("sendMessage", b'{"timeout": 40}') is None


def test_upstream_timeout_for_get_updates():
    p = prov()
    assert p.upstream_timeout("getUpdates", b"") == 10.0
    assert p.upstream_timeout("getUpdates", b'{"timeout": 30}') == 40.0
    assert p.upstream_timeout("getUpdates", b'{"timeout": 9999}') == 60.0  # потолок 50 + запас
    for bad in (b'{"timeout": -5}', b'{"timeout": "x"}', b'{"timeout": true}', b"not json", b"[1]"):
        assert p.upstream_timeout("getUpdates", bad) == 10.0


def test_json_depth_limit_is_explicit():
    from gatekeeper.server.providers.telegram import MAX_JSON_DEPTH
    ok = b"[" * MAX_JSON_DEPTH + b"]" * MAX_JSON_DEPTH
    too_deep = b"[" * (MAX_JSON_DEPTH + 1) + b"]" * (MAX_JSON_DEPTH + 1)
    r = _json(ok)
    assert prov().filter_response(r) is r
    assert prov().filter_response(_json(too_deep)) is None


def test_brackets_inside_strings_do_not_count_as_depth():
    body = ('{"text":"' + "[" * 500 + '\\"' + "{" * 500 + '"}').encode()
    r = _json(body)
    assert prov().filter_response(r) is r
