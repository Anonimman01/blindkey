"""Тесты сборки ответа: нейтральность и защита от инъекции заголовков."""
import pytest

from gatekeeper.server.http_response import NEUTRAL_BODY, build_response, neutral_response


def test_build_response_shape():
    raw = build_response(200, b"abc", "text/plain")
    head, _, body = raw.partition(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 200 OK\r\n")
    assert b"Content-Length: 3" in head and b"Connection: close" in head
    assert body == b"abc"


def test_neutral_bodies_identical_across_statuses():
    bodies = {neutral_response(s).partition(b"\r\n\r\n")[2] for s in (400, 403, 429, 503)}
    assert bodies == {NEUTRAL_BODY}


def test_neutral_unknown_status_falls_back_to_400():
    assert neutral_response(418).startswith(b"HTTP/1.1 400 ")


@pytest.mark.parametrize("bad", ["a\r\nX: y", "a\nb", "a\x00b", "é"])
def test_header_injection_rejected(bad):
    with pytest.raises(ValueError):
        build_response(200, b"", None, {"X-Test": bad})
    with pytest.raises(ValueError):
        build_response(200, b"", bad)


@pytest.mark.parametrize("name", ["Content-Length", "connection", "Transfer-Encoding", "A B", "A:B", ""])
def test_reserved_or_bad_header_names_rejected(name):
    with pytest.raises(ValueError):
        build_response(200, b"", None, {name: "v"})


def test_unknown_status_rejected():
    with pytest.raises(ValueError):
        build_response(999, b"")
