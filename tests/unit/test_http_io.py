"""Тесты чтения HTTP: smuggling, slowloris, огромные заголовки, запреты."""
import asyncio

import pytest

from gatekeeper.server.http_io import HttpError, HttpLimits, read_request

OK = b"POST /sendMessage HTTP/1.1\r\nHost: gw\r\nContent-Length: 5\r\n\r\nhello"


async def _run(raw: bytes, limits=None, eof=True):
    reader = asyncio.StreamReader()
    reader.feed_data(raw)
    if eof:
        reader.feed_eof()
    return await read_request(reader, limits)


def parse(raw: bytes, limits=None, eof=True):
    return asyncio.run(_run(raw, limits, eof))


def denied(raw: bytes, limits=None, eof=True) -> HttpError:
    with pytest.raises(HttpError) as ei:
        parse(raw, limits, eof)
    return ei.value


def test_valid_request_parsed():
    r = parse(OK)
    assert r.method == "POST" and r.target == "/sendMessage"
    assert r.body == b"hello"
    assert r.headers["host"] == "gw" and r.headers["content-length"] == "5"


def test_get_without_body():
    r = parse(b"GET /getMe HTTP/1.1\r\nHost: gw\r\n\r\n")
    assert r.method == "GET" and r.body == b""


# ---- request smuggling ----

def test_content_length_and_transfer_encoding_conflict():
    raw = (b"POST /sendMessage HTTP/1.1\r\nHost: gw\r\nContent-Length: 5\r\n"
           b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    assert denied(raw).status == 400


def test_transfer_encoding_alone_denied():
    raw = b"POST /sendMessage HTTP/1.1\r\nHost: gw\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
    assert denied(raw).status == 400


def test_obfuscated_transfer_encoding_denied():
    raw = (b"POST /sendMessage HTTP/1.1\r\nHost: gw\r\nContent-Length: 5\r\n"
           b"Transfer-Encoding: xchunked\r\n\r\nhello")
    assert denied(raw).status == 400


def test_duplicate_content_length_denied():
    raw = b"POST /x HTTP/1.1\r\nHost: gw\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"
    assert denied(raw).status == 400


def test_conflicting_content_length_denied():
    raw = b"POST /x HTTP/1.1\r\nHost: gw\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!"
    assert denied(raw).status == 400


def test_negative_or_garbage_content_length_denied():
    for cl in (b"-1", b"5 5", b"0x5", b"abc", b"+5"):
        raw = b"POST /x HTTP/1.1\r\nHost: gw\r\nContent-Length: " + cl + b"\r\n\r\nhello"
        assert denied(raw).status == 400


def test_pipelined_second_request_is_not_parsed():
    raw = OK + b"GET /getMe HTTP/1.1\r\nHost: gw\r\n\r\n"
    r = parse(raw)
    assert r.body == b"hello" and r.target == "/sendMessage"


# ---- запреты ----

@pytest.mark.parametrize(
    "extra",
    [b"Expect: 100-continue\r\n", b"Upgrade: websocket\r\nConnection: Upgrade\r\n",
     b"TE: trailers\r\n", b"Connection: foo\r\n"],
)
def test_forbidden_headers(extra):
    raw = b"GET /getMe HTTP/1.1\r\nHost: gw\r\n" + extra + b"\r\n"
    assert denied(raw).status == 400


def test_duplicate_header_denied():
    raw = b"GET /getMe HTTP/1.1\r\nHost: gw\r\nX-GK-Sig: a\r\nX-GK-Sig: b\r\n\r\n"
    assert denied(raw).status == 400


def test_http10_denied():
    assert denied(b"GET /getMe HTTP/1.0\r\n\r\n").status == 400


@pytest.mark.parametrize(
    "target",
    [b"http://evil.example/getMe", b"//evil/getMe", b"*", b"getMe", b"/a\x7fb"],
)
def test_bad_targets(target):
    raw = b"GET " + target + b" HTTP/1.1\r\nHost: gw\r\n\r\n"
    assert denied(raw).status == 400


def test_target_too_long():
    raw = b"GET /" + b"a" * 300 + b" HTTP/1.1\r\nHost: gw\r\n\r\n"
    assert denied(raw).status == 400


def test_non_ascii_target():
    raw = "GET /é HTTP/1.1\r\nHost: gw\r\n\r\n".encode("utf-8")
    assert denied(raw).status == 400


def test_bad_method():
    assert denied(b"get /getMe HTTP/1.1\r\nHost: gw\r\n\r\n").status == 400


def test_control_char_in_header_value():
    raw = b"GET /getMe HTTP/1.1\r\nHost: gw\r\nX-A: a\x01b\r\n\r\n"
    assert denied(raw).status == 400


def test_bare_lf_endings_denied():
    assert denied(b"GET /getMe HTTP/1.1\nHost: gw\n\n").status == 400


def test_garbage_denied():
    assert denied(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03").status == 400


def test_empty_connection_denied():
    assert denied(b"").status == 400


# ---- огромные заголовки и тело ----

def test_huge_header_value():
    raw = b"GET /getMe HTTP/1.1\r\nHost: gw\r\nX-A: " + b"a" * 20000 + b"\r\n\r\n"
    assert denied(raw).status in (400, 431)


def test_huge_headers_without_terminator_stop_early():
    raw = b"GET /getMe HTTP/1.1\r\nHost: gw\r\nX-A: " + b"a" * 100000
    assert denied(raw, eof=False).status in (400, 431)


def test_too_many_headers():
    hdrs = b"".join(b"X-H%d: v\r\n" % i for i in range(60))
    raw = b"GET /getMe HTTP/1.1\r\nHost: gw\r\n" + hdrs + b"\r\n"
    assert denied(raw).status == 431


def test_declared_body_too_large_rejected_without_reading():
    raw = b"POST /x HTTP/1.1\r\nHost: gw\r\nContent-Length: 999999999\r\n\r\n"
    assert denied(raw, HttpLimits(max_body=1000), eof=False).status == 413


def test_body_exceeds_limit():
    raw = b"POST /x HTTP/1.1\r\nHost: gw\r\nContent-Length: 20\r\n\r\n" + b"a" * 20
    assert denied(raw, HttpLimits(max_body=10)).status == 413


def test_truncated_body():
    raw = b"POST /x HTTP/1.1\r\nHost: gw\r\nContent-Length: 10\r\n\r\nabc"
    assert denied(raw).status == 400


# ---- slowloris ----

def test_silent_connection_times_out():
    assert denied(b"", HttpLimits(header_timeout=0.1), eof=False).status == 408


def test_partial_headers_then_silence_times_out():
    raw = b"GET /getMe HTTP/1.1\r\nHost: gw\r\n"
    assert denied(raw, HttpLimits(header_timeout=0.1), eof=False).status == 408


def test_slow_drip_hits_total_deadline():
    async def go():
        reader = asyncio.StreamReader()

        async def drip():
            for b in b"GET /getMe HTTP/1.1\r\nHost: gw\r\n\r\n":
                reader.feed_data(bytes([b]))
                await asyncio.sleep(0.02)

        task = asyncio.create_task(drip())
        try:
            await read_request(reader, HttpLimits(header_timeout=0.15))
        finally:
            task.cancel()

    with pytest.raises(HttpError) as ei:
        asyncio.run(go())
    assert ei.value.status == 408


def test_slow_body_times_out():
    raw = b"POST /x HTTP/1.1\r\nHost: gw\r\nContent-Length: 10\r\n\r\nab"
    assert denied(raw, HttpLimits(body_timeout=0.1), eof=False).status == 408
