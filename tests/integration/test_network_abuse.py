"""Сетевые негативные сценарии против живого шлюза (клиентский сертификат настоящий,
поэтому атаки доходят до HTTP-слоя). Ни одна не должна дойти до upstream."""
import socket
import time

from test_end_to_end import api, gw, tls_ctx  # noqa: F401  (gw: фикстура)


def raw(gw, payload: bytes, wait: float = 5.0) -> bytes:
    ctx = tls_ctx(gw, gw.bundle / "client.pem", gw.bundle / "client.key")
    chunks = []
    with socket.create_connection(("127.0.0.1", gw.port), timeout=wait) as s:
        with ctx.wrap_socket(s, server_hostname="127.0.0.1") as t:
            t.sendall(payload)
            try:
                while True:
                    d = t.recv(65536)
                    if not d:
                        break
                    chunks.append(d)
            except OSError:
                pass
    return b"".join(chunks)


def status(resp: bytes):
    return int(resp.split(b" ", 2)[1]) if resp.startswith(b"HTTP/") else None


def test_content_length_and_transfer_encoding_conflict(gw):
    resp = raw(gw, b"POST /sendMessage HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n"
                   b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    assert status(resp) == 400 and not gw.fake.requests


def test_duplicate_content_length(gw):
    resp = raw(gw, b"POST /sendMessage HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n"
                   b"Content-Length: 5\r\n\r\nhello")
    assert status(resp) == 400 and not gw.fake.requests


def test_huge_headers(gw):
    resp = raw(gw, b"GET /getMe HTTP/1.1\r\nHost: x\r\nX-A: " + b"a" * 20000 + b"\r\n\r\n")
    assert status(resp) in (400, 431) and not gw.fake.requests


def test_declared_oversize_body_rejected_without_reading(gw):
    resp = raw(gw, b"POST /sendMessage HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\n")
    assert status(resp) == 413 and not gw.fake.requests


def test_slowloris_headers_time_out(gw):
    t0 = time.monotonic()
    resp = raw(gw, b"GET /getMe HTTP/1.1\r\nHost: x\r\n")  # заголовок не закончен
    assert status(resp) == 408 and time.monotonic() - t0 < 4 and not gw.fake.requests


def test_slow_body_times_out(gw):
    t0 = time.monotonic()
    resp = raw(gw, b"POST /sendMessage HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nab")
    assert status(resp) == 408 and time.monotonic() - t0 < 4 and not gw.fake.requests


def test_garbage_does_not_break_gateway(gw):
    resp = raw(gw, bytes(range(256)) * 8)
    assert status(resp) == 400 and not gw.fake.requests
    assert api(gw).get_me()["ok"]


def test_per_ip_connection_limit_and_recovery(gw):
    ctx = tls_ctx(gw, gw.bundle / "client.pem", gw.bundle / "client.key")
    socks, closed = [], 0
    try:
        for _ in range(12):  # max_per_ip по умолчанию 10
            s = socket.create_connection(("127.0.0.1", gw.port), timeout=5)
            try:
                socks.append(ctx.wrap_socket(s, server_hostname="127.0.0.1"))
            except OSError:  # лимит срабатывает до рукопожатия: соединение сброшено
                s.close()
                closed += 1
        for t in socks:
            t.settimeout(0.3)
            try:
                if not t.recv(1):
                    closed += 1
            except TimeoutError:
                pass  # соединение держится: шлюз ждёт запрос
            except OSError:
                closed += 1
    finally:
        for t in socks:
            t.close()
    assert closed >= 1
    time.sleep(1.5)
    assert api(gw).get_me()["ok"]
