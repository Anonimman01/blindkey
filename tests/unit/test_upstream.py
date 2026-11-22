"""server/upstream.py: разбор ответа, лимиты и общий бюджет байт (C-14)."""
import asyncio
import socket
import threading
import time

import pytest

from gatekeeper.server.providers.base import UpstreamRequest
from gatekeeper.server.upstream import ResponseBudget, Upstream, UpstreamError

REQ = UpstreamRequest("GET", "/x", (("Host", "example"),))
JSON_OK = b'{"ok":true}'


class FakeServer(threading.Thread):
    """Один TCP-сервер на тест: отвечает фиксированными байтами (или молчит)."""

    def __init__(self, response: bytes | None, *, delay: float = 0.0) -> None:
        super().__init__(daemon=True)
        self._response, self._delay = response, delay
        self._stop = threading.Event()
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(4)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]

    def run(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            with conn:
                conn.settimeout(1.0)
                try:
                    conn.recv(65536)
                    if self._delay:
                        time.sleep(self._delay)
                    if self._response is not None:
                        conn.sendall(self._response)
                except OSError:
                    pass

    def stop(self) -> None:
        self._stop.set()
        self._sock.close()


def _response(body: bytes = JSON_OK, extra: bytes = b"", status: bytes = b"200 OK") -> bytes:
    return (b"HTTP/1.1 " + status + b"\r\nContent-Type: application/json\r\n"
            + extra + b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)


def _fetch(payload: bytes | None, *, delay: float = 0.0, **kwargs):
    server = FakeServer(payload, delay=delay)
    server.start()
    options = {"timeout": 2.0, **kwargs}
    upstream = Upstream("127.0.0.1", server.port, use_tls=False, **options)
    try:
        return asyncio.run(upstream.fetch(REQ))
    finally:
        server.stop()


def test_successful_response():
    resp = _fetch(_response())
    assert (resp.status, resp.content_type, resp.body) == (200, "application/json", JSON_OK)


def test_response_larger_than_limit_is_rejected():
    with pytest.raises(UpstreamError, match="response_too_large"):
        _fetch(_response(b"0123456789"), max_response=4)


def test_compressed_response_is_rejected():
    with pytest.raises(UpstreamError, match="unsupported_content_encoding"):
        _fetch(_response(extra=b"Content-Encoding: gzip\r\n"))


def test_timeout_is_reported():
    with pytest.raises(UpstreamError, match="timeout"):
        _fetch(None, delay=3.0, timeout=0.2)


def test_bad_content_type_is_dropped_not_fatal():
    resp = _fetch(_response(extra=b"Content-Type: " + b"x" * 300 + b"\r\n"))
    assert resp.status == 200 and resp.content_type is None


def test_budget_limits_total_buffered_bytes():
    budget = ResponseBudget(4)
    with pytest.raises(UpstreamError, match="global_response_budget_exceeded"):
        _fetch(_response(JSON_OK), budget=budget)
    assert budget.used == 0  # резерв освобождён при ошибке


def test_budget_is_released_after_success():
    budget = ResponseBudget(1024)
    resp = _fetch(_response(JSON_OK), budget=budget)
    assert resp.body == JSON_OK
    assert budget.used == 0


def test_budget_reserve_and_release():
    budget = ResponseBudget(10)
    assert budget.reserve(6) and budget.reserve(4)
    assert not budget.reserve(1)
    assert budget.used == 10
    budget.release(10)
    assert budget.used == 0
    budget.release(5)
    assert budget.used == 0  # не уходит в отрицательные
    with pytest.raises(ValueError):
        ResponseBudget(0)
