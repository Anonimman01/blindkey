"""Служебный Unix-сокет: /healthz и /metrics (только не-Windows)."""
import asyncio
import os
import stat
import sys
from types import SimpleNamespace

import pytest

from gatekeeper.server.app import GatekeeperApp
from gatekeeper.server.observe import Metrics

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="Unix sockets")


def make_app(sock):
    app = GatekeeperApp.__new__(GatekeeperApp)
    app.metrics, app.metrics_socket = Metrics(), str(sock)
    app.limiter = SimpleNamespace(total=2)
    app.audit = SimpleNamespace(next_seq=7)
    app.pipeline = SimpleNamespace(nonces=[1, 2, 3])
    return app


async def ask(path, line):
    r, w = await asyncio.open_unix_connection(path)
    w.write(line)
    await w.drain()
    data = await asyncio.wait_for(r.read(), 3)
    w.close()
    return data


def test_healthz_and_metrics(tmp_path):
    sock = tmp_path / "ops.sock"
    app = make_app(sock)
    app.metrics.inc("gk_requests_total", status=200)

    async def scenario():
        srv = await app._start_ops_socket()
        try:
            assert stat.S_IMODE(os.stat(sock).st_mode) == 0o600
            health = await ask(str(sock), b"GET /healthz HTTP/1.1\r\n\r\n")
            metrics = await ask(str(sock), b"GET /metrics HTTP/1.1\r\n\r\n")
            other = await ask(str(sock), b"POST /metrics HTTP/1.1\r\n\r\n")
        finally:
            srv.close()
        return health, metrics, other

    health, metrics, other = asyncio.run(scenario())
    assert health.startswith(b"HTTP/1.1 200") and b'{"ok":true}' in health
    assert b'gk_requests_total{status="200"} 1' in metrics
    assert b"gk_connections 2" in metrics and b"gk_audit_next_seq 7" in metrics
    assert other.startswith(b"HTTP/1.1 404")


def test_disabled_without_socket_path():
    app = make_app("x")
    app.metrics_socket = None
    assert asyncio.run(app._start_ops_socket()) is None
