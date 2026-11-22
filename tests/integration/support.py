"""Общие помощники интеграционных тестов (B-17).

Раньше conftest импортировал фикстуры из `test_end_to_end`: это ломается при
`--import-mode=importlib` и при переименовании тест-модуля. Теперь фикстуры объявлены в
conftest.py, а вспомогательные функции и константы живут в этом обычном модуле.
"""
from __future__ import annotations

import asyncio
import socket
import ssl
import threading
import time
from types import SimpleNamespace

from gatekeeper.client.botapi import BotApi

TOKEN = "123456789:AAH-fakeFAKEfakeFAKEfakeFAKEfake12345"
ALLOW = ["GET:getMe", "POST:sendMessage", "POST:getFile", "POST:downloadFile", "POST:getUpdates"]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, app, port):
        self.app, self.port = app, port
        self.loop = asyncio.new_event_loop()
        self.task = None
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._main())
        except asyncio.CancelledError:
            pass
        finally:
            self.loop.close()

    async def _main(self) -> None:
        self.task = asyncio.current_task()
        await self.app.serve()

    def start(self):
        self.thread.start()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("gateway did not start")

    def stop(self):
        if self.task is not None:
            self.loop.call_soon_threadsafe(self.task.cancel)
        self.thread.join(5)


def api(gw: SimpleNamespace, bundle=None) -> BotApi:
    return BotApi(str(bundle or gw.bundle), "127.0.0.1", gw.port)


def attempt(gw: SimpleNamespace, ctx) -> bytes | str:
    """'refused', если шлюз оборвал соединение или TLS; иначе полученные байты."""
    try:
        with (
            socket.create_connection(("127.0.0.1", gw.port), timeout=5) as raw,
            ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls,
        ):
            tls.sendall(b"GET /getMe HTTP/1.1\r\nHost: x\r\n\r\n")
            data = tls.recv(200)
    except OSError:
        return "refused"
    return data or "refused"


def tls_ctx(gw: SimpleNamespace, cert=None, key=None, maxv=None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # даже тестовый клиент не говорит на TLS < 1.2
    ctx.load_verify_locations(cafile=str(gw.bundle / "ca.pem"))
    if cert:
        ctx.load_cert_chain(str(cert), str(key))
    if maxv:
        ctx.maximum_version = maxv
    return ctx
