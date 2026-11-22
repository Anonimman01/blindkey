"""Запрос к настоящему API через h11. Полный таймаут и лимит размера ответа.

Тексты ошибок содержат только тип сбоя: путь запроса содержит секрет.
"""
from __future__ import annotations

import asyncio
import contextlib
import ssl
import threading

import h11

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.server.providers.base import UpstreamRequest, UpstreamResponse


class UpstreamError(GatekeeperError):
    """Upstream недоступен или ответил некорректно."""


class ResponseBudget:
    """Общий потолок байт, которые шлюз одновременно держит в памяти под ответы upstream (C-14).

    Ответ по-прежнему буферизуется целиком (фильтру нужен весь текст), но суммарный объём
    всех одновременных ответов ограничен: при исчерпании запрос получает 502, а не OOM.
    """

    def __init__(self, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._used = 0

    def reserve(self, amount: int) -> bool:
        with self._lock:
            if self._used + amount > self.max_bytes:
                return False
            self._used += amount
            return True

    def release(self, amount: int) -> None:
        with self._lock:
            self._used = max(0, self._used - amount)

    @property
    def used(self) -> int:
        with self._lock:
            return self._used


def _safe_content_type(raw: bytes | None) -> str | None:
    if raw is None or len(raw) > 200:
        return None
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return text if text.isprintable() else None


class Upstream:
    def __init__(self, host: str, port: int = 443, *, use_tls: bool = True,
                 ssl_context: ssl.SSLContext | None = None, timeout: float = 30.0,
                 max_response: int = 21_000_000,
                 budget: ResponseBudget | None = None) -> None:
        self.host, self.port, self.timeout, self.max_response = host, port, timeout, max_response
        self._ssl = (ssl_context or ssl.create_default_context()) if use_tls else None
        self._budget = budget

    async def fetch(self, req: UpstreamRequest, timeout: float | None = None) -> UpstreamResponse:
        try:
            async with asyncio.timeout(self.timeout if timeout is None else timeout):
                return await self._fetch(req)
        except TimeoutError:
            raise UpstreamError("timeout") from None
        except (OSError, h11.ProtocolError) as exc:  # ssl.SSLError входит в OSError
            raise UpstreamError(type(exc).__name__) from None

    async def _fetch(self, req: UpstreamRequest) -> UpstreamResponse:
        reader, writer = await asyncio.open_connection(
            self.host, self.port, ssl=self._ssl,
            server_hostname=self.host if self._ssl else None)
        reserved = 0
        try:
            conn = h11.Connection(h11.CLIENT, max_incomplete_event_size=16384)
            writer.write(conn.send(h11.Request(
                method=req.method, target=req.path, headers=list(req.headers))))
            if req.body:
                writer.write(conn.send(h11.Data(data=req.body)))
            writer.write(conn.send(h11.EndOfMessage()))
            await writer.drain()
            status, ctype, parts, size = None, None, [], 0
            while True:
                ev = conn.next_event()
                if ev is h11.NEED_DATA:
                    conn.receive_data(await reader.read(65536))
                elif isinstance(ev, h11.Response):
                    status = ev.status_code
                    # Запрошен identity. Любая другая кодировка (gzip/br/...) скрыла бы секрет
                    # от фильтра ответа: отказываем, не пытаясь распаковывать.
                    enc = dict(ev.headers).get(b"content-encoding", b"identity")
                    if enc.strip().lower() not in (b"", b"identity"):
                        raise UpstreamError("unsupported_content_encoding")
                    ctype = _safe_content_type(dict(ev.headers).get(b"content-type"))
                elif isinstance(ev, h11.Data):
                    size += len(ev.data)
                    if size > self.max_response:
                        raise UpstreamError("response_too_large")
                    if self._budget is not None:
                        if not self._budget.reserve(len(ev.data)):
                            raise UpstreamError("global_response_budget_exceeded")
                        reserved += len(ev.data)
                    parts.append(bytes(ev.data))
                elif isinstance(ev, h11.EndOfMessage):
                    break
                elif not isinstance(ev, h11.InformationalResponse):
                    raise UpstreamError("unexpected_event")
            if status is None:
                raise UpstreamError("no_response")
            return UpstreamResponse(status, ctype, b"".join(parts))
        finally:
            if self._budget is not None and reserved:
                self._budget.release(reserved)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
