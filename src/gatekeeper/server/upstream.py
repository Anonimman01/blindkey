"""Запрос к настоящему API через h11. Полный таймаут и лимит размера ответа.

Тексты ошибок содержат только тип сбоя: путь запроса содержит секрет.
"""
from __future__ import annotations

import asyncio
import ssl

import h11

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.server.providers.base import UpstreamRequest, UpstreamResponse


class UpstreamError(GatekeeperError):
    """Upstream недоступен или ответил некорректно."""


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
                 max_response: int = 21_000_000) -> None:
        self.host, self.port, self.timeout, self.max_response = host, port, timeout, max_response
        self._ssl = (ssl_context or ssl.create_default_context()) if use_tls else None

    async def fetch(self, req: UpstreamRequest, timeout: float | None = None) -> UpstreamResponse:
        try:
            async with asyncio.timeout(self.timeout if timeout is None else timeout):
                return await self._fetch(req)
        except TimeoutError as exc:
            raise UpstreamError("timeout") from None
        except (OSError, h11.ProtocolError) as exc:  # ssl.SSLError входит в OSError
            raise UpstreamError(type(exc).__name__) from None

    async def _fetch(self, req: UpstreamRequest) -> UpstreamResponse:
        reader, writer = await asyncio.open_connection(
            self.host, self.port, ssl=self._ssl,
            server_hostname=self.host if self._ssl else None)
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
                    ctype = _safe_content_type(dict(ev.headers).get(b"content-type"))
                elif isinstance(ev, h11.Data):
                    size += len(ev.data)
                    if size > self.max_response:
                        raise UpstreamError("response_too_large")
                    parts.append(bytes(ev.data))
                elif isinstance(ev, h11.EndOfMessage):
                    break
                elif not isinstance(ev, h11.InformationalResponse):
                    raise UpstreamError("unexpected_event")
            if status is None:
                raise UpstreamError("no_response")
            return UpstreamResponse(status, ctype, b"".join(parts))
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
