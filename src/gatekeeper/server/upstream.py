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


# Разбор JSON держит в памяти примерно 8x тела (объекты, строки): учитываем на время фильтра.
_JSON_FILTER_FACTOR = 8


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
        # Ответы с переданным владением резервом: id(resp) -> сколько байт держим.
        self._held: dict[int, int] = {}
        self._held_lock = threading.Lock()

    async def fetch(self, req: UpstreamRequest, timeout: float | None = None,
                    *, hold: bool = False) -> UpstreamResponse:
        """Ответ upstream. hold=True: резерв памяти остаётся занятым до release_response()."""
        try:
            async with asyncio.timeout(self.timeout if timeout is None else timeout):
                return await self._fetch(req, hold=hold)
        except TimeoutError:
            raise UpstreamError("timeout") from None
        except (OSError, h11.ProtocolError) as exc:  # ssl.SSLError входит в OSError
            raise UpstreamError(type(exc).__name__) from None

    async def _fetch(self, req: UpstreamRequest, *, hold: bool = False) -> UpstreamResponse:
        reader, writer = await asyncio.open_connection(
            self.host, self.port, ssl=self._ssl,
            server_hostname=self.host if self._ssl else None)
        reserved = 0
        resp: UpstreamResponse | None = None
        registered = False
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
            resp = UpstreamResponse(status, ctype, b"".join(parts))
            if hold and reserved:
                # Владение резервом переходит вызывающему: тело нужно ещё и фильтру.
                with self._held_lock:
                    self._held[id(resp)] = reserved
                registered = True
            return resp
        finally:
            if self._budget is not None and reserved and not registered:
                self._budget.release(reserved)
            writer.close()
            # wait_closed может быть прерван таймаутом или отменой уже после return resp:
            # тогда ответа у вызывающего не будет, и резерв обязан снять сам _fetch.
            try:
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
            except BaseException:
                if registered and resp is not None:
                    self.release_response(resp)
                raise

    def begin_filter(self, resp: UpstreamResponse) -> bool:
        """Учесть память на разбор JSON (≈8x тела) на время фильтрации. False = бюджета нет.

        Фильтр разбирает как JSON не только ответы с JSON-заголовком: тело, начинающееся с
        `{` или `[`, тоже (например, `text/plain` от провайдера). Для таких тел множитель тот
        же, иначе учёт памяти расходится с реальным разбором.
        """
        if self._budget is None:
            return True
        ct = (resp.content_type or "").lower()
        if "json" not in ct and resp.body[:64].lstrip()[:1] not in (b"{", b"["):
            return True
        extra = len(resp.body) * (_JSON_FILTER_FACTOR - 1)
        if extra <= 0:
            return True
        if not self._budget.reserve(extra):
            return False
        with self._held_lock:
            self._held[id(resp)] = self._held.get(id(resp), 0) + extra
        return True

    def release_response(self, resp: UpstreamResponse) -> None:
        """Снять резерв после фильтрации и отправки/отбрасывания ответа. Повторный вызов безопасен."""
        with self._held_lock:
            amount = self._held.pop(id(resp), 0)
        if self._budget is not None and amount:
            self._budget.release(amount)
