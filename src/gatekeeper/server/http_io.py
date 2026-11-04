"""Чтение HTTP-запроса поверх h11 с жёсткими лимитами и таймаутами.

Своего парсера нет: весь разбор делает h11. Здесь только лимиты и
дополнительные запреты (всё, что не нужно нашим клиентам, отклоняется):
- одно соединение = один запрос (шлюз закрывает соединение после ответа);
- Transfer-Encoding запрещён целиком (защита от smuggling: тело только
  по Content-Length; одновременное наличие обоих заголовков = отказ);
- повторяющиеся заголовки запрещены;
- Expect, Upgrade, HTTP/1.0, абсолютная форма target запрещены;
- таймауты общие на фазу (заголовки, тело), а не на одно чтение, поэтому
  slowloris (по байту в секунду) упирается в дедлайн.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field

import h11

from gatekeeper.core.errors import GatekeeperError

_CHUNK = 4096
_METHOD_RE = re.compile(r"^[A-Z]{3,10}$")
_FORBIDDEN_HEADERS = frozenset({"transfer-encoding", "expect", "upgrade", "te", "trailer"})


class HttpError(GatekeeperError):
    """Запрос отклонён на уровне HTTP. status идёт клиенту, reason только в журнал."""

    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


@dataclass(frozen=True)
class HttpLimits:
    max_header_bytes: int = 8192
    max_headers: int = 50
    max_target: int = 256
    max_body: int = 1_048_576
    header_timeout: float = 10.0
    body_timeout: float = 30.0


@dataclass(frozen=True)
class ParsedRequest:
    method: str
    target: str
    headers: dict = field(default_factory=dict)  # имена в нижнем регистре
    body: bytes = b""


def _proto_error(exc: Exception) -> HttpError:
    # Клиенту отдаём только 400 или 431: h11 подсказывает 501 для незнакомых
    # Transfer-Encoding, но нам нужен единый нейтральный отказ.
    hint = getattr(exc, "error_status_hint", 400)
    return HttpError(431 if hint == 431 else 400, "protocol_error")


async def _next_event(conn: h11.Connection, reader: asyncio.StreamReader,
                      raw: bytearray | None = None):
    while True:
        try:
            ev = conn.next_event()
        except h11.RemoteProtocolError as exc:
            raise _proto_error(exc) from exc
        if ev is h11.NEED_DATA:
            data = await reader.read(_CHUNK)
            if raw is not None:
                raw.extend(data)
            try:
                conn.receive_data(data)
            except h11.RemoteProtocolError as exc:
                raise _proto_error(exc) from exc
            continue
        if ev is h11.PAUSED or isinstance(ev, h11.ConnectionClosed):
            raise HttpError(400, "unexpected_close")
        return ev


def _check_value(raw: bytes) -> str:
    if any((b < 0x20 and b != 0x09) or b >= 0x7F for b in raw):
        raise HttpError(400, "bad_header_value")
    return raw.decode("ascii")


def _validate_request(ev: h11.Request, limits: HttpLimits) -> tuple[str, str, dict]:
    if ev.http_version != b"1.1":
        raise HttpError(400, "bad_http_version")
    try:
        method = ev.method.decode("ascii")
        target = ev.target.decode("ascii")
    except UnicodeDecodeError as exc:
        raise HttpError(400, "non_ascii_request_line") from exc
    if not _METHOD_RE.match(method):
        raise HttpError(400, "bad_method")
    if not target.startswith("/") or target.startswith("//") or len(target) > limits.max_target:
        raise HttpError(400, "bad_target")
    if any(ord(c) < 0x21 or ord(c) >= 0x7F for c in target):
        raise HttpError(400, "bad_target")
    if len(ev.headers) > limits.max_headers:
        raise HttpError(431, "too_many_headers")
    headers: dict[str, str] = {}
    for raw_name, raw_value in ev.headers:
        name = raw_name.decode("ascii").lower()
        if name in headers:
            raise HttpError(400, "duplicate_header")
        if name in _FORBIDDEN_HEADERS:
            raise HttpError(400, "forbidden_header")
        headers[name] = _check_value(raw_value)
    if "connection" in headers and headers["connection"].lower() not in ("close", "keep-alive"):
        raise HttpError(400, "bad_connection_header")
    return method, target, headers


def _check_raw_head(raw: bytearray) -> None:
    """Проверки по сырым байтам: h11 их скрывает (склеивает одинаковые
    повторы Content-Length и терпит голый LF), а для smuggling это важно."""
    end = raw.find(b"\r\n\r\n")
    head = bytes(raw if end == -1 else raw[: end + 4])
    if b"\n" in head.replace(b"\r\n", b""):
        raise HttpError(400, "bare_lf")
    seen: set[bytes] = set()
    for line in head.split(b"\r\n")[1:]:
        if not line:
            continue
        if line[:1] in (b" ", b"\t"):
            raise HttpError(400, "obs_fold")
        name = line.split(b":", 1)[0].strip().lower()
        if name in seen:
            raise HttpError(400, "duplicate_header")
        seen.add(name)


async def _read_head(reader, conn, limits: HttpLimits, raw: bytearray):
    try:
        async with asyncio.timeout(limits.header_timeout):
            ev = await _next_event(conn, reader, raw)
    except TimeoutError as exc:
        raise HttpError(408, "header_timeout") from exc
    if not isinstance(ev, h11.Request):
        raise HttpError(400, "not_a_request")
    return ev


async def _read_body(reader, conn, limits: HttpLimits) -> bytes:
    parts: list[bytes] = []
    size = 0
    try:
        async with asyncio.timeout(limits.body_timeout):
            while True:
                ev = await _next_event(conn, reader)
                if isinstance(ev, h11.Data):
                    size += len(ev.data)
                    if size > limits.max_body:
                        raise HttpError(413, "body_too_large")
                    parts.append(bytes(ev.data))
                elif isinstance(ev, h11.EndOfMessage):
                    return b"".join(parts)
                else:
                    raise HttpError(400, "unexpected_event")
    except TimeoutError as exc:
        raise HttpError(408, "body_timeout") from exc


async def read_request(
    reader: asyncio.StreamReader, limits: HttpLimits | None = None
) -> ParsedRequest:
    """Читает один запрос. При любой проблеме HttpError (status + reason)."""
    limits = limits or HttpLimits()
    conn = h11.Connection(h11.SERVER, max_incomplete_event_size=limits.max_header_bytes)
    raw = bytearray()
    head = await _read_head(reader, conn, limits, raw)
    _check_raw_head(raw)
    method, target, headers = _validate_request(head, limits)
    cl = headers.get("content-length")
    if cl is not None:
        if not cl.isascii() or not cl.isdigit():
            raise HttpError(400, "bad_content_length")
        if int(cl) > limits.max_body:
            raise HttpError(413, "body_too_large")  # тело даже не читаем
    body = await _read_body(reader, conn, limits)
    return ParsedRequest(method=method, target=target, headers=headers, body=body)