"""Один запрос-ответ по готовому сокету (синхронно, h11)."""
from __future__ import annotations

import socket
from dataclasses import dataclass

import h11

from gatekeeper.core.errors import GatekeeperError


class ClientHttpError(GatekeeperError):
    """Сбой транспорта или некорректный ответ шлюза."""


@dataclass(frozen=True)
class Response:
    status: int
    content_type: str | None
    body: bytes


def exchange(sock: socket.socket, method: str, target: str, headers: list[tuple[str, str]],
             body: bytes = b"", max_response: int = 21_000_000) -> Response:
    conn = h11.Connection(h11.CLIENT, max_incomplete_event_size=16384)
    try:
        out = conn.send(h11.Request(method=method, target=target, headers=headers))
        if body:
            out += conn.send(h11.Data(data=body))
        out += conn.send(h11.EndOfMessage())
        sock.sendall(out)
        status, ctype, parts, size = None, None, [], 0
        while True:
            ev = conn.next_event()
            if ev is h11.NEED_DATA:
                conn.receive_data(sock.recv(65536))
            elif isinstance(ev, h11.Response):
                status = ev.status_code
                raw = dict(ev.headers).get(b"content-type")
                ctype = raw.decode("ascii", "replace") if raw else None
            elif isinstance(ev, h11.Data):
                size += len(ev.data)
                if size > max_response:
                    raise ClientHttpError("response too large")
                parts.append(bytes(ev.data))
            elif isinstance(ev, h11.EndOfMessage):
                break
            elif not isinstance(ev, h11.InformationalResponse):
                raise ClientHttpError("unexpected http event")
    except h11.ProtocolError as exc:
        raise ClientHttpError(f"protocol error: {type(exc).__name__}") from None
    if status is None:
        raise ClientHttpError("no response")
    return Response(status, ctype, b"".join(parts))
