"""Сборка HTTP-ответа. Ответы на отказ нейтральные: одинаковое тело для всех причин.

Ответ собирается вручную (мы только пишем, не разбираем), поэтому все
значения заголовков проверяются на CR/LF/NUL. Соединение всегда закрывается.
"""
from __future__ import annotations

from http import HTTPStatus

NEUTRAL_BODY = b'{"ok":false}'
_SAFE_STATUSES = frozenset({400, 403, 404, 408, 413, 429, 431, 500, 502, 503})


def _check(text: str) -> str:
    if not isinstance(text, str) or any(ord(c) < 0x20 and c != "\t" or ord(c) >= 0x7F for c in text):
        raise ValueError("invalid header text")
    return text


def build_response(
    status: int,
    body: bytes = b"",
    content_type: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> bytes:
    try:
        phrase = HTTPStatus(status).phrase
    except ValueError as exc:
        raise ValueError("unknown status") from exc
    lines = [f"HTTP/1.1 {status} {phrase}"]
    if content_type is not None:
        lines.append(f"Content-Type: {_check(content_type)}")
    lines.append(f"Content-Length: {len(body)}")
    lines.append("Connection: close")
    for name, value in (extra_headers or {}).items():
        n = _check(name)
        if not n or ":" in n or " " in n or n.lower() in {"content-length", "connection", "transfer-encoding"}:
            raise ValueError("invalid header name")
        lines.append(f"{n}: {_check(value)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body


def neutral_response(status: int) -> bytes:
    """Ответ на отказ: только код (из узкого набора) и одинаковое тело."""
    if status not in _SAFE_STATUSES:
        status = 400
    return build_response(status, NEUTRAL_BODY, "application/json")
