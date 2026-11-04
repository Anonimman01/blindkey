"""Маскирование секретов в тексте и структурах (логи, журнал, ответы).

Три уровня защиты:
  1. точные значения: секреты, которые шлюз знает (токен бота, ключи подписи);
  2. шаблоны: токен Telegram, PEM-блоки приватных ключей, Bearer-заголовки;
  3. имена полей: значения под ключами token/secret/password/... маскируются целиком.
"""
from __future__ import annotations

import re
from typing import Any, Iterable

MASK = "[REDACTED]"
_MIN_SECRET_LEN = 6  # слишком короткие "секреты" маскировать нельзя: порвут весь текст

_PATTERNS = [
    # токен Telegram: <id>:<35 символов>
    re.compile(r"\b\d{6,12}:[A-Za-z0-9_-]{30,}\b"),
    # /bot<token>/ в URL
    re.compile(r"(?<=/bot)[^/\s?]+"),
    # PEM-блоки приватных ключей
    re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S
    ),
    # Authorization: Bearer xxx
    re.compile(r"(?i)(?<=bearer )[A-Za-z0-9._~+/=-]{8,}"),
]

_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(token|secret|passw(or)?d|private|authorization|api[_-]?key|master|signing[_-]?key|x-gk-sig)"
)


def _known(secrets: Iterable[str | bytes] | None) -> list[str]:
    out: list[str] = []
    for s in secrets or ():
        if isinstance(s, (bytes, bytearray)):
            variants = [bytes(s).hex()]
            try:
                variants.append(bytes(s).decode("utf-8"))
            except UnicodeDecodeError:
                pass
        else:
            variants = [str(s)]
        out += [v for v in variants if len(v) >= _MIN_SECRET_LEN]
    # длинные сначала, чтобы короткий секрет не раскрыл часть длинного
    return sorted(set(out), key=len, reverse=True)


def redact_text(text: str, secrets: Iterable[str | bytes] | None = None) -> str:
    if not isinstance(text, str):
        text = str(text)
    for s in _known(secrets):
        text = text.replace(s, MASK)
    for pat in _PATTERNS:
        text = pat.sub(MASK, text)
    return text


def redact_obj(obj: Any, secrets: Iterable[str | bytes] | None = None) -> Any:
    """Рекурсивно вернуть копию obj с замаскированными секретами."""
    known = _known(secrets)
    return _walk(obj, known)


def _walk(obj: Any, known: list[str]) -> Any:
    if isinstance(obj, str):
        return redact_text(obj, known)
    if isinstance(obj, (bytes, bytearray)):
        return redact_text(bytes(obj).decode("latin-1"), known)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            ks = redact_text(str(k), known) if not isinstance(k, str) else redact_text(k, known)
            if isinstance(k, str) and _SENSITIVE_KEY_RE.search(k) and v not in (None, "", [], {}):
                out[ks] = MASK
            else:
                out[ks] = _walk(v, known)
        return out
    if isinstance(obj, (list, tuple)):
        return [_walk(v, known) for v in obj]
    return obj
