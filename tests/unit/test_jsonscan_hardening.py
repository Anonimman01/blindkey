"""Сканер глубины JSON линеен (без ReDoS); неразбираемый JSON-ответ блокируется."""
import json
import re
import time

import pytest

from gatekeeper.server.providers.base import UpstreamResponse
from gatekeeper.server.providers.jsonscan import (
    MAX_JSON_DEPTH,
    _json_too_deep,
    response_must_be_blocked,
)

TOKEN = "123456789:AAH-fakeFAKEfakeFAKEfakeFAKEfake12345"
BS = chr(92)
Q = chr(34)
_OLD_TOKEN_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|[\[\]{}]', re.DOTALL)


def _old_too_deep(text: str, limit: int = MAX_JSON_DEPTH) -> bool:
    """Прежняя реализация на регулярке — эталон для корректных (не враждебных) входов."""
    depth = 0
    for m in _OLD_TOKEN_RE.finditer(text):
        ch = m.group()
        if ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def _blocked(body: bytes, ct: str | None) -> bool:
    return response_must_be_blocked(UpstreamResponse(200, ct, body), (TOKEN,), lambda s: TOKEN in s)


NORMAL = [
    '{"ok":true,"result":{"id":1,"text":"hello"}}',
    '[1,2,[3,[4,{"a":[5]}]]]',
    '{"s":"' + BS + BS + Q + 'quoted' + BS + BS + Q + ' and [brackets] inside"}',
    '{"s":"' + BS + 'u0041' + BS + 'u0042"}',
    '{"a":{"b":{"c":{}}}}',
    '[]', '{}', '{"x":null}',
    json.dumps({"deep": [[[[[{"x": ["y"]}]]]]]}),
    "[" * (MAX_JSON_DEPTH - 1) + "]" * (MAX_JSON_DEPTH - 1),
    "[" * (MAX_JSON_DEPTH + 5) + "]" * (MAX_JSON_DEPTH + 5),
]


@pytest.mark.parametrize("text", NORMAL)
def test_scanner_matches_old_verdict_on_normal_input(text):
    assert _json_too_deep(text) == _old_too_deep(text)


def test_brackets_inside_strings_do_not_count():
    assert not _json_too_deep('{"a":"' + "[" * 500 + '"}')
    assert _json_too_deep("[" * (MAX_JSON_DEPTH + 1))


HOSTILE = [
    "[" * 500_000 + "]" * 500_000,          # 1 МБ вложенности
    Q + BS * 1_000_000 + Q,                 # 1 МБ обратных слэшей внутри строки
    Q + (BS + Q) * 500_000,                 # 1 МБ экранированных кавычек, строка не закрыта
    '{"a":"' + BS * 500_000 + '","b":[1,2]}',
]


@pytest.mark.parametrize("body", HOSTILE)
def test_hostile_megabyte_is_fast(body):
    t0 = time.perf_counter()
    _json_too_deep(body)
    elapsed = time.perf_counter() - t0
    assert elapsed < 2.0, f"scan took {elapsed:.3f}s on {len(body)} chars"


def test_escaped_token_with_trailing_garbage_is_blocked():
    escaped = "".join(BS + f"u{ord(c):04x}" for c in TOKEN)
    body = '{"t":"' + escaped + '"}'
    assert TOKEN not in body
    assert _blocked(body.encode(), "application/json")            # утечка в \uXXXX
    assert _blocked((body + "garbage").encode(), "application/json")
    assert _blocked(b'{"a":1', "application/json")                # обрыв
    assert _blocked(b'{"a":1}{"a":2}', "application/json; charset=utf-8")


def test_duplicate_keys_still_blocked():
    assert _blocked(b'{"a":"safe","a":"' + TOKEN.encode() + b'"}', "application/json")


def test_plain_text_and_valid_json_unchanged():
    assert not _blocked(b"hello world, nothing to see", "text/plain")
    assert not _blocked(b"hello {not json", "text/plain")
    assert not _blocked(b"\x00\x01binary", "application/octet-stream")
    assert not _blocked(b'{"ok":true}', "application/json")
    assert not _blocked(b"", "application/json")


def test_ndjson_is_checked_line_by_line():
    assert not _blocked(b'{"ok":true}\n{"ok":false}\n', "application/x-ndjson")
    assert _blocked(b'{"ok":true}\n{"t":"' + TOKEN.encode() + b'"}\n', "application/x-ndjson")
    assert _blocked(b'{"ok":true}\nnot json\n', "application/x-ndjson")
    assert _blocked(b'{"ok":true}\n{"a":1', "application/x-ndjson")
    assert _blocked(b'{"a":1,"a":2}\n', "application/x-ndjson")
