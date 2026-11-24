"""Общая проверка ответа upstream на утечку секрета (Telegram, GitHub).

Блокировка (fail closed) в случаях:
- секрет найден побайтово, в тексте или в любой разобранной JSON-строке (в т. ч. в ключах),
  включая JSON-экранирование (\\u0041...);
- заявленный JSON не разбирается целиком (обрыв, мусор в хвосте): проверить нельзя;
- NDJSON: любая строка не JSON;
- JSON слишком глубоко вложен;
- в JSON-объекте повторяется ключ: `json.loads` оставил бы только последнее значение,
  и спрятанный в первом значении секрет не попал бы в проверяемое дерево.

JSON ищется по содержимому, а не только по заголовку: `text/json`, `application/x-ndjson`
и `text/plain` с телом `{...}` проверяются так же, как `application/json`.
"""
from __future__ import annotations

import json
from collections.abc import Callable

from gatekeeper.server.providers.base import UpstreamResponse

# Глубина вложенности JSON-ответа: ответы Bot API / GitHub неглубокие. Лимит явный, чтобы
# блокировка не зависела от recursion limit и версии интерпретатора.
MAX_JSON_DEPTH = 64


class _DuplicateKey(Exception):
    """Не ValueError: иначе вызывающий код принял бы это за «не JSON»."""


def _json_too_deep(text: str, limit: int = MAX_JSON_DEPTH) -> bool:
    """True, если скобки вне строк вложены глубже limit.

    Один проход по символам, без регулярных выражений: шаблон строки с экранированием
    давал квадратичное время на враждебном вводе (ReDoS). Строки пропускаются целиком,
    экранированная кавычка строку не закрывает (X-01).
    """
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                return True
        elif ch in "]}":
            depth -= 1
    return False


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise _DuplicateKey
        seen.add(key)
    return dict(pairs)


def _tree_leaks(data: object, leaks: Callable[[str], bool]) -> bool:
    stack = [data]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            if leaks(node):
                return True
        elif isinstance(node, dict):
            for k, v in node.items():
                stack.append(k)
                stack.append(v)
        elif isinstance(node, list):
            stack.extend(node)
    return False


def _parsed_leaks(text: str, leaks: Callable[[str], bool]) -> bool:
    """True = блокировать. Не-JSON текст не блокируется: сырой текст уже проверен."""
    try:
        return _tree_leaks(json.loads(text, object_pairs_hook=_strict_object), leaks)
    except _DuplicateKey:
        return True
    except RecursionError:
        return True
    except ValueError:
        return False


def response_must_be_blocked(resp: UpstreamResponse, secrets: tuple[str, ...],
                             leaks: Callable[[str], bool]) -> bool:
    """True = ответ нужно заблокировать (содержит секрет или не поддаётся надёжной проверке)."""
    for secret in secrets:
        if secret.encode("ascii") in resp.body:
            return True
    ct = (resp.content_type or "").lower()
    texty = "json" in ct or ct.startswith("text/") or not ct  # нет Content-Type: смотрим тело
    if not texty:
        return False  # двоичные типы (файлы) не разбираем: только побайтовая проверка выше
    text = resp.body.decode("utf-8", "replace")
    if leaks(text):
        return True
    if not text.strip():
        return False  # пустое тело (204 и т. п.): скрывать нечего
    if "ndjson" in ct:
        # NDJSON: каждая строка обязана быть корректным JSON без утечки (fail closed, X-02).
        # Делим только по `\n`: splitlines() режет ещё на U+2028, \x85, \v и \f, а они
        # могут законно стоять внутри JSON-строки — запись развалилась бы на куски.
        for raw_line in text.split("\n"):
            line = raw_line.strip()
            if not line:
                continue
            if _json_too_deep(line):
                return True
            try:
                data = json.loads(line, object_pairs_hook=_strict_object)
            except (_DuplicateKey, RecursionError, ValueError):
                return True
            if _tree_leaks(data, leaks):
                return True
        return False
    if "json" not in ct and resp.body[:64].lstrip()[:1] not in (b"{", b"["):
        return False  # обычный текст (или тело без Content-Type, не похожее на JSON)
    if _json_too_deep(text):
        return True
    try:
        data = json.loads(text, object_pairs_hook=_strict_object)
    except (_DuplicateKey, RecursionError):
        return True
    except ValueError:
        if "json" in ct:
            # Заявлен JSON, но тело целиком не разбирается (обрыв, мусор в хвосте):
            # надёжно проверить его нельзя — блокируем (fail closed).
            return True
        # Не-JSON Content-Type: отдельные строки всё же могут быть JSON.
        for line in text.split("\n"):
            line = line.strip()
            if line[:1] in ("{", "[") and _parsed_leaks(line, leaks):
                return True
        return False
    return _tree_leaks(data, leaks)
