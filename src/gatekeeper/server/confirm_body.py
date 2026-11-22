"""Параметры запроса для подтверждения оператором (C-04).

Раньше оператор видел первые ~200 символов тела (источник — первые 2 КБ), а тело может быть
до `max_body_bytes` (1 МБ). Клиент мог дописать в хвост повторяющийся ключ JSON, и Telegram
применял последнее значение (в аудите воспроизведено на `user_id`).

Поэтому для методов из `[confirm]` тело разбирается как строгое JSON:
* дубли ключей (на любой глубине) — отказ;
* `NaN`, `Infinity`, не-UTF-8 и не-JSON — отказ;
* оператору показываются сами параметры, а не сырой префикс тела.

Так подтверждается ровно то, что уйдёт upstream. Минус: подтверждаемые методы должны
передавать тело в JSON, а не form/multipart.
"""
from __future__ import annotations

import json

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.redact import redact_obj
from gatekeeper.server.providers.jsonscan import MAX_JSON_DEPTH
from gatekeeper.store.approvals import PARAM_PREVIEW_LEN, make_preview


class ConfirmBodyError(GatekeeperError):
    """Тело подтверждаемого метода нельзя безопасно показать оператору."""


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise ConfirmBodyError(f"duplicate JSON key: {key[:40]}")
        seen.add(key)
    return dict(pairs)


def _reject_constant(name: str) -> object:
    raise ConfirmBodyError(f"JSON constant is not allowed: {name}")


def _check_depth(root: object, limit: int = MAX_JSON_DEPTH) -> None:
    """Явная проверка глубины: json.loads разбирает массивы без рекурсии."""
    stack: list[tuple[object, int]] = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > limit:
            raise ConfirmBodyError(f"confirm body is nested deeper than {limit}")
        if isinstance(node, dict):
            stack.extend((value, depth + 1) for value in node.values())
        elif isinstance(node, list):
            stack.extend((value, depth + 1) for value in node)


def parse_confirm_params(body: bytes) -> object | None:
    """Разобрать тело подтверждаемого метода. None = параметров нет."""
    if not body.strip():
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        raise ConfirmBodyError("confirm body must be UTF-8 JSON") from None
    try:
        params = json.loads(text, object_pairs_hook=_no_duplicate_keys,
                            parse_constant=_reject_constant)
    except ConfirmBodyError:
        raise
    except RecursionError:
        raise ConfirmBodyError("confirm body is nested too deeply") from None
    except ValueError:
        raise ConfirmBodyError("confirm body must be valid JSON") from None
    _check_depth(params)
    return params


def describe_params(params: object | None, secrets: tuple = ()) -> str:
    """Одна строка с параметрами для оператора: секреты замаскированы, управляющие — '?'."""
    if params is None:
        return "(no parameters)"
    try:
        text = json.dumps(
            redact_obj(params, secrets), sort_keys=True, ensure_ascii=False,
            separators=(",", ":"), allow_nan=False,
        )
    except (TypeError, ValueError):
        return "(parameters are not representable as JSON)"
    return make_preview(text, PARAM_PREVIEW_LEN)
