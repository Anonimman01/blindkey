"""Основа провайдеров с токеном в заголовке `Authorization: Bearer` и фиксированной таблицей маршрутов.

Как у GitHub: клиент токена не видит, путь к upstream берётся из таблицы по api_name (а api_name
выбирает правило политики). Политика шлюза пропускает только `GET`/`POST` и не допускает query,
поэтому есть три вида маршрутов (см. `Route`):

- без параметров и без тела: `GET:listModels`;
- с параметрами пути: клиент шлёт `POST` с JSON `{"zone_id": "..."}`, шлюз вставляет значение в путь
  (значение проверяется строгим шаблоном) и делает upstream-запрос нужным методом (как
  `downloadFile` у Telegram);
- с телом: JSON-объект проверяется, разбирается и отправляется upstream заново (шлюз не пересылает
  байты клиента: дубли ключей, `NaN` и лишние поля не доходят до upstream).
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import ClassVar

from gatekeeper.server.providers.base import (
    Provider,
    ProviderError,
    UpstreamRequest,
    UpstreamResponse,
)
from gatekeeper.server.providers.jsonscan import _json_too_deep, response_must_be_blocked

_ALLOWED_CLIENT_METHODS = frozenset({"GET", "POST"})
_ALLOWED_UPSTREAM_METHODS = frozenset({"GET", "POST"})
_PLACEHOLDER_RE = re.compile(r"\{([a-z_]+)\}")
_MAX_CT_LEN = 200


@dataclass(frozen=True)
class Route:
    client_method: str            # метод клиента (то, что написано в правиле политики)
    method: str                   # метод запроса к upstream
    path: str                     # путь; параметры в фигурных скобках: "/zones/{zone_id}"
    params: tuple[str, ...] = ()  # имена параметров пути; клиент передаёт их в JSON-теле
    body: bool = False            # остальные поля JSON-тела уходят upstream

    def __post_init__(self) -> None:
        if (self.client_method not in _ALLOWED_CLIENT_METHODS
                or self.method not in _ALLOWED_UPSTREAM_METHODS):
            raise ValueError("route: only GET and POST are supported")
        if tuple(_PLACEHOLDER_RE.findall(self.path)) != self.params:
            raise ValueError("route: path placeholders must match params")
        if (self.params or self.body) and self.client_method != "POST":
            raise ValueError("route: params or body require client POST")
        if self.body and self.method != "POST":
            raise ValueError("route: body requires upstream POST")


class _DuplicateKey(Exception):
    pass


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: set[str] = set()
    for key, _ in pairs:
        if key in seen:
            raise _DuplicateKey
        seen.add(key)
    return dict(pairs)


def _reject_constant(name: str) -> object:
    raise ValueError("non-finite number")


def _parse_object(body: bytes, content_type: str | None) -> dict[str, object]:
    ct = content_type or ""
    if (len(ct) > _MAX_CT_LEN or not ct.isascii() or not ct.isprintable()
            or ct.split(";")[0].strip().lower() != "application/json"):
        raise ProviderError("content type must be application/json")
    try:
        text = body.decode("utf-8")
        if _json_too_deep(text):
            raise ProviderError("json is nested too deeply")
        data = json.loads(text, object_pairs_hook=_strict_object, parse_constant=_reject_constant)
    except _DuplicateKey as exc:
        raise ProviderError("duplicate keys in json body") from exc
    except (ValueError, RecursionError) as exc:
        raise ProviderError("body must be a JSON object") from exc
    if not isinstance(data, dict):
        raise ProviderError("body must be a JSON object")
    return data


class BearerProvider(Provider):
    """Подкласс задаёт: name, DEFAULT_HOST, TOKEN_RE, ROUTES, PARAM_RE (и при нужде TIMEOUT, check_body)."""

    DEFAULT_HOST: ClassVar[str]
    TOKEN_RE: ClassVar[re.Pattern[str]]
    ROUTES: ClassVar[Mapping[str, Route]]
    # Значение параметра пути: строго, без «..», слэшей и процент-кодирования.
    PARAM_RE: ClassVar[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    TIMEOUT: ClassVar[float | None] = None

    def __init__(self, token: str, host: str | None = None, port: int = 443) -> None:
        if not isinstance(token, str) or not self.TOKEN_RE.fullmatch(token):
            raise ProviderError(f"invalid {self.name} token format")
        self._token = token
        self.host = host or self.DEFAULT_HOST
        self.port = port

    def known_secrets(self) -> tuple[str, ...]:
        return (self._token,)

    def check_body(self, api_name: str, obj: dict[str, object]) -> None:
        """Дополнительные правила к телу (ProviderError = отказ). По умолчанию их нет."""

    def build_request(self, api_name: str, http_method: str, body: bytes,
                      content_type: str | None) -> UpstreamRequest:
        route = self.ROUTES.get(api_name)
        if route is None:
            raise ProviderError(f"unknown {self.name} api")
        if http_method != route.client_method:
            raise ProviderError(f"{api_name} requires {route.client_method}")
        path = route.path
        up_body = b""
        if route.params or route.body:
            obj = _parse_object(body, content_type)
            values: dict[str, str] = {}
            for pname in route.params:
                value = obj.pop(pname, None)
                if (not isinstance(value, str) or not self.PARAM_RE.fullmatch(value)
                        or ".." in value):
                    raise ProviderError(f"invalid {pname}")
                values[pname] = value
            if route.body:
                self.check_body(api_name, obj)
                try:
                    up_body = json.dumps(obj, ensure_ascii=True, allow_nan=False,
                                         separators=(",", ":")).encode("ascii")
                except (ValueError, RecursionError) as exc:
                    raise ProviderError("body is not serializable") from exc
            elif obj:
                raise ProviderError(f"{api_name} takes only {', '.join(route.params)}")
            path = path.format(**values)
        elif body:
            raise ProviderError(f"{api_name} takes no body")
        headers = [
            ("Host", self.host), ("Connection", "close"), ("User-Agent", "gatekeeper"),
            ("Accept", "application/json"), ("Accept-Encoding", "identity"),
            ("Authorization", f"Bearer {self._token}"),
        ]
        if up_body:
            headers += [("Content-Type", "application/json"), ("Content-Length", str(len(up_body)))]
        return UpstreamRequest(route.method, path, tuple(headers), up_body)

    def upstream_timeout(self, api_name: str, body: bytes) -> float | None:
        return self.TIMEOUT

    def _leaks(self, text: str) -> bool:
        return self._token in text

    def filter_response(self, resp: UpstreamResponse) -> UpstreamResponse | None:
        """None = ответ блокируется (fail closed). Логика та же, что у Telegram и GitHub."""
        if response_must_be_blocked(resp, (self._token,), self._leaks):
            return None
        return resp
