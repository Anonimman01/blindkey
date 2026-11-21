"""Провайдер GitHub REST API: токен подставляется только здесь, в заголовок Authorization.

В отличие от Telegram, у GitHub токен идёт не в путь, а в заголовок, но принцип тот же:
клиент токена не видит. Путь к upstream берётся из фиксированной таблицы по api_name
(а api_name выбирает правило политики), поэтому клиент не может обратиться к чужому URL.
Чтобы разрешить новый метод GitHub, достаточно добавить строку в _ROUTES.
"""
from __future__ import annotations

import json
import re

from gatekeeper.server.providers.base import (
    Provider,
    ProviderError,
    UpstreamRequest,
    UpstreamResponse,
)
from gatekeeper.server.providers.telegram import MAX_JSON_DEPTH, _json_too_deep

# Классический (ghp_, gho_, ghu_, ghs_, ghr_) и fine-grained (github_pat_) токены.
_TOKEN_RE = re.compile(r"^(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})$")
# Тот же шаблон без привязки к краям: ловит и чужие токены в ответе.
_ANY_TOKEN_RE = re.compile(r"gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}")

# api_name -> (HTTP-метод, путь upstream). Только то, что явно перечислено.
_ROUTES: dict[str, tuple[str, str]] = {
    "getUser": ("GET", "/user"),
    "listRepos": ("GET", "/user/repos"),
    "listNotifications": ("GET", "/notifications"),
    "getRateLimit": ("GET", "/rate_limit"),
}


class GitHubProvider(Provider):
    name = "github"

    def __init__(self, token: str, host: str = "api.github.com", port: int = 443) -> None:
        if not isinstance(token, str) or not _TOKEN_RE.match(token):
            raise ProviderError("invalid github token format")
        self._token = token
        self.host = host
        self.port = port

    def known_secrets(self) -> tuple[str, ...]:
        return (self._token,)

    def build_request(self, api_name: str, http_method: str, body: bytes,
                      content_type: str | None) -> UpstreamRequest:
        route = _ROUTES.get(api_name)
        if route is None:
            raise ProviderError("unknown github api")
        method, path = route
        if http_method != method:
            raise ProviderError(f"{api_name} requires {method}")
        if body:
            raise ProviderError(f"{api_name} takes no body")
        headers = (
            ("Host", self.host), ("Connection", "close"), ("User-Agent", "gatekeeper"),
            ("Accept", "application/vnd.github+json"), ("X-GitHub-Api-Version", "2022-11-28"),
            ("Accept-Encoding", "identity"), ("Authorization", f"Bearer {self._token}"),
        )
        return UpstreamRequest(method, path, headers)

    def _leaks(self, text: str) -> bool:
        return self._token in text or _ANY_TOKEN_RE.search(text) is not None

    def filter_response(self, resp: UpstreamResponse) -> UpstreamResponse | None:
        """None = ответ блокируется (fail closed). Логика та же, что у Telegram."""
        if self._token.encode("ascii") in resp.body:
            return None
        ct = (resp.content_type or "").lower()
        if not ct.startswith(("application/json", "text/")):
            return resp
        text = resp.body.decode("utf-8", "replace")
        if self._leaks(text):
            return None
        if ct.startswith("application/json"):
            if _json_too_deep(text, MAX_JSON_DEPTH):
                return None
            try:
                data = json.loads(text)
            except ValueError:
                return resp
            except RecursionError:
                return None
            stack = [data]
            while stack:  # токен мог прийти с JSON-экранированием (\u0067hp_...)
                node = stack.pop()
                if isinstance(node, str):
                    if self._leaks(node):
                        return None
                elif isinstance(node, dict):
                    for k, v in node.items():
                        stack.append(k)
                        stack.append(v)
                elif isinstance(node, list):
                    stack.extend(node)
        return resp
