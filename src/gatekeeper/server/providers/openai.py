"""Провайдер OpenAI API: ключ подставляется только здесь, в заголовок Authorization.

Ограничения: ответ буферизуется целиком, поэтому стриминг (`stream: true`) запрещён. Клиент
получает ответ модели, но не ключ; расход ограничивают лимиты и суточный бюджет шлюза (на клиента).
`host` настраивается (`upstream_host`), так что провайдер подходит и для совместимых API.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import ClassVar

from gatekeeper.server.providers.base import ProviderError
from gatekeeper.server.providers.bearer import BearerProvider, Route

# sk-..., sk-proj-..., sk-svcacct-..., sk-admin-...: проверяется только общий вид.
_TOKEN_RE = re.compile(r"^sk-[A-Za-z0-9_-]{20,255}$")


class OpenAIProvider(BearerProvider):
    name = "openai"
    DEFAULT_HOST = "api.openai.com"
    TOKEN_RE = _TOKEN_RE
    TIMEOUT: ClassVar[float | None] = 120.0  # генерация идёт дольше обычного запроса
    ROUTES: ClassVar[Mapping[str, Route]] = {
        "listModels": Route("GET", "GET", "/v1/models"),
        "chatCompletions": Route("POST", "POST", "/v1/chat/completions", body=True),
        "createResponse": Route("POST", "POST", "/v1/responses", body=True),
        "createEmbedding": Route("POST", "POST", "/v1/embeddings", body=True),
    }

    def check_body(self, api_name: str, obj: dict[str, object]) -> None:
        if obj.get("stream") not in (None, False):
            raise ProviderError("streaming is not supported")
