"""Провайдер Vercel REST API: токен подставляется только здесь, в заголовок Authorization.

Только чтение. Политика шлюза не допускает query-параметров, поэтому `teamId` передать нельзя:
используйте токен, ограниченный командой или проектом (такому `teamId` не нужен).
Методы с идентификатором (`getProject`, `getDeployment`) принимают его в JSON-теле:
`{"id": "prj_..."}`.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import ClassVar

from gatekeeper.server.providers.bearer import BearerProvider, Route

# Личные токены начинаются с vcp_; старые токены без префикса: 24 символа.
_TOKEN_RE = re.compile(r"^(?:vc[a-z]_[A-Za-z0-9_-]{16,255}|[A-Za-z0-9]{24})$")


class VercelProvider(BearerProvider):
    name = "vercel"
    DEFAULT_HOST = "api.vercel.com"
    TOKEN_RE = _TOKEN_RE
    ROUTES: ClassVar[Mapping[str, Route]] = {
        "getUser": Route("GET", "GET", "/v2/user"),
        "listProjects": Route("GET", "GET", "/v10/projects"),
        "listDeployments": Route("GET", "GET", "/v7/deployments"),
        "listDomains": Route("GET", "GET", "/v5/domains"),
        "getProject": Route("POST", "GET", "/v9/projects/{id}", params=("id",)),
        "getDeployment": Route("POST", "GET", "/v13/deployments/{id}", params=("id",)),
    }
