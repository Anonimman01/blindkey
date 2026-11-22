"""Провайдер Cloudflare API: токен подставляется только здесь, в заголовок Authorization.

Поддерживаются API-токены (пользовательские `cfut_`, аккаунтные `cfat_` и старые без префикса, 40
символов). Global API Key не поддерживается: он требует другой заголовок и даёт полный доступ.
Методы с идентификатором зоны принимают его в JSON-теле: `{"zone_id": "<32 hex>"}`.
`createDnsRecord` и `purgeCache` меняют состояние: добавьте их в `confirm_apis` провайдера.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import ClassVar

from gatekeeper.server.providers.bearer import BearerProvider, Route

_TOKEN_RE = re.compile(r"^(?:cf(?:ut|at)_[A-Za-z0-9_-]{40,80}|[A-Za-z0-9_-]{40})$")
_BASE = "/client/v4"


class CloudflareProvider(BearerProvider):
    name = "cloudflare"
    DEFAULT_HOST = "api.cloudflare.com"
    TOKEN_RE = _TOKEN_RE
    PARAM_RE = re.compile(r"^[0-9a-f]{32}$")
    ROUTES: ClassVar[Mapping[str, Route]] = {
        "verifyToken": Route("GET", "GET", f"{_BASE}/user/tokens/verify"),
        "listAccounts": Route("GET", "GET", f"{_BASE}/accounts"),
        "listZones": Route("GET", "GET", f"{_BASE}/zones"),
        "getZone": Route("POST", "GET", f"{_BASE}/zones/{{zone_id}}", params=("zone_id",)),
        "listDnsRecords": Route("POST", "GET", f"{_BASE}/zones/{{zone_id}}/dns_records",
                                params=("zone_id",)),
        "createDnsRecord": Route("POST", "POST", f"{_BASE}/zones/{{zone_id}}/dns_records",
                                 params=("zone_id",), body=True),
        "purgeCache": Route("POST", "POST", f"{_BASE}/zones/{{zone_id}}/purge_cache",
                            params=("zone_id",), body=True),
    }
