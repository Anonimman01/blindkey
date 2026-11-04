"""Интерфейс провайдера upstream-API. Секрет живёт только внутри провайдера."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from gatekeeper.core.errors import GatekeeperError


class ProviderError(GatekeeperError):
    """Запрос нельзя превратить в безопасный запрос к upstream (текст без секретов)."""


@dataclass(frozen=True)
class UpstreamRequest:
    method: str
    path: str                              # содержит секрет: в журнал не писать
    headers: tuple[tuple[str, str], ...]
    body: bytes = b""


@dataclass(frozen=True)
class UpstreamResponse:
    status: int
    content_type: str | None
    body: bytes


class Provider(ABC):
    name: str
    host: str
    port: int = 443

    @abstractmethod
    def build_request(self, api_name: str, http_method: str, body: bytes,
                      content_type: str | None) -> UpstreamRequest:
        """api_name берётся из правила политики (не от клиента). Ошибка = ProviderError."""

    @abstractmethod
    def known_secrets(self) -> tuple[str, ...]:
        """Значения, которые нельзя выпускать в журнал и ответы."""

    @abstractmethod
    def filter_response(self, resp: UpstreamResponse) -> UpstreamResponse | None:
        """None = ответ содержит секрет и блокируется."""

    def upstream_timeout(self, api_name: str, body: bytes) -> float | None:
        """Полный таймаут запроса к upstream; None = значение по умолчанию."""
        return None

    def dangerous(self, api_name: str) -> bool:  # v2: подтверждение человеком
        return False
