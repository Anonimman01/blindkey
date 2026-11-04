"""Реестр провайдеров."""
from __future__ import annotations

from gatekeeper.server.providers.base import Provider, ProviderError
from gatekeeper.server.providers.telegram import TelegramProvider


def create_provider(name: str, secret: str, host: str | None = None, port: int = 443) -> Provider:
    if name == "telegram":
        return TelegramProvider(secret, host=host or "api.telegram.org", port=port)
    raise ProviderError(f"unknown provider: {name}")
