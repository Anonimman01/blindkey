"""Клиент Bot API через шлюз: токена у клиента нет, только пакет сертификатов."""
from __future__ import annotations

import json

from gatekeeper.client.session import Session
from gatekeeper.client.transport import Transport
from gatekeeper.core.errors import GatekeeperError


class GatewayError(GatekeeperError):
    """Шлюз или Telegram вернули ошибку. status: HTTP-код ответа."""

    def __init__(self, status: int) -> None:
        super().__init__(f"gateway returned HTTP {status}")
        self.status = status


class BotApi:
    def __init__(self, bundle_dir: str, host: str, port: int, *, server_name: str | None = None) -> None:
        self._t = Transport(Session(bundle_dir), host, port, server_name=server_name)

    def call(self, api_name: str, payload: dict | None = None, *, http_method: str = "POST",
             timeout: float | None = None) -> dict:
        body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        resp = self._t.request(http_method, f"/{api_name}", body, timeout=timeout)
        if resp.status != 200:
            raise GatewayError(resp.status)
        try:
            return json.loads(resp.body)
        except ValueError as exc:
            raise GatekeeperError("gateway returned non-JSON body") from exc

    def get_me(self) -> dict:
        return self.call("getMe", http_method="GET")

    def send_message(self, chat_id: int | str, text: str, **extra) -> dict:
        return self.call("sendMessage", {"chat_id": chat_id, "text": text, **extra})

    def get_updates(self, offset: int | None = None, timeout: int = 30, **extra) -> dict:
        """Long polling. Нужно правило POST:getUpdates. timeout: 0..50 с (шлюз ограничивает)."""
        payload: dict = {"timeout": timeout, **extra}
        if offset is not None:
            payload["offset"] = offset
        # сокет ждёт дольше, чем шлюз держит запрос у Telegram
        return self.call("getUpdates", payload, timeout=timeout + 15)

    def get_file(self, file_id: str) -> dict:
        return self.call("getFile", {"file_id": file_id})

    def download_file(self, file_path: str) -> bytes:
        resp = self._t.request("POST", "/downloadFile", json.dumps({"file_path": file_path}).encode())
        if resp.status != 200:
            raise GatewayError(resp.status)
        return resp.body
