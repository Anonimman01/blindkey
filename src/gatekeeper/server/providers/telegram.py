"""Провайдер Telegram Bot API: токен подставляется только здесь, в путь запроса.

Скачивание файлов: Telegram отдаёт файлы по URL с токеном, поэтому клиент не получает
ссылку. Вместо неё есть псевдо-метод downloadFile (правило POST:downloadFile): клиент
шлёт {"file_path": "..."} из ответа getFile, шлюз сам скачивает и отдаёт содержимое.
"""
from __future__ import annotations

import json
import re

from gatekeeper.server.providers.base import (
    Provider, ProviderError, UpstreamRequest, UpstreamResponse,
)

_TOKEN_RE = re.compile(r"^[0-9]{3,12}:[A-Za-z0-9_-]{8,128}$")
_FILE_PATH_RE = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9_./-]{0,199}$")
# Полный токен Telegram по шаблону: ловит и чужие токены, и токен в искажённом виде.
# Остальные шаблоны redact (/bot..., Bearer, PEM) нужны только для журнала: в ответах
# они давали ложные срабатывания (/bothelp, «Bearer authentication»).
_FULL_TOKEN_RE = re.compile(r"\d+:[A-Za-z0-9_-]{30,}")
_BODY_TYPES = frozenset({"application/json", "application/x-www-form-urlencoded", "multipart/form-data"})
DOWNLOAD_METHOD = "downloadFile"
# Long polling: потолок параметра timeout у getUpdates и запас сверх него на сеть.
MAX_POLL_SECONDS = 50
POLL_MARGIN = 10.0


class TelegramProvider(Provider):
    name = "telegram"

    def __init__(self, token: str, host: str = "api.telegram.org", port: int = 443) -> None:
        if not isinstance(token, str) or not _TOKEN_RE.match(token):
            raise ProviderError("invalid bot token format")
        self._token = token
        self._token_secret_part = token.split(":", 1)[1]
        self.host = host
        self.port = port

    def known_secrets(self) -> tuple[str, ...]:
        return (self._token, self._token_secret_part)

    def _headers(self, body: bytes, content_type: str | None) -> tuple[tuple[str, str], ...]:
        h = [("Host", self.host), ("Connection", "close"),
             ("User-Agent", "gatekeeper"), ("Accept-Encoding", "identity")]
        if body:
            h += [("Content-Type", content_type or ""), ("Content-Length", str(len(body)))]
        return tuple(h)

    def build_request(self, api_name: str, http_method: str, body: bytes,
                      content_type: str | None) -> UpstreamRequest:
        if api_name == DOWNLOAD_METHOD:
            if http_method != "POST":
                raise ProviderError("downloadFile requires POST")
            try:
                file_path = json.loads(body.decode("utf-8"))["file_path"]
            except (ValueError, KeyError, TypeError, AttributeError) as exc:
                raise ProviderError("downloadFile needs JSON {file_path}") from exc
            if (not isinstance(file_path, str) or not _FILE_PATH_RE.match(file_path)
                    or ".." in file_path or "//" in file_path):
                raise ProviderError("invalid file_path")
            return UpstreamRequest("GET", f"/file/bot{self._token}/{file_path}",
                                   self._headers(b"", None))
        if body:
            ct = content_type or ""
            if (len(ct) > 200 or not ct.isascii() or not ct.isprintable()
                    or ct.split(";")[0].strip().lower() not in _BODY_TYPES):
                raise ProviderError("unsupported content type")
        return UpstreamRequest(http_method, f"/bot{self._token}/{api_name}",
                               self._headers(body, content_type), body)

    def upstream_timeout(self, api_name: str, body: bytes) -> float | None:
        """getUpdates держит соединение до `timeout` секунд: таймаут upstream = timeout + запас."""
        if api_name != "getUpdates":
            return None
        poll = 0
        if body:
            try:
                value = json.loads(body.decode("utf-8")).get("timeout", 0)
            except (ValueError, AttributeError):
                value = 0
            if isinstance(value, int) and not isinstance(value, bool):
                poll = max(0, min(value, MAX_POLL_SECONDS))
        return poll + POLL_MARGIN

    def _leaks(self, text: str) -> bool:
        if any(secret in text for secret in self.known_secrets()):
            return True
        return _FULL_TOKEN_RE.search(text) is not None

    def filter_response(self, resp: UpstreamResponse) -> UpstreamResponse | None:
        """None = ответ блокируется. Блок только по точным секретам и полному шаблону токена."""
        for secret in self.known_secrets():
            if secret.encode("ascii") in resp.body:
                return None
        ct = (resp.content_type or "").lower()
        if not ct.startswith(("application/json", "text/")):
            return resp
        text = resp.body.decode("utf-8", "replace")
        if self._leaks(text):
            return None
        if ct.startswith("application/json"):
            # Токен мог прийти с JSON-экранированием (\u0041...): проверяем разобранные строки.
            try:
                data = json.loads(text)
            except ValueError:
                return resp  # не JSON: сырой текст уже проверен
            except RecursionError:
                return None  # не удалось разобрать: блокируем (fail closed)
            stack = [data]
            while stack:
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
