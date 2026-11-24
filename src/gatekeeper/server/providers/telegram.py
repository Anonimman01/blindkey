"""Провайдер Telegram Bot API: токен подставляется только здесь, в путь запроса.

Скачивание файлов: Telegram отдаёт файлы по URL с токеном, поэтому клиент не получает
ссылку. Вместо неё есть псевдо-метод downloadFile (правило POST:downloadFile): клиент
шлёт {"file_path": "..."} из ответа getFile, шлюз сам скачивает и отдаёт содержимое.
"""
from __future__ import annotations

import json
import re
import urllib.parse

from gatekeeper.server.providers.base import (
    Provider,
    ProviderError,
    UpstreamRequest,
    UpstreamResponse,
)
from gatekeeper.server.providers.jsonscan import (  # noqa: F401  (реэкспорт для github/тестов)
    MAX_JSON_DEPTH,
    _json_too_deep,
    response_must_be_blocked,
)

# Secret part у BotFather — 35 символов; нижняя граница 30 исключает токены, чья secret part
# совпала бы с обычным текстом чужого сообщения.
_TOKEN_RE = re.compile(r"^[0-9]{3,12}:[A-Za-z0-9_-]{30,128}$")
_FILE_PATH_RE = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9_./-]{0,199}$")
# Ответ блокируется только по точным значениям секрета (known_secrets). Общий шаблон токена
# здесь не используется: чужое сообщение с токеноподобной строкой не должно блокировать
# getUpdates навсегда (offset не сдвигается), а шаблон без якоря давал квадратичное время.
# Шаблоны нужны только для маскирования журнала (core/redact.py).
_BODY_TYPES = frozenset({"application/json", "application/x-www-form-urlencoded", "multipart/form-data"})
DOWNLOAD_METHOD = "downloadFile"
# Long polling: потолок параметра timeout у getUpdates и запас сверх него на сеть.
MAX_POLL_SECONDS = 50
POLL_MARGIN = 10.0
# Form-тело разбираем ради одного параметра: гигантский body не должен тратить память.
_MAX_FORM_BODY = 64 * 1024


def _json_poll(body: bytes) -> int | None:
    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    value = data.get("timeout") if isinstance(data, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _form_poll(body: bytes) -> int | None:
    if len(body) > _MAX_FORM_BODY:
        return None
    try:
        fields = urllib.parse.parse_qs(body.decode("ascii"), max_num_fields=64)
    except (UnicodeDecodeError, ValueError):
        return None
    raw = fields.get("timeout")
    if not raw:
        return None
    try:
        return int(raw[0])
    except ValueError:
        return None


def _poll_seconds(body: bytes) -> int:
    if not body:
        return 0
    value = _json_poll(body)
    if value is None:
        value = _form_poll(body)
    return 0 if value is None else max(0, min(value, MAX_POLL_SECONDS))


class TelegramProvider(Provider):
    name = "telegram"

    def __init__(self, token: str, host: str = "api.telegram.org", port: int = 443) -> None:
        if not isinstance(token, str) or not _TOKEN_RE.fullmatch(token):
            raise ProviderError("invalid bot token format")
        self._token = token
        self._token_secret_part = token.split(":", 1)[1]
        self.host = host
        self.port = port

    def known_secrets(self) -> tuple[str, ...]:
        """Для журнала и предпросмотра (маскирование): токен и его secret part."""
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
            if (not isinstance(file_path, str) or not _FILE_PATH_RE.fullmatch(file_path)
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
        """getUpdates держит соединение до `timeout` секунд: таймаут upstream = timeout + запас.

        Bot API принимает и JSON, и `application/x-www-form-urlencoded`: при form-теле
        параметр не находился, и long polling обрывался таймаутом по умолчанию.
        """
        if api_name != "getUpdates":
            return None
        return _poll_seconds(body) + POLL_MARGIN

    def _leaks(self, text: str) -> bool:
        # Только полный токен: secret part входит в него как подстрока, а отдельная проверка
        # давала бы ложные срабатывания на чужих сообщениях (и вечный блок getUpdates).
        return self._token in text

    def filter_response(self, resp: UpstreamResponse) -> UpstreamResponse | None:
        """None = ответ блокируется (fail closed): секрет, дубли ключей JSON, глубина."""
        if response_must_be_blocked(resp, (self._token,), self._leaks):
            return None
        return resp
