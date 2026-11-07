"""Подтверждения опасных действий (v2).

Метод из `[confirm] apis` шлюз не выполняет сразу: первый запрос создаёт заявку (pending),
оператор на машине шлюза подтверждает её (`gatekeeper approve`), и повтор того же запроса
проходит один раз. Подтверждение привязано к (клиент, метод HTTP, имя API, SHA-256 тела):
изменённое тело или другой клиент подтверждения не получают. Подтверждение одноразовое и живёт
`ttl` секунд. Заявки лежат в approvals.json (0600) под межпроцессным замком; шлюз читает файл на
каждый запрос, поэтому перезапуск не нужен. Клиент подтвердить себя не может: файл доступен
только оператору.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.timeutil import unix_now
from gatekeeper.server.audit.sink import _try_lock, _unlock

_BINARY = getattr(os, "O_BINARY", 0)
PENDING, APPROVED = "pending", "approved"
ID_LEN = 12             # длина показываемого идентификатора заявки (hex)
MIN_ID_PREFIX = 6       # короче префикс в CLI не принимается
MAX_PENDING = 100       # всего заявок и подтверждений в файле
MAX_PER_CLIENT = 20     # на одного клиента
PREVIEW_LEN = 200


class ApprovalError(GatekeeperError):
    """Ошибка хранилища подтверждений."""


def request_key(client_id: str, http_method: str, api: str, body: bytes) -> str:
    """Ключ заявки: хеш от клиента, метода, имени API и хеша тела."""
    body_hash = hashlib.sha256(body).hexdigest()
    raw = "\n".join((client_id, http_method, api, body_hash)).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def make_preview(text: str, limit: int = PREVIEW_LEN) -> str:
    """Безопасная для терминала одна строка: непечатаемые символы (в том числе ESC) = '?'."""
    out = "".join(ch if ch.isprintable() else "?" for ch in text[:limit])
    return out + ("…" if len(text) > limit else "")


@dataclass(frozen=True)
class RequestResult:
    state: str   # "approved" (подтверждение израсходовано) | "pending" | "new" | "full"
    id: str


class Approvals:
    def __init__(self, path: str | os.PathLike, ttl: int = 300,
                 clock: Callable[[], int] = unix_now) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        self.path, self.ttl, self._clock = Path(path), ttl, clock

    # ---- файл ----
    def _read(self) -> dict[str, dict]:
        try:
            raw = self.path.read_text("utf-8")
        except FileNotFoundError:
            return {}
        try:
            doc = json.loads(raw)
            items = doc["items"]
            if doc.get("version") != 1 or not isinstance(items, dict):
                raise ValueError
        except (ValueError, KeyError, TypeError) as exc:
            raise ApprovalError("approvals.json is malformed") from exc
        return items

    def _save(self, items: dict[str, dict]) -> None:
        data = json.dumps({"version": 1, "items": items}, indent=2, sort_keys=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _BINARY, 0o600)
        try:
            os.write(fd, data.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.path)

    @contextmanager
    def _locked(self, timeout: float = 10.0) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock = self.path.with_name(self.path.name + ".lock")
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | _BINARY, 0o600)
        try:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    _try_lock(fd)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise ApprovalError("approvals lock timeout") from None
                    time.sleep(0.005)
            try:
                yield
            finally:
                try:
                    _unlock(fd)
                except OSError:
                    pass
        finally:
            os.close(fd)

    def _purge(self, items: dict[str, dict]) -> bool:
        now = self._clock()
        dead = [k for k, v in items.items() if not isinstance(v.get("expires"), int) or v["expires"] <= now]
        for k in dead:
            del items[k]
        return bool(dead)

    # ---- шлюз ----
    def request(self, client_id: str, http_method: str, api: str, body: bytes,
                preview: str, ip: str) -> RequestResult:
        """Подтверждение есть: израсходовать его (approved). Иначе завести или найти заявку."""
        key = request_key(client_id, http_method, api, body)
        rid = key[:ID_LEN]
        with self._locked():
            items = self._read()
            changed = self._purge(items)
            entry = items.get(key)
            if entry is not None and entry.get("status") == APPROVED:
                del items[key]
                self._save(items)
                return RequestResult("approved", rid)
            if entry is not None:
                if changed:
                    self._save(items)
                return RequestResult("pending", rid)
            mine = sum(1 for v in items.values() if v.get("client") == client_id)
            if len(items) >= MAX_PENDING or mine >= MAX_PER_CLIENT:
                if changed:
                    self._save(items)
                return RequestResult("full", rid)
            now = self._clock()
            items[key] = {
                "client": client_id, "method": http_method, "api": api,
                "body_sha256": hashlib.sha256(body).hexdigest(), "body_len": len(body),
                "preview": preview, "ip": ip, "status": PENDING,
                "created": now, "expires": now + self.ttl,
            }
            self._save(items)
            return RequestResult("new", rid)

    # ---- оператор ----
    def list_items(self) -> list[tuple[str, dict]]:
        """Действующие заявки и подтверждения (id, запись), старые первыми."""
        with self._locked():
            items = self._read()
            if self._purge(items):
                self._save(items)
        return sorted(((k[:ID_LEN], v) for k, v in items.items()), key=lambda t: t[1]["created"])

    @staticmethod
    def _resolve(items: dict[str, dict], prefix: str) -> str:
        prefix = (prefix or "").lower()
        if len(prefix) < MIN_ID_PREFIX:
            raise ApprovalError(f"id too short (need at least {MIN_ID_PREFIX} characters)")
        found = [k for k in items if k.startswith(prefix)]
        if not found:
            raise ApprovalError("no such request (expired or already handled)")
        if len(found) > 1:
            raise ApprovalError("id is ambiguous")
        return found[0]

    def approve(self, prefix: str) -> dict:
        """Подтвердить заявку: срок подтверждения отсчитывается от этого момента."""
        with self._locked():
            items = self._read()
            self._purge(items)
            key = self._resolve(items, prefix)
            entry = items[key]
            if entry.get("status") != PENDING:
                raise ApprovalError("already approved")
            entry["status"] = APPROVED
            entry["expires"] = self._clock() + self.ttl
            self._save(items)
            return dict(entry, id=key[:ID_LEN])

    def reject(self, prefix: str) -> dict:
        """Отклонить заявку или отозвать неиспользованное подтверждение."""
        with self._locked():
            items = self._read()
            self._purge(items)
            key = self._resolve(items, prefix)
            entry = items.pop(key)
            self._save(items)
            return dict(entry, id=key[:ID_LEN])
