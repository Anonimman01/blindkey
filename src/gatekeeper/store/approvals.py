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
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.timeutil import unix_now
from gatekeeper.server.audit.sink import _try_lock, _unlock
from gatekeeper.store.atomic import atomic_write_private
from gatekeeper.store.fsperm import FilePermissionError, harden_private_file

_BINARY = getattr(os, "O_BINARY", 0)
PENDING, APPROVED = "pending", "approved"
ID_LEN = 12             # длина показываемого идентификатора заявки (hex)
MIN_ID_PREFIX = 6       # короче префикс в CLI не принимается
MAX_PENDING = 100       # всего заявок и подтверждений в файле
MAX_PER_CLIENT = 20     # на одного клиента
PREVIEW_LEN = 200
# Для параметров подтверждаемого JSON-запроса места больше: оператор должен видеть все
# ключи запроса, а не начало тела (C-04).
PARAM_PREVIEW_LEN = 400


class ApprovalError(GatekeeperError):
    """Ошибка хранилища подтверждений."""


def request_key(client_id: str, http_method: str, api: str, body: bytes,
                content_type: str = "") -> str:
    """Ключ заявки: хеш от клиента, метода, имени API, хеша тела и Content-Type.

    Content-Type входит в ключ: одно и то же тело как JSON и как form — разные запросы (X-03).
    """
    body_hash = hashlib.sha256(body).hexdigest()
    raw = "\n".join((client_id, http_method, api, body_hash, content_type)).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


_HEX64 = frozenset("0123456789abcdef")


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX64


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_entry(key: object, v: object) -> None:
    """Запись должна быть целой и согласованной с ключом (клиент/метод/API/хеш тела)."""
    if not _is_hex64(key) or not isinstance(v, dict):
        raise ValueError("bad entry")
    if v.get("status") not in (PENDING, APPROVED):
        raise ValueError("bad status")
    # Записи старого формата (без content_type) считаются повреждёнными и отбрасываются:
    # заявки живут ttl секунд, терять их при обновлении не жалко (миграция не нужна).
    for f in ("client", "method", "api", "preview", "ip", "content_type"):
        if not isinstance(v.get(f), str):
            raise ValueError(f"bad {f}")
    if not _is_hex64(v.get("body_sha256")):
        raise ValueError("bad body_sha256")
    for f in ("body_len", "created", "expires"):
        if not _is_int(v.get(f)):
            raise ValueError(f"bad {f}")
    raw = "\n".join((v["client"], v["method"], v["api"], v["body_sha256"],
                     v["content_type"])).encode("utf-8")
    if hashlib.sha256(raw).hexdigest() != key:
        raise ValueError("key does not match entry")


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
        self.last_dropped = 0  # сколько повреждённых записей проигнорировано последним чтением

    # ---- файл ----
    def _read(self) -> tuple[dict[str, dict], int]:
        """Вернуть (годные записи, число выброшенных повреждённых).

        Повреждённая запись больше не ломает весь файл (B-10): она пропускается, а
        `list_items`/`request` перезаписывают файл без неё. Некорректная структура
        самого файла по-прежнему ошибка: иначе его легко принять за пустой.
        """
        try:
            harden_private_file(self.path)  # владелец, не симлинк, режим 0600
        except FilePermissionError as exc:
            raise ApprovalError(f"approvals.json: {exc}") from exc
        try:
            raw = self.path.read_text("utf-8")
        except FileNotFoundError:
            return {}, 0
        try:
            doc = json.loads(raw)
            items = doc["items"]
            if doc.get("version") != 1 or not isinstance(items, dict):
                raise ValueError("bad structure")
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ApprovalError("approvals.json is malformed (fix or delete the file)") from exc
        valid: dict[str, dict] = {}
        dropped = 0
        for key, v in items.items():
            try:
                _validate_entry(key, v)
            except ValueError:
                dropped += 1  # повреждённая/подделанная запись: не даём ей сломать остальные
                continue
            valid[key] = v
        return valid, dropped

    def _save(self, items: dict[str, dict]) -> None:
        data = json.dumps({"version": 1, "items": items}, indent=2, sort_keys=True)
        atomic_write_private(self.path, data.encode("utf-8"))

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
                with suppress(OSError):
                    _unlock(fd)
        finally:
            os.close(fd)

    def _purge(self, items: dict[str, dict]) -> bool:
        now = self._clock()
        dead = [k for k, v in items.items() if v["expires"] <= now]
        for k in dead:
            del items[k]
        return bool(dead)

    # ---- шлюз ----
    def request(self, client_id: str, http_method: str, api: str, body: bytes,
                preview: str, ip: str, content_type: str = "", *,
                consume: bool = True) -> RequestResult:
        """Подтверждение есть: approved. Иначе завести или найти заявку.

        `consume=True` (по умолчанию): подтверждение при этом расходуется. Шлюз вызывает с
        `consume=False`, прогоняет остальные проверки и расходует подтверждение методом
        `consume()` непосредственно перед обращением к upstream (issue #11).
        """
        key = request_key(client_id, http_method, api, body, content_type)
        rid = key[:ID_LEN]
        with self._locked():
            items, dropped = self._read()
            changed = self._purge(items) or dropped > 0
            entry = items.get(key)
            if entry is not None and entry.get("status") == APPROVED:
                if consume:
                    del items[key]
                    self._save(items)
                elif changed:
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
                "content_type": content_type,
                "created": now, "expires": now + self.ttl,
            }
            self._save(items)
            return RequestResult("new", rid)

    def consume(self, client_id: str, http_method: str, api: str, body: bytes,
                content_type: str = "") -> bool:
        """Израсходовать подтверждение. False, если его уже нет (истекло или взято параллельным
        запросом): одно подтверждение разрешает ровно одно выполнение."""
        key = request_key(client_id, http_method, api, body, content_type)
        with self._locked():
            items, dropped = self._read()
            changed = self._purge(items) or dropped > 0
            entry = items.get(key)
            if entry is None or entry.get("status") != APPROVED:
                if changed:
                    self._save(items)
                return False
            del items[key]
            self._save(items)
            return True

    # ---- оператор ----
    def list_items(self) -> list[tuple[str, dict]]:
        """Действующие заявки и подтверждения (id, запись), старые первыми.

        Повреждённые записи пропускаются и удаляются из файла; их число — в `last_dropped`.
        """
        with self._locked():
            items, dropped = self._read()
            if self._purge(items) or dropped:
                self._save(items)
        self.last_dropped = dropped
        return sorted(((k[:ID_LEN], v) for k, v in items.items()), key=lambda t: t[1]["created"])

    def peek(self, prefix: str) -> dict:
        """Показать заявку, ничего не меняя (нужно, чтобы записать журнал до действия)."""
        with self._locked():
            items, _dropped = self._read()
            self._purge(items)
            key = self._resolve(items, prefix)
            return dict(items[key], id=key[:ID_LEN])

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
            items, _dropped = self._read()
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
            items, _dropped = self._read()
            self._purge(items)
            key = self._resolve(items, prefix)
            entry = items.pop(key)
            self._save(items)
            return dict(entry, id=key[:ID_LEN])
