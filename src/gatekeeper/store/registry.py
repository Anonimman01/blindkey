"""Реестр клиентов (JSON, права 0600, атомарная запись). В v2: sqlite3.

Формат clients.json:
  {"version":1,"clients":{"<id>":{"fingerprint":"<hex64>","master_secret":"<hex64>",
   "status":"active","created":T,"expires":T,"allow":["POST:sendMessage", ...]}}}
master_secret хранится только на шлюзе и в пакете клиента; наружу из CLI не выводится.
"""
from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.signing import is_valid_client_id
from gatekeeper.server.audit.sink import _try_lock, _unlock

_BINARY = getattr(os, "O_BINARY", 0)
STATUSES = frozenset({"active", "frozen", "revoked"})
# Разрешённые переходы статуса. revoked необратим: для возврата выпускают нового клиента.
_TRANSITIONS = {"active": {"frozen", "revoked"}, "frozen": {"active", "revoked"}, "revoked": set()}


class RegistryError(GatekeeperError):
    """Ошибка реестра клиентов."""


class Registry:
    def __init__(self, path: str | os.PathLike):
        self.path = Path(path)

    def load(self) -> dict[str, dict]:
        try:
            raw = self.path.read_text("utf-8")
        except FileNotFoundError:
            return {}
        try:
            doc = json.loads(raw)
            clients = doc["clients"]
            if doc.get("version") != 1 or not isinstance(clients, dict):
                raise ValueError
        except (ValueError, KeyError, TypeError) as exc:
            raise RegistryError("clients.json is malformed") from exc
        return clients

    def _save(self, clients: dict[str, dict]) -> None:
        data = json.dumps({"version": 1, "clients": clients}, indent=2, sort_keys=True)
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
        """Межпроцессный замок на цикл «прочитать, изменить, записать» (файл <реестр>.lock)."""
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
                        raise RegistryError("registry lock timeout") from None
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

    def init_empty(self) -> None:
        if self.path.exists():
            raise RegistryError("clients.json already exists")
        self._save({})

    def add(self, client_id: str, entry: dict) -> None:
        if not is_valid_client_id(client_id):
            raise RegistryError("invalid client_id")
        with self._locked():
            clients = self.load()
            if client_id in clients:
                raise RegistryError(f"client already exists: {client_id}")
            for other in clients.values():
                if other.get("fingerprint") == entry.get("fingerprint"):
                    raise RegistryError("fingerprint already registered")
            clients[client_id] = entry
            self._save(clients)

    def set_status(self, client_id: str, status: str) -> None:
        """Меняет статус по таблице переходов (revoked необратим)."""
        if status not in STATUSES:
            raise RegistryError("invalid status")
        with self._locked():
            clients = self.load()
            if client_id not in clients:
                raise RegistryError("unknown client")
            current = clients[client_id].get("status")
            if status not in _TRANSITIONS.get(current, ()):
                raise RegistryError(f"cannot change status {current} -> {status}")
            clients[client_id]["status"] = status
            self._save(clients)

    def renew(self, client_id: str, *, fingerprint: str, master_secret: str, expires: int) -> None:
        """Подменяет сертификат и ключ клиента; старый отпечаток сразу перестаёт работать."""
        with self._locked():
            clients = self.load()
            entry = clients.get(client_id)
            if entry is None:
                raise RegistryError("unknown client")
            if entry.get("status") == "revoked":
                raise RegistryError("client is revoked: issue a new client instead")
            for cid, other in clients.items():
                if cid != client_id and other.get("fingerprint") == fingerprint:
                    raise RegistryError("fingerprint already registered")
            entry.update({"fingerprint": fingerprint, "master_secret": master_secret,
                          "expires": expires})
            self._save(clients)
