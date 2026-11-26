"""Реестр клиентов (JSON, права 0600, атомарная запись). В v2: sqlite3.

Формат clients.json:
  {"version":1,"clients":{"<id>":{"fingerprint":"<hex64>","master_secret":"<hex64>",
   "status":"active","created":T,"expires":T,"allow":["POST:sendMessage", ...]}}}
master_secret хранится только на шлюзе и в пакете клиента; наружу из CLI не выводится.
"""
from __future__ import annotations

import json
import os
import stat
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.signing import is_valid_client_id
from gatekeeper.server.audit.sink import _try_lock, _unlock
from gatekeeper.store.atomic import atomic_write_private
from gatekeeper.store.registry_key import (
    ENV_KEY_FILE,
    RegistryKeyError,
    load_key_from_env,
    seal,
    unseal,
)

_BINARY = getattr(os, "O_BINARY", 0)
STATUSES = frozenset({"active", "frozen", "revoked"})
# Разрешённые переходы статуса. revoked необратим: для возврата выпускают нового клиента.
_TRANSITIONS = {"active": {"frozen", "revoked"}, "frozen": {"active", "revoked"}, "revoked": set()}


class RegistryError(GatekeeperError):
    """Ошибка реестра клиентов."""


class RegistryLockedError(RegistryError):
    """clients.json зашифрован, а ключа нет: секреты прочитать нельзя.

    Метаданные (статус, отпечаток, срок) при этом доступны: `load(decrypt=False)` и
    `set_status(..., decrypt=False)` работают без ключа, иначе инцидент нельзя закрыть.
    """


class Registry:
    """Реестр клиентов. При наличии ключа master_secret хранится зашифрованным (B2).

    На диске тогда лежит `master_secret_enc`, а `load()` возвращает расшифрованный
    `master_secret` в памяти: остальной код (identity, CLI) работает как раньше.
    """

    def __init__(self, path: str | os.PathLike, *, key: bytes | None = None):
        self.path = Path(path)
        # Единственный переключатель шифрования — переменная окружения с путём к ключу:
        # без неё всё как раньше (открытый текст), с ней и чтение, и запись шифруются.
        # Так опция работает одинаково для шлюза и для CLI (add-client, renew, freeze).
        if key is None and os.environ.get(ENV_KEY_FILE):
            key = load_key_from_env()
        self._key = key

    def _decrypt_entry(self, client_id: str, entry: dict) -> dict:
        enc = entry.get("master_secret_enc")
        if enc is None:
            return entry
        if self._key is None:
            raise RegistryLockedError(
                "clients.json is encrypted: set GATEKEEPER_REGISTRY_KEY_FILE "
                "(or run `gatekeeper encrypt-registry --decrypt`); status/freeze/revoke "
                "work without the key")
        try:
            entry["master_secret"] = unseal(self._key, enc, client_id)
        except RegistryKeyError as exc:
            raise RegistryError(f"client {client_id}: {exc}") from exc
        return entry

    @staticmethod
    def _with_secret(client_id: str, entry: dict, key: bytes | None) -> dict:
        """Копия записи в том виде, в котором её надо записать на диск."""
        out = dict(entry)
        enc = out.pop("master_secret_enc", None)
        secret = out.pop("master_secret", None)
        if secret is None:
            # Секрета в памяти нет (load(decrypt=False) или запись без секрета): шифротекст
            # сохраняем как есть, иначе смена статуса стёрла бы master_secret клиента.
            if enc is not None:
                out["master_secret_enc"] = enc
            return out
        if key is None:
            out["master_secret"] = secret
        else:
            out["master_secret_enc"] = seal(key, secret, client_id)
        return out

    def load(self, *, decrypt: bool = True) -> dict[str, dict]:
        """Прочитать реестр. `decrypt=False` — только метаданные, без master_secret.

        Так `status`/`freeze`/`revoke` работают и без ключа шифрования: для реакции на
        инцидент секрет не нужен, а ключ есть только у службы шлюза.
        """
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
        if not decrypt:
            return dict(clients)
        return {cid: self._decrypt_entry(cid, entry) if isinstance(entry, dict) else entry
                for cid, entry in clients.items()}

    def check_permissions(self) -> None:
        """Файл хранит master_secret (открытым текстом или шифротекстом): доступ только владельцу.

        Нарушение (бэкап, cp без -p, umask 022) = RegistryError. На Windows не проверяется.
        """
        if os.name == "nt":
            return
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(st.st_mode):
            raise RegistryError("clients.json is not a regular file")
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise RegistryError("clients.json must not be accessible to group/others (chmod 600)")
        if st.st_uid != os.geteuid():  # type: ignore[attr-defined,unused-ignore]
            raise RegistryError("clients.json must be owned by the user running gatekeeper")

    def _save(self, clients: dict[str, dict]) -> None:
        stored = {cid: self._with_secret(cid, entry, self._key) if isinstance(entry, dict) else entry
                  for cid, entry in clients.items()}
        data = json.dumps({"version": 1, "clients": stored}, indent=2, sort_keys=True)
        atomic_write_private(self.path, data.encode("utf-8"))

    def rekey(self, key: bytes | None) -> None:
        """Переписать реестр под новый ключ: key=None — хранить открытым текстом (B2)."""
        with self._locked():
            clients = self.load()
            self._key = key
            self._save(clients)

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
                with suppress(OSError):
                    _unlock(fd)
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

    def set_status(self, client_id: str, status: str, *, decrypt: bool = True) -> None:
        """Меняет статус по таблице переходов (revoked необратим).

        `decrypt=False` — для работы с шифрованным реестром без ключа: шифротекст
        сохраняется без изменений.
        """
        if status not in STATUSES:
            raise RegistryError("invalid status")
        with self._locked():
            clients = self.load(decrypt=decrypt)
            if client_id not in clients:
                raise RegistryError("unknown client")
            current = clients[client_id].get("status")
            if current is None or status not in _TRANSITIONS.get(current, ()):
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
