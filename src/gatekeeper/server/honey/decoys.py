"""Приманочные клиенты: настоящие по виду сертификаты, выпущенные нашим CA, но
не внесённые в реестр клиентов. Их кладут туда, где вор будет искать секреты
(старый каталог, репозиторий, бэкап). Любой запрос с таким сертификатом это
тревога и бан источника (см. pipeline: проверка идёт до идентификации).

Файл decoys.json: {"version":1,"decoys":{"<имя>":{"fingerprint":"<hex64>","created":T,"hint":"..."}}}
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from gatekeeper.core.errors import GatekeeperError

_BINARY = getattr(os, "O_BINARY", 0)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class DecoyError(GatekeeperError):
    """Ошибка хранилища приманок."""


class DecoyStore:
    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self._sig: object = "unset"
        self._fps: frozenset[str] = frozenset()
        self._reload(strict=True)  # битый файл при старте = ошибка запуска

    def _read(self) -> dict[str, dict]:
        try:
            raw = self.path.read_text("utf-8")
        except FileNotFoundError:
            return {}
        try:
            doc = json.loads(raw)
            decoys = doc["decoys"]
            if doc.get("version") != 1 or not isinstance(decoys, dict):
                raise ValueError
            for e in decoys.values():
                if not _HEX64.match(e["fingerprint"]):
                    raise ValueError
        except (ValueError, KeyError, TypeError) as exc:
            raise DecoyError("decoys.json is malformed") from exc
        return decoys

    def _reload(self, strict: bool = False) -> None:
        try:
            st = os.stat(self.path)
            sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        except FileNotFoundError:
            sig = None
        if sig == self._sig:
            return
        try:
            self._fps = frozenset(e["fingerprint"] for e in self._read().values())
        except DecoyError:
            if strict:
                raise  # после старта оставляем прежний набор приманок
        self._sig = sig

    def is_decoy(self, fingerprint: str) -> bool:
        self._reload()
        return fingerprint in self._fps

    def add(self, name: str, fingerprint: str, created: int, hint: str = "") -> None:
        if not _HEX64.match(fingerprint):
            raise DecoyError("invalid fingerprint")
        decoys = self._read()
        if name in decoys:
            raise DecoyError(f"decoy already exists: {name}")
        decoys[name] = {"fingerprint": fingerprint, "created": created, "hint": hint}
        data = json.dumps({"version": 1, "decoys": decoys}, indent=2, sort_keys=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _BINARY, 0o600)
        try:
            os.write(fd, data.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, self.path)
        self._reload()