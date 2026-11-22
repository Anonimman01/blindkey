"""Постоянное состояние шлюза в SQLite (stdlib): nonce, суточный бюджет, баны, аномалии.

Зачем: без этого перезапуск (`systemctl restart`, падение) открывал окно повтора запросов,
обнулял суточную квоту и забывал счётчики автозаморозки.

Режим WAL + synchronous=NORMAL: транзакция переживает падение процесса и перезапуск службы,
но не обязана переживать внезапную потерю питания (последние транзакции могут пропасть).
Для nonce с окном в десятки секунд и для квоты это приемлемо; журнал аудита по-прежнему
пишется с fsync. Любая ошибка БД пробрасывается наверх, и конвейер отвечает отказом (fail closed).
"""
from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

_BINARY = getattr(os, "O_BINARY", 0)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS nonces(
    client TEXT NOT NULL, nonce TEXT NOT NULL, exp INTEGER NOT NULL,
    PRIMARY KEY(client, nonce)) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS nonces_exp ON nonces(exp);
CREATE TABLE IF NOT EXISTS budget(
    client TEXT PRIMARY KEY, day INTEGER NOT NULL, used INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS bans(ip TEXT PRIMARY KEY, until INTEGER NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hits(client TEXT NOT NULL, ts INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS hits_client ON hits(client, ts);
"""


class StateStore:
    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        # Создаём файл сами, чтобы права были 0600 (sqlite иначе берёт umask).
        os.close(os.open(self.path, os.O_RDWR | os.O_CREAT | _BINARY, 0o600))
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _exec(self, sql: str, args: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            return self._db.execute(sql, args)

    def _all(self, sql: str, args: tuple = ()) -> list[tuple]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    # --- nonce ---
    def load_nonces(self, now: int) -> list[tuple[str, str, int]]:
        return self._all("SELECT client, nonce, exp FROM nonces WHERE exp > ? ORDER BY exp", (now,))

    def add_nonce(self, client: str, nonce: str, exp: int) -> None:
        self._exec("INSERT OR REPLACE INTO nonces VALUES (?,?,?)", (client, nonce, exp))

    def purge_nonces(self, now: int) -> None:
        self._exec("DELETE FROM nonces WHERE exp <= ?", (now,))

    # --- бюджет ---
    def load_budget(self, day: int) -> dict[str, int]:
        return dict(self._all("SELECT client, used FROM budget WHERE day = ?", (day,)))

    def set_budget(self, client: str, day: int, used: int) -> None:
        self._exec("INSERT OR REPLACE INTO budget VALUES (?,?,?)", (client, day, used))

    def purge_budget(self, day: int) -> None:
        self._exec("DELETE FROM budget WHERE day < ?", (day,))

    # --- баны по IP ---
    def load_bans(self, now: int) -> dict[str, int]:
        return dict(self._all("SELECT ip, until FROM bans WHERE until > ?", (now,)))

    def set_ban(self, ip: str, until: int) -> None:
        self._exec("INSERT OR REPLACE INTO bans VALUES (?,?)", (ip, until))

    def del_ban(self, ip: str) -> None:
        self._exec("DELETE FROM bans WHERE ip = ?", (ip,))

    # --- аномалии (автозаморозка) ---
    def load_hits(self, since: int) -> list[tuple[str, int]]:
        return self._all("SELECT client, ts FROM hits WHERE ts > ? ORDER BY ts", (since,))

    def add_hit(self, client: str, ts: int, prune_before: int) -> None:
        with self._lock:
            self._db.execute("INSERT INTO hits VALUES (?,?)", (client, ts))
            self._db.execute("DELETE FROM hits WHERE client = ? AND ts <= ?", (client, prune_before))

    def clear_hits(self, client: str) -> None:
        self._exec("DELETE FROM hits WHERE client = ?", (client,))
