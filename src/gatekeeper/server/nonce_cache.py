"""Кэш nonce для защиты от повтора (replay).

Окно хранения должно быть не меньше окна допустимого расхождения часов
в обе стороны: запрос с временем в пределах ±skew может прийти повторно
в течение 2*skew секунд. Берём 2*skew + запас.
При переполнении кэша новые nonce отклоняются (fail closed). Чтобы один клиент не мог
занять весь кэш и отрезать остальных, на клиента действует свой потолок (max_per_client).
Если передан StateStore, nonce переживают перезапуск шлюза.
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from collections.abc import Callable
from typing import TYPE_CHECKING

from gatekeeper.core import constants
from gatekeeper.core.timeutil import unix_now

if TYPE_CHECKING:
    from gatekeeper.server.state import StateStore

DEFAULT_TTL = 2 * constants.MAX_CLOCK_SKEW_SECONDS + 10
DEFAULT_MAX_ENTRIES = 100_000
DEFAULT_MAX_PER_CLIENT = 20_000
_DB_PURGE_EVERY = 60  # секунд между чистками таблицы в SQLite


class NonceCache:
    def __init__(
        self,
        ttl: int = DEFAULT_TTL,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        clock: Callable[[], int] = unix_now,
        *,
        max_per_client: int = DEFAULT_MAX_PER_CLIENT,
        store: StateStore | None = None,
    ) -> None:
        if ttl <= 0 or max_entries <= 0 or max_per_client <= 0:
            raise ValueError("ttl, max_entries and max_per_client must be positive")
        self._ttl = ttl
        self._max = max_entries
        self._max_client = max_per_client
        self._clock = clock
        self._store = store
        self._lock = threading.Lock()
        # (client_id, nonce) -> время истечения; порядок вставки = порядок истечения
        self._items: OrderedDict[tuple[str, str], int] = OrderedDict()
        self._per_client: dict[str, int] = {}
        self._last_db_purge = clock()
        if store:
            for cid, nonce, exp in store.load_nonces(clock()):
                self._items[(cid, nonce)] = exp
                self._per_client[cid] = self._per_client.get(cid, 0) + 1

    def _purge(self, now: int) -> None:
        while self._items:
            key, exp = next(iter(self._items.items()))
            if exp > now:
                break
            del self._items[key]
            left = self._per_client.get(key[0], 0) - 1
            if left > 0:
                self._per_client[key[0]] = left
            else:
                self._per_client.pop(key[0], None)
        if self._store and now - self._last_db_purge >= _DB_PURGE_EVERY:
            self._last_db_purge = now
            self._store.purge_nonces(now)

    def check_and_add(self, client_id: str, nonce: str) -> bool:
        """True, если nonce новый (и запомнен). False: повтор или переполнение."""
        now = self._clock()
        key = (client_id, nonce)
        with self._lock:
            self._purge(now)
            if key in self._items:
                return False
            if len(self._items) >= self._max or self._per_client.get(client_id, 0) >= self._max_client:
                return False
            exp = now + self._ttl
            self._items[key] = exp
            self._per_client[client_id] = self._per_client.get(client_id, 0) + 1
            if self._store:
                self._store.add_nonce(client_id, nonce, exp)
            return True

    def __len__(self) -> int:
        with self._lock:
            self._purge(self._clock())
            return len(self._items)
