"""Кэш nonce для защиты от повтора (replay).

Окно хранения должно быть не меньше окна допустимого расхождения часов
в обе стороны: запрос с временем в пределах ±skew может прийти повторно
в течение 2*skew секунд. Берём 2*skew + запас.
При переполнении кэша новые nonce отклоняются (fail closed).
"""
from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Callable

from gatekeeper.core import constants
from gatekeeper.core.timeutil import unix_now

DEFAULT_TTL = 2 * constants.MAX_CLOCK_SKEW_SECONDS + 10
DEFAULT_MAX_ENTRIES = 100_000


class NonceCache:
    def __init__(
        self,
        ttl: int = DEFAULT_TTL,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        clock: Callable[[], int] = unix_now,
    ) -> None:
        if ttl <= 0 or max_entries <= 0:
            raise ValueError("ttl and max_entries must be positive")
        self._ttl = ttl
        self._max = max_entries
        self._clock = clock
        self._lock = threading.Lock()
        # (client_id, nonce) -> время истечения; порядок вставки = порядок истечения
        self._items: "OrderedDict[tuple[str, str], int]" = OrderedDict()

    def _purge(self, now: int) -> None:
        while self._items:
            key, exp = next(iter(self._items.items()))
            if exp > now:
                break
            del self._items[key]

    def check_and_add(self, client_id: str, nonce: str) -> bool:
        """True, если nonce новый (и запомнен). False: повтор или кэш полон."""
        now = self._clock()
        key = (client_id, nonce)
        with self._lock:
            self._purge(now)
            if key in self._items:
                return False
            if len(self._items) >= self._max:
                return False
            self._items[key] = now + self._ttl
            return True

    def __len__(self) -> int:
        with self._lock:
            self._purge(self._clock())
            return len(self._items)
