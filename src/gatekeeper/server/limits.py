"""Лимиты: соединения, бан по IP, частота запросов, суточный бюджет.

Всё без сети, время передаётся через clock (для тестов). Потокобезопасно.
Состояние в памяти: после перезапуска шлюза сбрасывается (честное
ограничение MVP).
"""
from __future__ import annotations

import threading
from collections import defaultdict
from typing import Callable

from gatekeeper.core.timeutil import unix_now


class IpBanList:
    def __init__(self, clock: Callable[[], int] = unix_now) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._until: dict[str, int] = {}

    def ban(self, ip: str, seconds: int) -> None:
        if seconds <= 0:
            return
        until = self._clock() + seconds
        with self._lock:
            if self._until.get(ip, 0) < until:
                self._until[ip] = until

    def is_banned(self, ip: str) -> bool:
        now = self._clock()
        with self._lock:
            until = self._until.get(ip)
            if until is None:
                return False
            if until <= now:
                del self._until[ip]
                return False
            return True


class ConnectionLimiter:
    """Ограничение числа одновременных соединений: общее и с одного IP."""

    def __init__(self, max_total: int = 100, max_per_ip: int = 10) -> None:
        if max_total <= 0 or max_per_ip <= 0:
            raise ValueError("limits must be positive")
        self._max_total = max_total
        self._max_per_ip = max_per_ip
        self._lock = threading.Lock()
        self._total = 0
        self._per_ip: dict[str, int] = defaultdict(int)

    def try_acquire(self, ip: str) -> bool:
        with self._lock:
            if self._total >= self._max_total or self._per_ip.get(ip, 0) >= self._max_per_ip:
                return False
            self._total += 1
            self._per_ip[ip] += 1
            return True

    def release(self, ip: str) -> None:
        with self._lock:
            if self._per_ip.get(ip, 0) > 0:
                self._per_ip[ip] -= 1
                if self._per_ip[ip] == 0:
                    del self._per_ip[ip]
                if self._total > 0:
                    self._total -= 1

    @property
    def total(self) -> int:
        with self._lock:
            return self._total


class RateLimiter:
    """Токен-бакет на ключ (client_id или IP): rate токенов/с, ёмкость burst."""

    def __init__(
        self,
        rate_per_sec: float,
        burst: int,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if rate_per_sec <= 0 or burst <= 0:
            raise ValueError("rate and burst must be positive")
        import time

        self._rate = float(rate_per_sec)
        self._burst = float(burst)
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._state: dict[str, tuple[float, float]] = {}  # key -> (tokens, last)

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = self._clock()
        with self._lock:
            tokens, last = self._state.get(key, (self._burst, now))
            tokens = min(self._burst, tokens + max(0.0, now - last) * self._rate)
            if tokens < cost:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - cost, now)
            return True


class DailyBudget:
    """Суточная квота запросов на клиента (сутки по UTC)."""

    def __init__(self, limit: int, clock: Callable[[], int] = unix_now) -> None:
        if limit <= 0:
            raise ValueError("limit must be positive")
        self._limit = limit
        self._clock = clock
        self._lock = threading.Lock()
        self._day = self._clock() // 86400
        self._used: dict[str, int] = defaultdict(int)

    def try_spend(self, client_id: str, amount: int = 1) -> bool:
        day = self._clock() // 86400
        with self._lock:
            if day != self._day:
                self._day = day
                self._used.clear()
            if self._used[client_id] + amount > self._limit:
                return False
            self._used[client_id] += amount
            return True

    def used(self, client_id: str) -> int:
        with self._lock:
            return self._used.get(client_id, 0)
