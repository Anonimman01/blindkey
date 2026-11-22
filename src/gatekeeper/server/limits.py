"""Лимиты: соединения, бан по IP, частота запросов, суточный бюджет.

Всё без сети, время передаётся через clock (для тестов). Потокобезопасно.
Состояние живёт в памяти; если передан StateStore, баны и суточный бюджет ещё и пишутся
в SQLite и подхватываются после перезапуска. Словари с ключом «IP» ограничены по размеру.
"""
from __future__ import annotations

import ipaddress
import math
import threading
from collections import OrderedDict, defaultdict
from collections.abc import Callable
from typing import TYPE_CHECKING

from gatekeeper.core.timeutil import unix_now

if TYPE_CHECKING:
    from gatekeeper.server.state import StateStore

DEFAULT_MAX_KEYS = 10_000


def normalize_ip(ip: str) -> str:
    """Ключ для лимитов соединений: IPv4 — как есть, IPv6 — сеть /64 (C-13).

    Клиенту обычно выдаётся целая /64, поэтому адреса из одной сети не должны
    занимать все слоты `max_per_ip` по отдельности.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ip
    if addr.version == 6:
        return str(ipaddress.ip_network(f"{addr}/64", strict=False))
    return str(addr)


class IpBanList:
    def __init__(self, clock: Callable[[], int] = unix_now, *,
                 store: StateStore | None = None, max_entries: int = DEFAULT_MAX_KEYS) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._store = store
        self._max = max_entries
        self._until: dict[str, int] = store.load_bans(clock()) if store else {}

    def ban(self, ip: str, seconds: int) -> None:
        if seconds <= 0:
            return
        now = self._clock()
        until = now + seconds
        with self._lock:
            if self._until.get(ip, 0) >= until:
                return
            if ip not in self._until and len(self._until) >= self._max:
                self._make_room(now)
            self._until[ip] = until
            if self._store:
                self._store.set_ban(ip, until)

    def _make_room(self, now: int) -> None:
        """Под замком: выкинуть истёкшие баны, а если мало, то ближайший к истечению."""
        for ip in [k for k, u in self._until.items() if u <= now]:
            del self._until[ip]
        if len(self._until) >= self._max:
            oldest = min(self._until, key=self._until.__getitem__)
            del self._until[oldest]
            if self._store:
                self._store.del_ban(oldest)

    def is_banned(self, ip: str) -> bool:
        now = self._clock()
        with self._lock:
            until = self._until.get(ip)
            if until is None:
                return False
            if until <= now:
                del self._until[ip]
                if self._store:
                    self._store.del_ban(ip)
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

    @property
    def max_total(self) -> int:
        return self._max_total


class RateLimiter:
    """Токен-бакет на ключ (client_id или IP): rate токенов/с, ёмкость burst.

    Число ключей ограничено (LRU): злоумышленник, перебирающий IP, не раздует память.
    Вытеснение безопасно: ключ без записи начинает с полным бакетом, как новый.
    """

    def __init__(
        self,
        rate_per_sec: float,
        burst: int,
        clock: Callable[[], float] | None = None,
        max_keys: int = DEFAULT_MAX_KEYS,
    ) -> None:
        if not math.isfinite(rate_per_sec) or not math.isfinite(burst):
            raise ValueError("rate and burst must be finite")
        if rate_per_sec <= 0 or burst <= 0 or max_keys <= 0:
            raise ValueError("rate, burst and max_keys must be positive")
        import time

        self._rate = float(rate_per_sec)
        self._burst = float(burst)
        self._clock = clock or time.monotonic
        self._max_keys = max_keys
        self._lock = threading.Lock()
        self._state: OrderedDict[str, tuple[float, float]] = OrderedDict()  # key -> (tokens, last)

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = self._clock()
        with self._lock:
            tokens, last = self._state.get(key, (self._burst, now))
            tokens = min(self._burst, tokens + max(0.0, now - last) * self._rate)
            ok = tokens >= cost
            self._state[key] = (tokens - cost if ok else tokens, now)
            self._state.move_to_end(key)
            while len(self._state) > self._max_keys:
                self._state.popitem(last=False)
            return ok

    def retry_after(self, key: str, cost: float = 1.0) -> int:
        """Через сколько секунд (целых, >= 1) в бакете снова будет хватать токенов."""
        now = self._clock()
        with self._lock:
            tokens, last = self._state.get(key, (self._burst, now))
            tokens = min(self._burst, tokens + max(0.0, now - last) * self._rate)
        return max(1, math.ceil(max(0.0, cost - tokens) / self._rate))

    def __len__(self) -> int:
        with self._lock:
            return len(self._state)


class DailyBudget:
    """Суточная квота запросов на клиента (сутки по UTC)."""

    def __init__(self, limit: int, clock: Callable[[], int] = unix_now, *,
                 store: StateStore | None = None) -> None:
        if limit <= 0:
            raise ValueError("limit must be positive")
        self._limit = limit
        self._clock = clock
        self._store = store
        self._lock = threading.Lock()
        self._day = self._clock() // 86400
        self._used: dict[str, int] = defaultdict(int)
        if store:
            self._used.update(store.load_budget(self._day))
            store.purge_budget(self._day)

    def try_spend(self, client_id: str, amount: int = 1) -> bool:
        day = self._clock() // 86400
        with self._lock:
            if day != self._day:
                self._day = day
                self._used.clear()
                if self._store:
                    self._store.purge_budget(day)
            if self._used[client_id] + amount > self._limit:
                return False
            self._used[client_id] += amount
            if self._store:
                self._store.set_budget(client_id, day, self._used[client_id])
            return True

    def used(self, client_id: str) -> int:
        with self._lock:
            return self._used.get(client_id, 0)

    def can_spend(self, client_id: str, amount: int = 1) -> bool:
        """Проверить квоту, ничего не тратя (чтобы отказ не «съедал» подтверждение)."""
        day = self._clock() // 86400
        with self._lock:
            used = self._used.get(client_id, 0) if day == self._day else 0
            return used + amount <= self._limit

    def seconds_until_reset(self) -> int:
        """Секунд до начала следующих суток по UTC (для Retry-After)."""
        return max(1, 86400 - self._clock() % 86400)
