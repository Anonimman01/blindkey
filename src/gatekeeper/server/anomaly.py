"""Автозаморозка клиента по аномалиям.

Считаются только отказы, которые уже привязаны к клиенту с действующим сертификатом
(неверная подпись, повтор, нарушение политики). Чужак без сертификата их вызвать не
может, поэтому через этот механизм нельзя заморозить чужого клиента. Квоты (rate,
budget) и расхождение часов (stale_time) не считаются: это ошибки настройки, а не атака.
decoy_triggered сюда не входит: у приманки нет клиента, её уже обрабатывает бан по IP.

Состояние в памяти: после перезапуска шлюза счётчики сбрасываются.
"""
from __future__ import annotations

import threading
from collections import defaultdict, deque
from typing import Callable

from gatekeeper.core.events import EventType
from gatekeeper.core.timeutil import unix_now

COUNTED_EVENTS = frozenset({
    EventType.DENY_BAD_SIGNATURE, EventType.DENY_REPLAY, EventType.DENY_POLICY,
})


class AnomalyMonitor:
    """Скользящее окно по клиенту: threshold событий за window секунд = сработало.

    threshold == 0 отключает механизм.
    """

    def __init__(self, threshold: int = 0, window: int = 60,
                 clock: Callable[[], int] = unix_now) -> None:
        if threshold < 0 or window <= 0:
            raise ValueError("threshold must be >= 0 and window > 0")
        self.threshold, self.window, self._clock = threshold, window, clock
        self._lock = threading.Lock()
        self._hits: dict[str, deque[int]] = defaultdict(deque)

    @property
    def enabled(self) -> bool:
        return self.threshold > 0

    def record(self, client_id: str, etype: object) -> int | None:
        """Учитывает событие. Возвращает число событий в окне, если порог достигнут
        (окно клиента при этом сбрасывается), иначе None."""
        if not self.enabled or etype not in COUNTED_EVENTS:
            return None
        now = self._clock()
        with self._lock:
            q = self._hits[client_id]
            q.append(now)
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.threshold:
                n = len(q)
                del self._hits[client_id]
                return n
            return None
