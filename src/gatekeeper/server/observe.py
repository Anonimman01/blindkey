"""Наблюдаемость: request-id, счётчики и гистограммы для /metrics, метки в ответах.

request-id не раскрывает причину отказа: он случайный и одинаково выглядит для любого ответа,
зато связывает ответ клиента с записью в журнале (поле rid).
"""
from __future__ import annotations

import os
import threading
import time
from contextvars import ContextVar

from gatekeeper.core import constants

request_id: ContextVar[str | None] = ContextVar("gk_request_id", default=None)

# Секундные бакеты для gk_request_seconds / gk_upstream_seconds. Без них histogram_quantile()
# не работает, а голая пара _sum/_count гистограммой не является (B-09).
SECONDS_BUCKETS: tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0,
)


def new_request_id() -> str:
    return os.urandom(8).hex()


def stamp(resp: bytes, rid: str) -> bytes:
    """Вставить X-Request-Id сразу после строки статуса готового ответа."""
    head, sep, rest = resp.partition(b"\r\n")
    if not sep:
        return resp
    header = constants.HEADER_REQUEST_ID.encode("ascii")
    return head + b"\r\n" + header + b": " + rid.encode("ascii") + b"\r\n" + rest


def _esc(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def _fmt(value: float) -> str:
    return f"{value:g}"


class Metrics:
    """Счётчики и гистограммы с метками, вывод в формате Prometheus (text exposition)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        # Гейджи с метками (например заполненность кэша на клиента): в отличие от
        # counters они не растут, а перезаписываются при каждом scrape.
        self._gauges: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._started = time.monotonic()

    def inc(self, name: str, value: float = 1.0, **labels: object) -> None:
        key = (name, tuple(sorted((k, str(v)) for k, v in labels.items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + value

    def gauge(self, name: str, value: float, **labels: object) -> None:
        """Установить значение гейджа с метками (0/1/доли, а не счётчик)."""
        key = (name, tuple(sorted((k, str(v)) for k, v in labels.items())))
        with self._lock:
            self._gauges[key] = float(value)

    def observe(self, name: str, value: float, buckets: tuple[float, ...] = SECONDS_BUCKETS,
                **labels: object) -> None:
        """Учесть наблюдение в гистограмме: name_bucket{le=...}, name_sum, name_count."""
        if value < 0:
            value = 0.0
        base = tuple(sorted((k, str(v)) for k, v in labels.items()))
        with self._lock:
            for bound in (*buckets, float("inf")):
                if value <= bound:
                    key = (f"{name}_bucket", (*base, ("le", "+Inf" if bound == float("inf")
                                                      else _fmt(bound))))
                    self._counters[key] = self._counters.get(key, 0.0) + 1.0
            sum_key = (f"{name}_sum", base)
            count_key = (f"{name}_count", base)
            self._counters[sum_key] = self._counters.get(sum_key, 0.0) + value
            self._counters[count_key] = self._counters.get(count_key, 0.0) + 1.0

    def render(self, gauges: dict[str, float] | None = None) -> str:
        with self._lock:
            items = sorted(self._counters.items())
            labeled = sorted(self._gauges.items())
        lines = []
        for (name, labels), val in items + labeled:
            lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels)
            lines.append(f"{name}{{{lab}}} {val:g}" if lab else f"{name} {val:g}")
        merged = {"gk_uptime_seconds": time.monotonic() - self._started, **(gauges or {})}
        for name, val in sorted(merged.items()):
            lines.append(f"{name} {val:g}")
        return "\n".join(lines) + "\n"

