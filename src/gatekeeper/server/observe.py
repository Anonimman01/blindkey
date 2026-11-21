"""Наблюдаемость: request-id, счётчики для /metrics, метки в ответах.

request-id не раскрывает причину отказа: он случайный и одинаково выглядит для любого ответа,
зато связывает ответ клиента с записью в журнале (поле rid).
"""
from __future__ import annotations

import os
import threading
import time
from contextvars import ContextVar

request_id: ContextVar[str | None] = ContextVar("gk_request_id", default=None)


def new_request_id() -> str:
    return os.urandom(8).hex()


def stamp(resp: bytes, rid: str) -> bytes:
    """Вставить X-Request-Id сразу после строки статуса готового ответа."""
    head, sep, rest = resp.partition(b"\r\n")
    if not sep:
        return resp
    return head + b"\r\n" + b"X-Request-Id: " + rid.encode("ascii") + b"\r\n" + rest


def _esc(value: object) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


class Metrics:
    """Простые счётчики с метками, вывод в формате Prometheus (text exposition)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[tuple[str, tuple[tuple[str, str], ...]], float] = {}
        self._started = time.monotonic()

    def inc(self, name: str, value: float = 1.0, **labels: object) -> None:
        key = (name, tuple(sorted((k, str(v)) for k, v in labels.items())))
        with self._lock:
            self._counters[key] = self._counters.get(key, 0.0) + value

    def render(self, gauges: dict[str, float] | None = None) -> str:
        with self._lock:
            items = sorted(self._counters.items())
        lines = []
        for (name, labels), val in items:
            lab = ",".join(f'{k}="{_esc(v)}"' for k, v in labels)
            lines.append(f"{name}{{{lab}}} {val:g}" if lab else f"{name} {val:g}")
        merged = {"gk_uptime_seconds": time.monotonic() - self._started, **(gauges or {})}
        for name, val in sorted(merged.items()):
            lines.append(f"{name} {val:g}")
        return "\n".join(lines) + "\n"
