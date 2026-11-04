"""Работа со временем для проверки свежести запроса."""
from __future__ import annotations

import time

from gatekeeper.core import constants


def unix_now() -> int:
    return int(time.time())


def is_fresh(
    timestamp: int,
    now: int | None = None,
    skew: int = constants.MAX_CLOCK_SKEW_SECONDS,
) -> bool:
    """True, если timestamp не дальше skew секунд от now (в обе стороны)."""
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        return False
    if now is None:
        now = unix_now()
    return abs(now - timestamp) <= skew
