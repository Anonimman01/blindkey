"""Состояние переживает перезапуск: nonce, бюджет, баны, аномалии; лимиты ограничены."""
import os

import pytest

from gatekeeper.core.events import EventType
from gatekeeper.server.anomaly import AnomalyMonitor
from gatekeeper.server.limits import DailyBudget, IpBanList, RateLimiter
from gatekeeper.server.nonce_cache import NonceCache
from gatekeeper.server.state import StateStore


@pytest.fixture
def db(tmp_path):
    return tmp_path / "state.db"


@pytest.fixture
def store(db):
    """StateStore с закрытием в teardown: иначе соединение sqlite течёт (ResourceWarning)."""
    opened = []

    def make():
        s = StateStore(db)
        opened.append(s)
        return s

    yield make
    for s in opened:
        s.close()


def test_nonce_survives_restart(store):
    t = [1000]
    s1 = store()
    assert NonceCache(ttl=100, clock=lambda: t[0], store=s1).check_and_add("a", "n1")
    s1.close()
    cache = NonceCache(ttl=100, clock=lambda: t[0], store=store())
    assert not cache.check_and_add("a", "n1")  # повтор после рестарта отклонён
    t[0] += 101
    assert cache.check_and_add("a", "n1")  # после истечения окна снова можно


def test_budget_survives_restart_and_resets_next_day(store):
    t = [86400 * 10 + 5]
    b1 = DailyBudget(2, clock=lambda: t[0], store=store())
    assert b1.try_spend("a") and b1.try_spend("a")
    b2 = DailyBudget(2, clock=lambda: t[0], store=store())  # «systemctl restart»
    assert not b2.try_spend("a")
    t[0] += 86400
    assert b2.try_spend("a")


def test_bans_survive_restart_and_expire(store):
    t = [1000]
    IpBanList(lambda: t[0], store=store()).ban("1.2.3.4", 60)
    bans = IpBanList(lambda: t[0], store=store())
    assert bans.is_banned("1.2.3.4")
    t[0] += 61
    assert not bans.is_banned("1.2.3.4")
    assert not IpBanList(lambda: t[0], store=store()).is_banned("1.2.3.4")


def test_anomaly_window_survives_restart(store):
    t = [1000]
    m1 = AnomalyMonitor(3, 60, lambda: t[0], store=store())
    assert m1.record("a", EventType.DENY_REPLAY) is None
    assert m1.record("a", EventType.DENY_REPLAY) is None
    m2 = AnomalyMonitor(3, 60, lambda: t[0], store=store())
    assert m2.record("a", EventType.DENY_REPLAY) == 3  # порог достигнут с учётом прошлого


def test_state_file_is_private(db, store):
    store()
    if os.name != "nt":
        assert (db.stat().st_mode & 0o777) == 0o600


def test_one_client_cannot_fill_nonce_cache():
    cache = NonceCache(max_entries=10, max_per_client=3)
    assert all(cache.check_and_add("noisy", f"n{i}") for i in range(3))
    assert not cache.check_and_add("noisy", "n3")
    assert cache.check_and_add("quiet", "n0")  # остальные клиенты не отрезаны


def test_rate_limiter_keys_are_bounded():
    rl = RateLimiter(1.0, 1, clock=lambda: 0.0, max_keys=100)
    for i in range(1000):
        rl.allow(f"ip{i}")
    assert len(rl) == 100


def test_ban_list_is_bounded():
    bans = IpBanList(lambda: 1000, max_entries=5)
    for i in range(50):
        bans.ban(f"10.0.0.{i}", 60 + i)
    assert len(bans._until) <= 5
    assert bans.is_banned("10.0.0.49")  # остаются самые поздние


def test_retry_after_values():
    t = [0.0]
    rl = RateLimiter(0.5, 1, clock=lambda: t[0])
    assert rl.allow("a") and not rl.allow("a")
    assert rl.retry_after("a") == 2
    t[0] = 1.0
    assert rl.retry_after("a") == 1
    b = DailyBudget(1, clock=lambda: 86400 * 3 + 86300)
    assert b.seconds_until_reset() == 100
