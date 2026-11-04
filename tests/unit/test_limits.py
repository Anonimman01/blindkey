"""Тесты лимитов: бан по IP, соединения, частота, суточный бюджет."""
import pytest

from gatekeeper.server.limits import ConnectionLimiter, DailyBudget, IpBanList, RateLimiter


class Clock:
    def __init__(self, t=1_000_000):
        self.t = t

    def __call__(self):
        return self.t


def test_ban_and_expiry():
    clk = Clock()
    b = IpBanList(clock=clk)
    assert not b.is_banned("1.2.3.4")
    b.ban("1.2.3.4", 60)
    assert b.is_banned("1.2.3.4")
    assert not b.is_banned("1.2.3.5")
    clk.t += 60
    assert not b.is_banned("1.2.3.4")


def test_ban_never_shortened():
    clk = Clock()
    b = IpBanList(clock=clk)
    b.ban("ip", 100)
    b.ban("ip", 10)
    clk.t += 50
    assert b.is_banned("ip")


def test_ban_nonpositive_ignored():
    b = IpBanList(clock=Clock())
    b.ban("ip", 0)
    assert not b.is_banned("ip")


def test_connection_limits_per_ip_and_total():
    cl = ConnectionLimiter(max_total=3, max_per_ip=2)
    assert cl.try_acquire("a") and cl.try_acquire("a")
    assert cl.try_acquire("a") is False          # лимит с одного IP
    assert cl.try_acquire("b")
    assert cl.try_acquire("c") is False          # общий лимит
    assert cl.total == 3
    cl.release("a")
    assert cl.try_acquire("c")


def test_connection_release_is_safe_when_unknown():
    cl = ConnectionLimiter(2, 2)
    cl.release("nobody")
    assert cl.total == 0


def test_connection_denied_does_not_leak_state():
    cl = ConnectionLimiter(max_total=1, max_per_ip=1)
    assert cl.try_acquire("a")
    assert cl.try_acquire("b") is False
    cl.release("a")
    assert cl.try_acquire("b")


def test_rate_limiter_burst_and_refill():
    t = [0.0]
    rl = RateLimiter(rate_per_sec=1, burst=2, clock=lambda: t[0])
    assert rl.allow("c") and rl.allow("c")
    assert rl.allow("c") is False
    t[0] += 1.0
    assert rl.allow("c") is True
    assert rl.allow("c") is False
    assert rl.allow("other")                      # ключи независимы


def test_rate_limiter_caps_at_burst():
    t = [0.0]
    rl = RateLimiter(rate_per_sec=10, burst=2, clock=lambda: t[0])
    t[0] += 1000
    assert rl.allow("c") and rl.allow("c")
    assert rl.allow("c") is False


def test_daily_budget_and_reset():
    clk = Clock(86400 * 10 + 100)
    b = DailyBudget(limit=2, clock=clk)
    assert b.try_spend("a") and b.try_spend("a")
    assert b.try_spend("a") is False
    assert b.try_spend("b")
    clk.t += 86400
    assert b.try_spend("a") is True
    assert b.used("a") == 1


@pytest.mark.parametrize("make", [
    lambda: ConnectionLimiter(0, 1),
    lambda: ConnectionLimiter(1, 0),
    lambda: RateLimiter(0, 1),
    lambda: RateLimiter(1, 0),
    lambda: DailyBudget(0),
])
def test_bad_params(make):
    with pytest.raises(ValueError):
        make()
