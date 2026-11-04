"""Тесты кэша nonce: повтор, TTL, раздельность клиентов, переполнение."""
import pytest

from gatekeeper.server.nonce_cache import NonceCache


class Clock:
    def __init__(self, t=1000):
        self.t = t

    def __call__(self):
        return self.t


def test_first_ok_replay_denied():
    c = NonceCache(clock=Clock())
    assert c.check_and_add("a", "n" * 16) is True
    assert c.check_and_add("a", "n" * 16) is False


def test_same_nonce_different_clients_independent():
    c = NonceCache(clock=Clock())
    assert c.check_and_add("a", "n" * 16)
    assert c.check_and_add("b", "n" * 16)


def test_expiry_allows_reuse_after_ttl():
    clk = Clock()
    c = NonceCache(ttl=70, clock=clk)
    assert c.check_and_add("a", "x" * 16)
    clk.t += 69
    assert c.check_and_add("a", "x" * 16) is False
    clk.t += 1
    assert c.check_and_add("a", "x" * 16) is True


def test_default_ttl_covers_double_skew():
    from gatekeeper.core.constants import MAX_CLOCK_SKEW_SECONDS
    from gatekeeper.server.nonce_cache import DEFAULT_TTL

    assert DEFAULT_TTL >= 2 * MAX_CLOCK_SKEW_SECONDS


def test_full_cache_fails_closed():
    clk = Clock()
    c = NonceCache(ttl=60, max_entries=2, clock=clk)
    assert c.check_and_add("a", "1" * 16)
    assert c.check_and_add("a", "2" * 16)
    assert c.check_and_add("a", "3" * 16) is False
    clk.t += 60
    assert c.check_and_add("a", "3" * 16) is True
    assert len(c) == 1


def test_bad_params():
    with pytest.raises(ValueError):
        NonceCache(ttl=0)
    with pytest.raises(ValueError):
        NonceCache(max_entries=0)
