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


# ---- A6: заполненность и предупреждение при 80% ----

def test_fill_ratios_are_reported():
    cache = NonceCache(ttl=100, max_entries=10, max_per_client=4, clock=lambda: 1000)
    assert cache.fill() == 0.0 and cache.client_fill("a") == 0.0
    assert cache.check_and_add("a", "n1") and cache.check_and_add("a", "n2")
    assert cache.fill() == 0.2 and cache.client_fill("a") == 0.5
    assert cache.fills() == {"a": 0.5}
    assert cache.capacity == 10 and cache.client_capacity == 4


def test_fill_ratio_never_exceeds_one_when_full(tmp_path):
    from test_pipeline import audit_text, call, make_env, make_req

    from gatekeeper.server.nonce_cache import NonceCache as Cache

    env = make_env(tmp_path)
    env.p.nonces = Cache(max_entries=2, max_per_client=100)
    call(env, make_req(env.fp))
    call(env, make_req(env.fp))
    log = audit_text(env)
    assert "nonce_cache_high_water" in log
    assert '"scope":"global"' in log.replace(" ", "")
    assert '"fill":1.0' in log.replace(" ", "")


def test_client_scope_high_water_event(tmp_path):
    from test_pipeline import audit_text, call, make_env, make_req

    from gatekeeper.server.nonce_cache import NonceCache as Cache

    env = make_env(tmp_path, burst=10, budget=10)
    env.p.nonces = Cache(max_entries=1000, max_per_client=2)
    call(env, make_req(env.fp))
    call(env, make_req(env.fp))            # 2/2 на клиента = 100%
    log = audit_text(env)
    assert '"scope":"client"' in log.replace(" ", "")


def test_high_water_event_is_rate_limited(tmp_path):
    """Лимит частоты: заполненный кэш не заливает журнал событием на каждый запрос."""
    from test_pipeline import audit_text, call, make_env, make_req

    from gatekeeper.server.nonce_cache import NonceCache as Cache

    env = make_env(tmp_path, burst=50, budget=50)
    env.p.nonces = Cache(max_entries=10, max_per_client=100)
    for _ in range(10):                    # 80%, 90% — события; 100% — подавлено (burst=2)
        call(env, make_req(env.fp))
    assert audit_text(env).count("nonce_cache_high_water") == 2


def test_client_fill_gauge_has_a_client_label():
    from gatekeeper.server.observe import Metrics

    m = Metrics()
    m.gauge("gk_nonce_cache_client_fill_ratio", 0.375, client="alice")
    assert 'gk_nonce_cache_client_fill_ratio{client="alice"} 0.375' in m.render()
