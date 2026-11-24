"""IPv4-mapped IPv6 не должен обходить лимиты и баны: ключ источника один и тот же."""
from gatekeeper.server.limits import ConnectionLimiter, IpBanList, RateLimiter, normalize_ip

V4, MAPPED = "1.2.3.4", "::ffff:1.2.3.4"


def test_mapped_ipv4_is_plain_ipv4():
    assert normalize_ip(MAPPED) == V4
    assert normalize_ip("::FFFF:1.2.3.4") == V4
    assert normalize_ip("0:0:0:0:0:ffff:0102:0304") == V4


def test_ipv6_grouping_and_garbage_are_unchanged():
    assert normalize_ip("2001:db8:1:2::1") == "2001:db8:1:2::/64"
    assert normalize_ip("2001:db8:1:3::1") != normalize_ip("2001:db8:1:2::1")
    assert normalize_ip("unknown") == "unknown"
    assert normalize_ip("") == ""
    # scope-id: разбор не должен падать (сеть /64 или ключ как есть — по версии Python)
    assert normalize_ip("fe80::1%eth0") in {"fe80::/64", "fe80::1%eth0"}


def test_connection_slot_is_shared():
    lim = ConnectionLimiter(max_total=10, max_per_ip=1)
    assert lim.try_acquire(normalize_ip(V4))
    assert not lim.try_acquire(normalize_ip(MAPPED))
    lim.release(normalize_ip(MAPPED))
    assert lim.try_acquire(normalize_ip(V4))


def test_ban_is_shared_both_ways():
    t = [1000]
    bans = IpBanList(lambda: t[0])
    bans.ban(V4, 60)
    assert bans.is_banned(MAPPED)
    other = IpBanList(lambda: t[0])
    other.ban(MAPPED, 60)
    assert other.is_banned(V4)
    t[0] += 61
    assert not bans.is_banned(MAPPED)


def test_zone_is_not_part_of_the_key():
    assert normalize_ip("fe80::1%eth0") == normalize_ip("fe80::1%wlan0") == "fe80::/64"
    assert normalize_ip("::ffff:1.2.3.4%eth0") == V4


def test_legacy_ban_keys_are_migrated_on_start(tmp_path):
    """Баны из state.db под старым ключом (`::ffff:…`, зона) должны снова срабатывать."""
    from gatekeeper.server.state import StateStore

    store = StateStore(tmp_path / "state.db")
    now = 1_000_000
    store.set_ban("::ffff:1.2.3.4", now + 600)
    store.set_ban("fe80::1%eth0", now + 600)
    try:
        bans = IpBanList(lambda: now, store=store)
        assert bans.is_banned("1.2.3.4")
        assert bans.is_banned("fe80::abcd")
        assert set(store.load_bans(now)) == {"1.2.3.4", "fe80::/64"}
    finally:
        store.close()


def test_rate_limiter_key_is_shared():
    rl = RateLimiter(1.0, 1, clock=lambda: 0.0)
    assert rl.allow(normalize_ip(V4))
    assert not rl.allow(normalize_ip(MAPPED))
