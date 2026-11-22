"""C-13: лимит соединений считает IPv6 сетью /64, а не отдельными адресами."""
from gatekeeper.server.limits import ConnectionLimiter, normalize_ip


def test_ipv4_is_counted_per_address():
    assert normalize_ip("203.0.113.7") == "203.0.113.7"


def test_ipv6_is_counted_per_64():
    assert normalize_ip("2001:db8:1:2::1") == normalize_ip("2001:db8:1:2::ffff")
    assert normalize_ip("2001:db8:1:2::1") == "2001:db8:1:2::/64"
    assert normalize_ip("2001:db8:1:3::1") != normalize_ip("2001:db8:1:2::1")


def test_unknown_peer_is_not_normalized():
    assert normalize_ip("unknown") == "unknown"


def test_addresses_of_one_ipv6_network_share_the_per_ip_limit():
    limiter = ConnectionLimiter(max_total=100, max_per_ip=2)
    assert limiter.try_acquire(normalize_ip("2001:db8:1:2::1"))
    assert limiter.try_acquire(normalize_ip("2001:db8:1:2::2"))
    assert not limiter.try_acquire(normalize_ip("2001:db8:1:2::3"))
    limiter.release(normalize_ip("2001:db8:1:2::1"))
    assert limiter.try_acquire(normalize_ip("2001:db8:1:2::4"))
    assert limiter.total == 2


def test_max_total_is_exposed():
    assert ConnectionLimiter(max_total=7, max_per_ip=3).max_total == 7
