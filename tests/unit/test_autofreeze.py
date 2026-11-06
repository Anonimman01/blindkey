"""Автозаморозка по аномалиям: AnomalyMonitor, конвейер, конфиг."""
import json

import pytest

from gatekeeper.core.events import EventType
from gatekeeper.server.anomaly import AnomalyMonitor
from gatekeeper.server.config import ConfigError, load_config
from gatekeeper.store.registry import Registry

from test_pipeline import audit_text, call, make_env, make_req


class Clock:
    def __init__(self):
        self.t = 1_000_000

    def __call__(self):
        return self.t


# ---- AnomalyMonitor ----

def test_monitor_disabled_by_default():
    m = AnomalyMonitor()
    assert not m.enabled
    assert all(m.record("a", EventType.DENY_BAD_SIGNATURE) is None for _ in range(100))


def test_monitor_triggers_at_threshold_and_resets():
    m = AnomalyMonitor(3, 60, Clock())
    assert m.record("a", EventType.DENY_REPLAY) is None
    assert m.record("a", EventType.DENY_POLICY) is None
    assert m.record("a", EventType.DENY_BAD_SIGNATURE) == 3
    assert m.record("a", EventType.DENY_REPLAY) is None  # окно сброшено


def test_monitor_window_expires():
    clk = Clock()
    m = AnomalyMonitor(3, 60, clk)
    m.record("a", EventType.DENY_REPLAY)
    m.record("a", EventType.DENY_REPLAY)
    clk.t += 60  # первые два вышли из окна
    assert m.record("a", EventType.DENY_REPLAY) is None


def test_monitor_per_client_and_ignores_other_events():
    m = AnomalyMonitor(2, 60, Clock())
    m.record("a", EventType.DENY_REPLAY)
    assert m.record("b", EventType.DENY_REPLAY) is None
    for ev in (EventType.DENY_RATE_LIMIT, EventType.DENY_BUDGET, EventType.DENY_STALE_TIME,
               EventType.DENY_UNKNOWN_CLIENT, EventType.DECOY_TRIGGERED, EventType.REQUEST_OK):
        assert m.record("a", ev) is None
    assert m.record("a", EventType.DENY_POLICY) == 2


@pytest.mark.parametrize("args", [(-1, 60), (3, 0), (3, -5)])
def test_monitor_rejects_bad_args(args):
    with pytest.raises(ValueError):
        AnomalyMonitor(*args)


# ---- Pipeline ----

def arm(env, tmp_path, threshold=3, window=60):
    reg = Registry(tmp_path / "clients.json")
    env.p.anomalies = AnomalyMonitor(threshold, window)
    env.p.freeze_client = lambda cid: reg.set_status(cid, "frozen")
    return reg


def status(reg):
    return reg.load()["alice"]["status"]


def test_autofreeze_after_bad_signatures(tmp_path):
    env = make_env(tmp_path)
    reg = arm(env, tmp_path)
    for _ in range(2):
        assert call(env, make_req(env.fp, key=bytes(32)))[0] == 403
    assert status(reg) == "active"
    assert call(env, make_req(env.fp, key=bytes(32)))[0] == 403
    assert status(reg) == "frozen"
    ev = [json.loads(l) for l in audit_text(env).splitlines() if "client_frozen" in l]
    assert len(ev) == 1
    # после заморозки даже корректный запрос не проходит, без перезапуска
    assert call(env, make_req(env.fp))[0] == 403 and not env.up.calls


def test_autofreeze_logged_as_alert_with_auto_flag(tmp_path):
    env = make_env(tmp_path)
    arm(env, tmp_path, threshold=1)
    call(env, make_req(env.fp, key=bytes(32)))
    line = next(l for l in audit_text(env).splitlines() if "client_frozen" in l)
    assert '"auto":true' in line.replace(" ", "") and "alert" in line
    assert "deny_bad_signature" in line


def test_autofreeze_counts_policy_denials(tmp_path):
    env = make_env(tmp_path)
    reg = arm(env, tmp_path, threshold=2)
    for _ in range(2):
        call(env, make_req(env.fp, method="POST", target="/deleteMessage"))
    assert status(reg) == "frozen"


def test_no_autofreeze_when_disabled(tmp_path):
    env = make_env(tmp_path)
    reg = arm(env, tmp_path, threshold=0)
    for _ in range(20):
        call(env, make_req(env.fp, key=bytes(32)))
    assert status(reg) == "active"


def test_no_autofreeze_for_good_traffic_and_quota(tmp_path):
    env = make_env(tmp_path, burst=1)
    reg = arm(env, tmp_path, threshold=2)
    for _ in range(10):  # первый ok, остальные deny_rate_limit
        call(env, make_req(env.fp))
    assert status(reg) == "active"


def test_unknown_cert_cannot_freeze_anyone(tmp_path):
    env = make_env(tmp_path)
    reg = arm(env, tmp_path, threshold=1)
    for _ in range(5):
        call(env, make_req(env.fp), der=b"junk")
    assert status(reg) == "active"


def test_autofreeze_failure_does_not_break_response(tmp_path):
    env = make_env(tmp_path)
    env.p.anomalies = AnomalyMonitor(1, 60)

    def boom(cid):
        raise RuntimeError("registry down")

    env.p.freeze_client = boom
    assert call(env, make_req(env.fp, key=bytes(32)))[0] == 403
    assert "autofreeze_failed" in audit_text(env)


def test_already_revoked_client_is_not_unrevoked(tmp_path):
    env = make_env(tmp_path)
    reg = arm(env, tmp_path, threshold=1)
    reg.set_status("alice", "revoked")
    call(env, make_req(env.fp, key=bytes(32)))
    assert status(reg) == "revoked"


# ---- Config ----

def _cfg(tmp_path, text):
    p = tmp_path / "c.toml"
    p.write_text(text, "utf-8")
    return load_config(p)


def test_config_defaults_off(tmp_path):
    c = _cfg(tmp_path, "")
    assert c.autofreeze_threshold == 0 and c.autofreeze_window == 60


def test_config_anomaly_section(tmp_path):
    c = _cfg(tmp_path, "[anomaly]\nautofreeze_threshold = 10\nautofreeze_window = 120\n")
    assert (c.autofreeze_threshold, c.autofreeze_window) == (10, 120)


@pytest.mark.parametrize("body", [
    "[anomaly]\nautofreeze_threshold = -1\n", "[anomaly]\nautofreeze_window = 0\n",
    "[anomaly]\nautofreeze_threshold = 1.5\n", "[anomaly]\nbogus = 1\n"])
def test_config_rejects_bad(tmp_path, body):
    with pytest.raises(ConfigError):
        _cfg(tmp_path, body)
