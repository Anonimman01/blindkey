"""request-id, Date, Retry-After, Cache-Control, метрики, group commit журнала."""
import re
import threading
import time

from test_pipeline import audit_text, call, make_env, make_req

from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.audit.verify import verify_file
from gatekeeper.server.observe import Metrics, stamp


def headers(resp: bytes) -> dict[str, str]:
    head = resp.partition(b"\r\n\r\n")[0].decode().split("\r\n")[1:]
    return {k.lower(): v for k, v in (h.split(": ", 1) for h in head)}


def test_every_response_has_request_id_date_no_store(tmp_path):
    env = make_env(tmp_path)
    _, ok = call(env, make_req(env.fp))
    _, denied = call(env, make_req(env.fp, key=bytes(32)))
    for resp in (ok, denied):
        h = headers(resp)
        assert re.fullmatch(r"[0-9a-f]{16}", h["x-request-id"])
        assert h["date"].endswith("GMT") and h["cache-control"] == "no-store"
    assert headers(ok)["x-request-id"] != headers(denied)["x-request-id"]


def test_request_id_links_response_to_audit(tmp_path):
    env = make_env(tmp_path)
    _, resp = call(env, make_req(env.fp, key=bytes(32)))
    assert headers(resp)["x-request-id"] in audit_text(env)


def test_denied_responses_stay_neutral(tmp_path):
    env = make_env(tmp_path)
    _, bad_sig = call(env, make_req(env.fp, key=bytes(32)))
    _, not_allowed = call(env, make_req(env.fp, target="/getUpdates", method="GET", body=b""))
    assert bad_sig.partition(b"\r\n\r\n")[2] == not_allowed.partition(b"\r\n\r\n")[2]
    assert "retry-after" not in headers(bad_sig)


def test_rate_limit_sends_retry_after(tmp_path):
    env = make_env(tmp_path, burst=1)
    call(env, make_req(env.fp))
    status, resp = call(env, make_req(env.fp))
    assert status == 429 and int(headers(resp)["retry-after"]) >= 1


def test_budget_sends_retry_after(tmp_path):
    env = make_env(tmp_path, budget=1)
    call(env, make_req(env.fp))
    status, resp = call(env, make_req(env.fp))
    assert status == 429 and 1 <= int(headers(resp)["retry-after"]) <= 86400


def test_stamp_inserts_after_status_line():
    out = stamp(b"HTTP/1.1 200 OK\r\nA: b\r\n\r\nbody", "abc")
    assert out == b"HTTP/1.1 200 OK\r\nX-Request-Id: abc\r\nA: b\r\n\r\nbody"


def test_metrics_render():
    m = Metrics()
    m.inc("gk_requests_total", status=200)
    m.inc("gk_requests_total", status=200)
    m.inc("gk_events_total", type='a"b')
    text = m.render({"gk_connections": 3})
    assert 'gk_requests_total{status="200"} 2' in text
    assert 'type="a\\"b"' in text and "gk_connections 3" in text


def test_pipeline_counts_metrics(tmp_path):
    env = make_env(tmp_path)
    env.p.metrics = Metrics()
    call(env, make_req(env.fp))
    call(env, make_req(env.fp, key=bytes(32)))
    text = env.p.metrics.render()
    assert 'gk_requests_total{status="200"} 1' in text
    assert 'gk_requests_total{status="403"} 1' in text
    assert 'gk_events_total{type="deny_bad_signature"} 1' in text


def test_group_commit_keeps_chain_valid_under_threads(tmp_path):
    log, head = tmp_path / "a" / "audit.log", tmp_path / "a" / "chain.head"
    chain = AuditChain(FileSink(log, head))
    n_threads, per = 16, 25
    errors = []

    def work(tid):
        try:
            for i in range(per):
                chain.append("request_ok", {"t": tid, "i": i})
        except Exception as exc:
            errors.append(exc)

    ts = [threading.Thread(target=work, args=(i,)) for i in range(n_threads)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert not errors
    res = verify_file(log, head)
    assert res.ok and res.last_seq == n_threads * per - 1


def test_group_commit_batches_fsyncs(tmp_path, monkeypatch):
    sink = FileSink(tmp_path / "a" / "audit.log", tmp_path / "a" / "chain.head")
    chain = AuditChain(sink)
    calls = []
    orig = sink.append_lines

    def slow(lines):
        calls.append(len(lines))
        time.sleep(0.02)  # имитируем fsync: за это время копится следующая пачка
        orig(lines)

    monkeypatch.setattr(sink, "append_lines", slow)
    ts = [threading.Thread(target=chain.append, args=("request_ok", {"i": i})) for i in range(40)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    assert sum(calls) == 40 and len(calls) < 40  # меньше fsync, чем записей
    assert verify_file(sink.path, sink.head_path).ok


def test_bad_record_does_not_break_batch(tmp_path):
    import pytest

    from gatekeeper.core.errors import AuditError
    chain = AuditChain(FileSink(tmp_path / "a" / "audit.log", tmp_path / "a" / "chain.head"))
    chain.append("request_ok", {"i": 1})
    with pytest.raises(AuditError):
        chain.append("request_ok", {"bad": object()})
    chain.append("request_ok", {"i": 2})
    assert verify_file(tmp_path / "a" / "audit.log", tmp_path / "a" / "chain.head").last_seq == 1


def test_latency_metrics_are_real_histograms(tmp_path):
    """B-09: gk_*_seconds отдаются как гистограмма, histogram_quantile работает."""
    env = make_env(tmp_path)
    env.p.metrics = Metrics()
    call(env, make_req(env.fp))
    text = env.p.metrics.render()
    assert 'gk_request_seconds_bucket{le="+Inf"} 1' in text
    assert "gk_request_seconds_count 1" in text
    assert "gk_request_seconds_sum" in text
    assert 'gk_upstream_seconds_bucket{provider="telegram",le="+Inf"} 1' in text
    assert "gk_upstream_seconds_count" in text


def test_request_id_header_constant_matches_the_response():
    """B-08: константа и фактический заголовок ответа — одно и то же имя."""
    from gatekeeper.core import constants

    assert constants.HEADER_REQUEST_ID == "X-Request-Id"
    assert b"X-Request-Id" in stamp(b"HTTP/1.1 200 OK\r\n\r\n", "abc")
