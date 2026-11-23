"""Резерв памяти под ответ живёт до конца фильтрации, а не до конца fetch() (C-14, X-07)."""
import asyncio
import socket
import threading

import pytest

from gatekeeper.server.providers.base import UpstreamRequest
from gatekeeper.server.providers.telegram import TelegramProvider
from gatekeeper.server.upstream import ResponseBudget, Upstream, UpstreamError

BODY = b'{"x":"' + b"a" * 40_000 + b'"}'


class FakeServer:
    """Мини-upstream: отдаёт одно и то же тело на любое число соединений."""

    def __init__(self, body=BODY, ctype="application/json"):
        self.body, self.ctype = body, ctype
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.recv(65536)
                    head = (f"HTTP/1.1 200 OK\r\nContent-Type: {self.ctype}\r\n"
                            f"Content-Length: {len(self.body)}\r\nConnection: close\r\n\r\n")
                    conn.sendall(head.encode() + self.body)
                except OSError:
                    pass

    def close(self):
        self.sock.close()


def req():
    return UpstreamRequest("POST", "/x", (("host", "localhost"),), b"")


def test_reservation_is_held_until_released():
    srv = FakeServer()
    try:
        budget = ResponseBudget(len(BODY) * 3 + 100)
        up = Upstream("127.0.0.1", srv.port, use_tls=False, timeout=5.0, budget=budget)

        async def scenario():
            held = [await up.fetch(req(), hold=True) for _ in range(3)]
            assert budget.used >= 3 * len(BODY)      # тела ещё «в памяти»
            with pytest.raises(UpstreamError):
                await up.fetch(req(), hold=True)     # глобальный потолок не превышен
            assert budget.used <= budget.max_bytes
            for r in held:
                up.release_response(r)
            assert budget.used == 0
            up.release_response(held[0])             # повторное освобождение безопасно
            assert budget.used == 0
        asyncio.run(scenario())
    finally:
        srv.close()


def test_json_filter_accounts_for_parsing_overhead():
    srv = FakeServer()
    try:
        budget = ResponseBudget(len(BODY) * 9)
        up = Upstream("127.0.0.1", srv.port, use_tls=False, timeout=5.0, budget=budget)

        async def scenario():
            a = await up.fetch(req(), hold=True)
            assert up.begin_filter(a) is True
            assert budget.used == len(BODY) * 8      # 8x на время разбора JSON
            b = await up.fetch(req(), hold=True)
            assert up.begin_filter(b) is False       # второй разбор уже не влезает
            assert budget.used == len(BODY) * 9
            up.release_response(a)
            up.release_response(b)
            assert budget.used == 0
        asyncio.run(scenario())
    finally:
        srv.close()


def test_non_json_reservation_is_unchanged():
    srv = FakeServer(b"plain text body", "text/plain")
    try:
        budget = ResponseBudget(1000)
        up = Upstream("127.0.0.1", srv.port, use_tls=False, timeout=5.0, budget=budget)

        async def scenario():
            r = await up.fetch(req(), hold=True)
            assert up.begin_filter(r) is True
            assert budget.used == len(r.body)        # никакого множителя для не-JSON
            up.release_response(r)
            assert budget.used == 0
        asyncio.run(scenario())
    finally:
        srv.close()


def test_fetch_without_hold_releases_immediately():
    srv = FakeServer()
    try:
        budget = ResponseBudget(len(BODY) * 2)
        up = Upstream("127.0.0.1", srv.port, use_tls=False, timeout=5.0, budget=budget)

        async def scenario():
            for _ in range(4):
                await up.fetch(req())                # прежнее поведение не изменилось
            assert budget.used == 0
        asyncio.run(scenario())
    finally:
        srv.close()


class TrackingUpstream:
    """FakeUpstream из test_pipeline + настоящий учёт резерва памяти."""

    def __init__(self, budget):
        from test_pipeline import FakeUpstream
        self.inner = FakeUpstream()
        self.budget = budget
        self.held = {}

    async def fetch(self, req, timeout=None, *, hold=False):
        resp = await self.inner.fetch(req, timeout, hold=hold)
        if hold:
            assert self.budget.reserve(len(resp.body))
            self.held[id(resp)] = len(resp.body)
        return resp

    def begin_filter(self, resp):
        return True

    def release_response(self, resp):
        amount = self.held.pop(id(resp), 0)
        if amount:
            self.budget.release(amount)


def test_pipeline_holds_reservation_during_filter_and_releases_after(tmp_path, monkeypatch):
    from test_pipeline import call, make_env, make_req
    env = make_env(tmp_path)
    budget = ResponseBudget(1_000_000)
    tracker = TrackingUpstream(budget)
    env.p.upstreams = dict.fromkeys(env.p.upstreams, tracker)
    real = TelegramProvider.filter_response
    seen = []

    def spy(self, resp):
        seen.append(budget.used)
        return real(self, resp)

    monkeypatch.setattr(TelegramProvider, "filter_response", spy)
    status, _ = call(env, make_req(env.fp))
    assert status == 200
    assert seen and seen[0] >= len(tracker.inner.response.body)  # резерв жив во время фильтра
    assert budget.used == 0                                     # и снят после отправки ответа


def test_pipeline_releases_reservation_when_filter_raises(tmp_path, monkeypatch):
    from test_pipeline import call, make_env, make_req
    env = make_env(tmp_path)
    budget = ResponseBudget(1_000_000)
    tracker = TrackingUpstream(budget)
    env.p.upstreams = dict.fromkeys(env.p.upstreams, tracker)

    def boom(self, resp):
        raise RuntimeError("filter crashed")

    monkeypatch.setattr(TelegramProvider, "filter_response", boom)
    status, _ = call(env, make_req(env.fp))
    assert status == 500                    # fail closed
    assert budget.used == 0                 # резерв не потерян
    assert tracker.held == {}


class BoomMetrics:
    """Метрика upstream падает: это не должно удерживать резерв памяти."""

    def inc(self, name, **labels):
        if name == "gk_upstream_requests_total":
            raise RuntimeError("metrics broke")

    def observe(self, name, value, **labels):
        return None


def test_reservation_released_when_metric_raises(tmp_path):
    from test_pipeline import call, make_env, make_req
    env = make_env(tmp_path)
    budget = ResponseBudget(1_000_000)
    tracker = TrackingUpstream(budget)
    env.p.upstreams = dict.fromkeys(env.p.upstreams, tracker)
    env.p.metrics = BoomMetrics()
    status, _ = call(env, make_req(env.fp))
    assert status == 500            # fail closed: метрика упала внутри обработки ответа
    assert budget.used == 0         # try открыт сразу после fetch, резерв снят
    assert tracker.held == {}


class NoBudgetUpstream:
    """Резерв уже не даёт места под разбор JSON: begin_filter отказывает."""

    def __init__(self):
        from test_pipeline import FakeUpstream
        self.inner = FakeUpstream()

    async def fetch(self, req, timeout=None, *, hold=False):
        return await self.inner.fetch(req, timeout, hold=hold)

    def begin_filter(self, resp):
        return False

    def release_response(self, resp):
        return None


def test_budget_refusal_is_alert_with_executed_flag(tmp_path):
    from test_pipeline import audit_text, call, make_env, make_req
    env = make_env(tmp_path)
    env.p.upstreams = dict.fromkeys(env.p.upstreams, NoBudgetUpstream())
    status, _ = call(env, make_req(env.fp))
    assert status == 502
    text = audit_text(env)
    assert "response_budget_exceeded" in text
    assert '"executed":true' in text.replace(" ", "")   # действие на upstream уже выполнено
    assert '"sev":"alert"' in text.replace(" ", "")    # оператор должен это увидеть


def test_json_shaped_body_without_json_header_uses_multiplier():
    """Фильтр разбирает тело, начинающееся с { или [, даже без JSON-заголовка."""
    body = b'{"x":"' + b"a" * 1000 + b'"}'
    srv = FakeServer(body, "text/plain")
    try:
        budget = ResponseBudget(len(body) * 8)
        up = Upstream("127.0.0.1", srv.port, use_tls=False, timeout=5.0, budget=budget)

        async def scenario():
            r = await up.fetch(req(), hold=True)
            assert up.begin_filter(r) is True
            assert budget.used == len(body) * 8      # тот же множитель, что для application/json
            up.release_response(r)
            assert budget.used == 0
        asyncio.run(scenario())
    finally:
        srv.close()


def test_concurrent_reservations_never_exceed_the_budget():
    """12 параллельных ответов на реальном Upstream: суммарный резерв не выше max_bytes."""
    srv = FakeServer()
    try:
        budget = ResponseBudget(len(BODY) * 5 + 100)   # места хватает ровно на 5 тел
        up = Upstream("127.0.0.1", srv.port, use_tls=False, timeout=5.0, budget=budget)

        async def one(results, index):
            try:
                results[index] = await up.fetch(req(), hold=True)
            except UpstreamError:
                results[index] = None

        async def scenario():
            results: list = [None] * 12
            tasks = [asyncio.create_task(one(results, i)) for i in range(12)]
            samples = []
            while not all(t.done() for t in tasks):
                samples.append(budget.used)
                await asyncio.sleep(0)
            await asyncio.gather(*tasks)
            samples.append(budget.used)
            assert max(samples) <= budget.max_bytes     # потолок не превышен ни в один момент
            held = [r for r in results if r is not None]
            assert 0 < len(held) <= 5
            assert budget.used == sum(len(r.body) for r in held)  # учёт без утечек
            for r in held:
                up.release_response(r)
            assert budget.used == 0
        asyncio.run(scenario())
    finally:
        srv.close()


def test_reservation_is_released_when_close_hangs(monkeypatch):
    """Таймаут на wait_closed после готового ответа не должен съедать резерв навсегда."""
    srv = FakeServer()
    budget = ResponseBudget(len(BODY) * 3)
    up = Upstream("127.0.0.1", srv.port, use_tls=False, timeout=1.0, budget=budget)
    real_open = asyncio.open_connection
    opened = []

    class HangingCloseWriter:
        def __init__(self, writer):
            self._writer = writer

        def __getattr__(self, name):
            return getattr(self._writer, name)

        async def wait_closed(self):
            await asyncio.sleep(10)          # дольше таймаута соединения

    async def slow_open(*args, **kwargs):
        reader, writer = await real_open(*args, **kwargs)
        opened.append(writer)
        return reader, HangingCloseWriter(writer) if len(opened) == 1 else writer

    async def scenario():
        with pytest.raises(UpstreamError, match="timeout"):
            await up.fetch(req(), hold=True)  # вызывающий ответа не получает
        assert budget.used == 0              # резерв снят внутри _fetch
        assert up._held == {}                # и владение им не осталось висеть
        again = await up.fetch(req(), hold=True)   # место снова доступно
        assert budget.used == len(BODY)
        up.release_response(again)
        assert budget.used == 0

    monkeypatch.setattr(asyncio, "open_connection", slow_open)
    try:
        asyncio.run(scenario())
    finally:
        srv.close()
