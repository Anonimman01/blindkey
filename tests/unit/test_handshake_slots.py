"""Слот рукопожатия на IP берётся до start_tls и снимается сразу после него (X-04)."""
import asyncio

from gatekeeper.server.app import GatekeeperApp
from gatekeeper.server.http_io import HttpLimits
from gatekeeper.server.limits import ConnectionLimiter, RateLimiter
from gatekeeper.server.observe import Metrics


class FakeAudit:
    def __init__(self):
        self.events = []

    def append(self, *a, **kw):
        self.events.append(a)
        return {"seq": len(self.events), "hash": "0" * 64}


class FakeBans:
    """Любой адрес «забанен»: соединение завершается сразу после рукопожатия."""

    def is_banned(self, ip):
        return True


class FakeWriter:
    def __init__(self, ip, gate):
        self.ip, self.gate = ip, gate
        self.closed = False
        self.started = 0

    def get_extra_info(self, name):
        return (self.ip, 40000) if name == "peername" else None

    async def start_tls(self, ctx, **kw):
        self.started += 1
        await self.gate.wait()
        raise OSError("handshake aborted")

    def close(self):
        self.closed = True

    async def wait_closed(self):
        return None


class ReadyTlsWriter(FakeWriter):
    """Рукопожатие проходит сразу: слот должен освободиться до обработки запроса."""

    async def start_tls(self, ctx, **kw):
        self.started += 1


def make_app(per_ip, audit):
    return GatekeeperApp(pipeline=None, bans=FakeBans(), limiter=ConnectionLimiter(50, 10),
                         audit=audit, http_limits=HttpLimits(), ssl_ctx=None,
                         host="127.0.0.1", port=0, metrics=Metrics(),
                         max_handshaking_per_ip=per_ip)


def test_no_slot_closes_connection_counts_metric_and_skips_audit():
    async def scenario():
        audit = FakeAudit()
        app = make_app(1, audit)
        gate = asyncio.Event()
        busy = FakeWriter("1.2.3.4", gate)
        task = asyncio.create_task(app._handle_conn(None, busy))
        for _ in range(20):
            await asyncio.sleep(0)
        assert busy.started == 1
        extra = FakeWriter("1.2.3.4", gate)
        await app._handle_conn(None, extra)
        assert extra.closed and extra.started == 0     # до start_tls не дошло
        assert audit.events == []                      # журнал не флудим
        assert "gk_handshake_rejected_total" in app.metrics.render()
        other = FakeWriter("5.6.7.8", gate)            # другой IP не страдает
        pending = asyncio.create_task(app._handle_conn(None, other))
        for _ in range(20):
            await asyncio.sleep(0)
        assert other.started == 1
        gate.set()
        await asyncio.gather(task, pending)
        # слоты освобождены: тот же IP снова может начать рукопожатие
        again = FakeWriter("1.2.3.4", gate)
        await app._handle_conn(None, again)
        assert again.started == 1
    asyncio.run(scenario())


def test_mapped_ipv4_shares_the_handshake_slot():
    async def scenario():
        app = make_app(1, FakeAudit())
        gate = asyncio.Event()
        busy = FakeWriter("1.2.3.4", gate)
        task = asyncio.create_task(app._handle_conn(None, busy))
        for _ in range(20):
            await asyncio.sleep(0)
        mapped = FakeWriter("::ffff:1.2.3.4", gate)
        await app._handle_conn(None, mapped)
        assert mapped.closed and mapped.started == 0
        gate.set()
        await task
    asyncio.run(scenario())


def test_slot_is_free_after_successful_handshake():
    """Слот держится только на рукопожатие, а не на всё соединение."""
    async def scenario():
        app = make_app(1, FakeAudit())
        writer = ReadyTlsWriter("1.2.3.4", asyncio.Event())
        await app._handle_conn(None, writer)
        assert writer.started == 1
        assert app._handshake_slots._used == 0
        assert app._handshake_slots._by_ip == {}
    asyncio.run(scenario())


def test_four_ready_clients_from_one_ip_are_not_rejected():
    """4 клиента одного IP с завершённым TLS: лимит рукопожатий не должен их отсекать."""
    async def scenario():
        app = make_app(3, FakeAudit())
        writers = [ReadyTlsWriter("1.2.3.4", asyncio.Event()) for _ in range(4)]
        await asyncio.gather(*(app._handle_conn(None, w) for w in writers))
        assert [w.started for w in writers] == [1, 1, 1, 1]
        assert "gk_handshake_rejected_total" not in app.metrics.render()
        assert app._handshake_slots._used == 0
    asyncio.run(scenario())


def test_failure_log_limiter_is_global_on_fake_clock():
    app = make_app(3, FakeAudit())
    t = [0.0]
    # Фейковые часы: иначе тест зависит от реального времени и может ловить недобор токенов.
    app._tls_log = RateLimiter(1.0, 5, clock=lambda: t[0])
    app._tls_log_all = RateLimiter(5.0, 20, clock=lambda: t[0], max_keys=1)
    # Разные IP: свой бакет у каждого полный, но глобальный потолок один на всех.
    allowed = sum(app._tls_log.allow(f"10.0.0.{i}") and app._tls_log_all.allow("*")
                  for i in range(200))
    assert allowed == 20
    # Через секунду глобальный бакет пополнился на rate (5 токенов), не больше burst.
    t[0] = 1.0
    allowed_after = sum(app._tls_log_all.allow("*") for _ in range(200))
    assert allowed_after == 5
