"""Сервер: asyncio + mTLS. Здесь сборка всех частей и обработка соединений."""
from __future__ import annotations

import asyncio
import ssl

from gatekeeper.core.events import EventType
from gatekeeper.pki import ca as pki_ca
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.config import Config
from gatekeeper.server.honey.decoys import DecoyStore
from gatekeeper.server.http_io import HttpError, HttpLimits, read_request
from gatekeeper.server.http_response import neutral_response
from gatekeeper.server.identity import IdentityStore
from gatekeeper.server.limits import ConnectionLimiter, DailyBudget, IpBanList, RateLimiter
from gatekeeper.server.nonce_cache import NonceCache
from gatekeeper.server.pipeline import Pipeline
from gatekeeper.server.providers import create_provider
from gatekeeper.server.tls import build_server_context, peer_cert_der
from gatekeeper.server.upstream import Upstream
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry
from gatekeeper.store.secrets import load_secret

_CONN_DEADLINE = 120.0  # потолок на всё соединение
_HANDSHAKE_TIMEOUT = 10.0


class GatekeeperApp:
    def __init__(self, *, pipeline: Pipeline, bans: IpBanList, limiter: ConnectionLimiter,
                 audit: AuditChain, http_limits: HttpLimits, ssl_ctx: ssl.SSLContext,
                 host: str, port: int) -> None:
        self.pipeline, self.bans, self.limiter, self.audit = pipeline, bans, limiter, audit
        self.http_limits, self.ssl_ctx, self.host, self.port = http_limits, ssl_ctx, host, port
        self._malformed_log = RateLimiter(rate_per_sec=1.0, burst=5)  # защита журнала от флуда
        self._tls_log = RateLimiter(rate_per_sec=1.0, burst=5)
        self._conn_tasks: set[asyncio.Task] = set()  # живые обработчики соединений

    async def _handshake(self, writer: asyncio.StreamWriter, ip: str) -> bool:
        """mTLS-рукопожатие. Неудача пишется в журнал (с лимитом на IP) и закрывает соединение."""
        try:
            await writer.start_tls(self.ssl_ctx, ssl_handshake_timeout=_HANDSHAKE_TIMEOUT)
            return True
        except (ssl.SSLError, OSError, TimeoutError, EOFError) as exc:
            if isinstance(exc, ssl.SSLError):
                reason = (getattr(exc, "reason", None) or "ssl_error")
            elif isinstance(exc, TimeoutError):
                reason = "handshake_timeout"
            else:
                reason = type(exc).__name__
            if self._tls_log.allow(ip):
                await asyncio.to_thread(self.audit.append, EventType.DENY_TLS_HANDSHAKE,
                                        {"reason": str(reason)[:64], "ip": ip})
            return False

    async def _on_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._conn_tasks.add(task)
            task.add_done_callback(self._conn_tasks.discard)
        await self._handle_conn(reader, writer)

    async def _handle_conn(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else "unknown"
        acquired = False
        try:
            if self.bans.is_banned(ip) or not self.limiter.try_acquire(ip):
                return
            acquired = True
            async with asyncio.timeout(_CONN_DEADLINE):
                if not await self._handshake(writer, ip):
                    return
                der = peer_cert_der(writer)
                try:
                    req = await read_request(reader, self.http_limits)
                except HttpError as exc:
                    if self._malformed_log.allow(ip):
                        await asyncio.to_thread(self.audit.append, EventType.DENY_MALFORMED,
                                                {"reason": exc.reason, "ip": ip})
                    resp = neutral_response(exc.status)
                else:
                    resp = await self.pipeline.handle(req, ip, der)
                writer.write(resp)
                await writer.drain()
        except (OSError, TimeoutError):
            pass
        finally:
            if acquired:
                self.limiter.release(ip)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def serve(self, on_started=None) -> None:
        """on_started вызывается только после того, как порт реально занят."""
        server = await asyncio.start_server(
            self._on_conn, self.host, self.port)  # TLS поднимаем сами, в _handshake
        async with server:
            await asyncio.to_thread(self.audit.append, EventType.SERVER_STARTED,
                                    {"action": "run", "listen": f"{self.host}:{self.port}"})
            if on_started is not None:
                on_started()
            try:
                await server.serve_forever()
            finally:
                await self._cancel_conn_tasks()

    async def _cancel_conn_tasks(self) -> None:
        """При остановке отменяем незавершённые соединения и дожидаемся их закрытия."""
        tasks = list(self._conn_tasks)
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


def build_app(layout: Layout, cfg: Config) -> GatekeeperApp:
    secret = load_secret(cfg.secret_env, cfg.secret_file)
    provider = create_provider(cfg.provider, secret, cfg.upstream_host, cfg.upstream_port)
    audit = AuditChain(FileSink(layout.audit_log), secrets=provider.known_secrets())
    bans = IpBanList()
    ca_cert = pki_ca.load_cert_pem(layout.ca_cert.read_bytes())
    pipeline = Pipeline(
        identity=IdentityStore(Registry(layout.clients_file), ca_cert),
        provider=provider,
        upstream=Upstream(provider.host, provider.port, use_tls=cfg.upstream_tls),
        audit=audit, nonces=NonceCache(),
        client_limiter=RateLimiter(cfg.rate_per_sec, cfg.burst),
        budget=DailyBudget(cfg.daily_budget), bans=bans,
        decoy_check=DecoyStore(layout.decoys_file).is_decoy, decoy_ban_seconds=cfg.decoy_ban_seconds)
    return GatekeeperApp(
        pipeline=pipeline, bans=bans,
        limiter=ConnectionLimiter(cfg.max_connections, cfg.max_per_ip), audit=audit,
        http_limits=HttpLimits(max_body=cfg.max_body_bytes, header_timeout=cfg.header_timeout,
                               body_timeout=cfg.body_timeout),
        ssl_ctx=build_server_context(layout.ca_cert, layout.server_cert, layout.server_key),
        host=cfg.listen_host, port=cfg.listen_port)
