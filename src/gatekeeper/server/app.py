"""Сервер: asyncio + mTLS. Здесь сборка всех частей и обработка соединений."""
from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import ssl
import stat

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.events import EventType
from gatekeeper.pki import ca as pki_ca
from gatekeeper.server.anomaly import AnomalyMonitor
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.config import Config, ConfigError
from gatekeeper.server.honey.decoys import DecoyStore
from gatekeeper.server.http_io import HttpError, HttpLimits, read_request
from gatekeeper.server.http_response import build_response, neutral_response
from gatekeeper.server.identity import IdentityStore
from gatekeeper.server.limits import (
    ConnectionLimiter,
    DailyBudget,
    IpBanList,
    RateLimiter,
)
from gatekeeper.server.nonce_cache import NonceCache
from gatekeeper.server.observe import Metrics, new_request_id, stamp
from gatekeeper.server.pipeline import Pipeline
from gatekeeper.server.providers import create_provider
from gatekeeper.server.state import StateStore
from gatekeeper.server.tls import build_server_context, peer_cert_der
from gatekeeper.server.upstream import Upstream
from gatekeeper.store.approvals import Approvals
from gatekeeper.store.fsperm import harden_private_file, harden_sqlite_files
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry
from gatekeeper.store.secrets import load_secret

_CONN_DEADLINE = 120.0  # потолок на всё соединение
_HANDSHAKE_TIMEOUT = 10.0
_OPS_LINE_LIMIT = 4096  # длина строки запроса на служебном сокете


def _unlink_if_socket(path: str) -> bool:
    """Удаляет путь, только если это Unix-сокет. False = путь занят не сокетом (не трогаем)."""
    try:
        mode = os.lstat(path).st_mode
    except FileNotFoundError:
        return True
    if not stat.S_ISSOCK(mode):
        return False
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
    return True


class GatekeeperApp:
    def __init__(self, *, pipeline: Pipeline, bans: IpBanList, limiter: ConnectionLimiter,
                 audit: AuditChain, http_limits: HttpLimits, ssl_ctx: ssl.SSLContext,
                 host: str, port: int, metrics: Metrics | None = None,
                 metrics_socket: str | None = None) -> None:
        self.metrics, self.metrics_socket = metrics, metrics_socket
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
                    rid = new_request_id()
                    if self._malformed_log.allow(ip):
                        await asyncio.to_thread(self.audit.append, EventType.DENY_MALFORMED,
                                                {"reason": exc.reason, "ip": ip,
                                                 "rid": rid})
                    if self.metrics is not None:
                        self.metrics.inc("gk_requests_total", status=str(exc.status))
                    resp = stamp(neutral_response(exc.status), rid)
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
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def serve(self, on_started=None) -> None:
        """on_started вызывается только после того, как порт реально занят.

        SIGTERM (systemctl stop) завершает работу штатно: закрывается служебный сокет,
        отменяются соединения. Без обработчика процесс умирал бы, не выполнив `finally`.
        """
        server = await asyncio.start_server(
            self._on_conn, self.host, self.port)  # TLS поднимаем сами, в _handshake
        loop = asyncio.get_running_loop()
        stop = asyncio.Event()
        sigterm_installed = False
        with contextlib.suppress(NotImplementedError, RuntimeError, ValueError):
            loop.add_signal_handler(signal.SIGTERM, stop.set)
            sigterm_installed = True
        ops = None
        try:
            async with server:
                # Сокет — до записи «server_started»: при ошибке журнал не должен врать о запуске.
                ops = await self._start_ops_socket()
                await asyncio.to_thread(self.audit.append, EventType.SERVER_STARTED,
                                        {"action": "run", "listen": f"{self.host}:{self.port}"})
                if on_started is not None:
                    on_started()
                forever = asyncio.ensure_future(server.serve_forever())
                waiter = asyncio.ensure_future(stop.wait())
                try:
                    await asyncio.wait({forever, waiter}, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    forever.cancel()
                    waiter.cancel()
                    await asyncio.gather(forever, waiter, return_exceptions=True)
        finally:
            if sigterm_installed:
                with contextlib.suppress(Exception):
                    loop.remove_signal_handler(signal.SIGTERM)
            if ops is not None:
                ops.close()
                with contextlib.suppress(OSError):
                    _unlink_if_socket(self.metrics_socket)  # type: ignore[arg-type]
            await self._cancel_conn_tasks()

    def _gauges(self) -> dict[str, float]:
        return {"gk_connections": float(self.limiter.total),
                "gk_audit_next_seq": float(self.audit.next_seq),
                "gk_nonce_cache_entries": float(len(self.pipeline.nonces))}

    async def _start_ops_socket(self):
        """Служебный Unix-сокет: GET /healthz и GET /metrics. Не на публичном порту."""
        if not self.metrics_socket or os.name == "nt" or self.metrics is None:
            return None
        if not _unlink_if_socket(self.metrics_socket):
            raise ConfigError(f"metrics_socket path exists and is not a socket: {self.metrics_socket}")
        old = os.umask(0o177)  # сокет создаётся сразу с правами 0600
        try:
            return await asyncio.start_unix_server(  # type: ignore[attr-defined,unused-ignore]
                self._on_ops, self.metrics_socket, limit=_OPS_LINE_LIMIT)
        finally:
            os.umask(old)

    async def _on_ops(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(), 2.0)
            parts = line.split()
            path = parts[1].decode("ascii", "replace") if len(parts) >= 2 else ""
            if parts[:1] == [b"GET"] and path == "/healthz":
                body, ctype, status = b'{"ok":true}', "application/json", 200
            elif parts[:1] == [b"GET"] and path == "/metrics" and self.metrics is not None:
                body = self.metrics.render(self._gauges()).encode()
                ctype, status = "text/plain; version=0.0.4", 200
            else:
                body, ctype, status = b'{"ok":false}', "application/json", 404
            writer.write(build_response(status, body, ctype))
            await writer.drain()
        except (ValueError, asyncio.LimitOverrunError):  # строка длиннее лимита
            with contextlib.suppress(OSError):
                writer.write(build_response(400, b'{"ok":false}', "application/json"))
                await writer.drain()
        except (OSError, TimeoutError):
            pass
        finally:
            writer.close()

    async def _cancel_conn_tasks(self) -> None:
        """При остановке отменяем незавершённые соединения и дожидаемся их закрытия."""
        tasks = list(self._conn_tasks)
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)


def _validate_client_providers(*, registry_path, names: tuple[str, ...], default: str | None) -> None:
    """Опечатка в имени провайдера или «неявный» провайдер должны ломать запуск, а не запросы."""
    try:
        clients = Registry(registry_path).load()
    except GatekeeperError:
        return  # битый реестр обнаружат своими проверками
    unknown = sorted(cid for cid, e in clients.items()
                     if isinstance(e, dict) and e.get("provider") not in (None, *names))
    if unknown:
        raise ConfigError(f"clients refer to providers missing from config: {unknown}")
    if len(names) > 1 and default is None:
        implicit = sorted(cid for cid, e in clients.items()
                          if isinstance(e, dict) and e.get("provider") is None
                          and e.get("status") != "revoked")
        if implicit:
            raise ConfigError(
                "several providers are configured but these clients have no provider and "
                f"default_provider is not set: {implicit} (set [server] default_provider "
                "or re-issue the clients with --provider)")


def build_app(layout: Layout, cfg: Config) -> GatekeeperApp:
    # Существующие файлы данных: права 0600, владелец, не симлинк (создание даёт 0600 само).
    for private in (layout.audit_log, layout.audit_log.parent / "chain.head",
                    layout.approvals_file, layout.decoys_file):
        harden_private_file(private)
    harden_sqlite_files(layout.state_db)
    providers, upstreams = {}, {}
    for pc in cfg.effective_providers():
        secret = load_secret(pc.secret_env, pc.secret_file)
        providers[pc.name] = create_provider(pc.name, secret, pc.upstream_host, pc.upstream_port)
        upstreams[pc.name] = Upstream(providers[pc.name].host, providers[pc.name].port,
                                      use_tls=pc.upstream_tls, max_response=pc.max_response_bytes)
    _validate_client_providers(registry_path=layout.clients_file, names=tuple(providers),
                               default=cfg.default_provider)
    all_secrets = tuple(s for pv in providers.values() for s in pv.known_secrets())
    audit = AuditChain(FileSink(layout.audit_log), secrets=all_secrets)
    store = StateStore(layout.state_db) if cfg.persist_state else None
    metrics = Metrics()
    bans = IpBanList(store=store)
    ca_cert = pki_ca.load_cert_pem(layout.ca_cert.read_bytes())
    registry = Registry(layout.clients_file)
    registry.check_permissions()  # в файле лежат master_secret: группа/остальные не допускаются
    pipeline = Pipeline(
        identity=IdentityStore(registry, ca_cert),
        providers=providers, upstreams=upstreams,
        audit=audit, nonces=NonceCache(store=store), metrics=metrics,
        client_limiter=RateLimiter(cfg.rate_per_sec, cfg.burst),
        budget=DailyBudget(cfg.daily_budget, store=store), bans=bans,
        decoy_check=DecoyStore(layout.decoys_file).is_decoy, decoy_ban_seconds=cfg.decoy_ban_seconds,
        anomalies=AnomalyMonitor(cfg.autofreeze_threshold, cfg.autofreeze_window, store=store),
        freeze_client=lambda cid: registry.set_status(cid, "frozen"),
        approvals=(Approvals(layout.approvals_file, cfg.confirm_ttl)
                   if cfg.confirm_apis or any(pc.confirm_apis for pc in cfg.effective_providers())
                   else None),
        confirm_apis=frozenset(cfg.confirm_apis),
        default_provider=cfg.default_provider or next(iter(providers)),
        provider_confirm={pc.name: frozenset(pc.confirm_apis) for pc in cfg.effective_providers()},
        max_inflight={pc.name: pc.max_inflight for pc in cfg.effective_providers()})
    return GatekeeperApp(
        pipeline=pipeline, bans=bans,
        limiter=ConnectionLimiter(cfg.max_connections, cfg.max_per_ip), audit=audit,
        http_limits=HttpLimits(max_body=cfg.max_body_bytes, header_timeout=cfg.header_timeout,
                               body_timeout=cfg.body_timeout),
        ssl_ctx=build_server_context(layout.ca_cert, layout.server_cert, layout.server_key),
        host=cfg.listen_host, port=cfg.listen_port,
        metrics=metrics, metrics_socket=cfg.metrics_socket)
