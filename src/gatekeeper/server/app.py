"""Сервер: asyncio + mTLS. Здесь сборка всех частей и обработка соединений."""
from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import ssl
import stat
import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.events import EventType, Severity
from gatekeeper.core.timeutil import unix_now
from gatekeeper.pki import ca as pki_ca
from gatekeeper.server.anomaly import AnomalyMonitor
from gatekeeper.server.audit.anchor import Anchor, append_anchor
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
    normalize_ip,
)
from gatekeeper.server.nonce_cache import NonceCache
from gatekeeper.server.observe import Metrics, new_request_id, stamp
from gatekeeper.server.pipeline import Pipeline
from gatekeeper.server.providers import create_provider
from gatekeeper.server.state import StateStore
from gatekeeper.server.tls import build_server_context, peer_cert_der
from gatekeeper.server.upstream import ResponseBudget, Upstream
from gatekeeper.store.approvals import Approvals, load_operator_key
from gatekeeper.store.fsperm import harden_private_file, harden_sqlite_files
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry
from gatekeeper.store.secrets import load_secret

_CONN_DEADLINE = 120.0  # потолок на всё соединение
_HANDSHAKE_TIMEOUT = 5.0
_OPS_LINE_LIMIT = 4096  # длина строки запроса на служебном сокете
# Серверный сертификат живёт 365 дней и сам не продлевается: предупреждаем за 30 дней
# и повторяем проверку раз в сутки (мониторинга срока у проекта нет).
CERT_WARN_SECONDS = 30 * 86400
_CERT_CHECK_INTERVAL = 86400.0


def _cert_expiry_seconds(path: str | os.PathLike | None) -> int | None:
    """Секунд до истечения серверного сертификата; None = файла нет или он не читается."""
    if path is None:
        return None
    try:
        cert = pki_ca.load_cert_pem(Path(path).read_bytes())
    except (OSError, GatekeeperError):
        return None
    return int((pki_ca.cert_not_after(cert) - datetime.now(UTC)).total_seconds())


class _HandshakeSlots:
    """Синхронный счётчик одновременных рукопожатий: общий и на IP (без await перед start_tls).

    Ждать семафор нельзя: до `start_tls` поток управления не должен уступать event loop,
    иначе уже пришедший ClientHello останется в буфере StreamReader и рукопожатие зависнет.
    Слот на IP берётся до рукопожатия: один источник не может открыть много полуготовых
    рукопожатий и держать их до таймаута (X-04).
    """

    def __init__(self, limit: int, per_ip: int = 3) -> None:
        self._limit = max(1, limit)
        self._per_ip = max(1, per_ip)
        self._lock = threading.Lock()
        self._used = 0
        self._by_ip: dict[str, int] = {}

    def try_acquire(self, key: str) -> bool:
        with self._lock:
            if self._used >= self._limit or self._by_ip.get(key, 0) >= self._per_ip:
                return False
            self._used += 1
            self._by_ip[key] = self._by_ip.get(key, 0) + 1
            return True

    def release(self, key: str) -> None:
        with self._lock:
            self._used = max(0, self._used - 1)
            left = self._by_ip.get(key, 0) - 1
            if left > 0:
                self._by_ip[key] = left
            else:
                self._by_ip.pop(key, None)  # ключи не копятся: слоты освобождаются


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
                 metrics_socket: str | None = None, max_handshaking_per_ip: int = 3,
                 closers: tuple[Callable[[], None], ...] = (),
                 server_cert: str | os.PathLike | None = None,
                 anchor_file: str | None = None, anchor_interval: int = 3600) -> None:
        self.metrics, self.metrics_socket = metrics, metrics_socket
        # Срок серверного сертификата: гейдж обновляется при старте и раз в сутки.
        self.server_cert = server_cert
        self._cert_expiry: int | None = _cert_expiry_seconds(server_cert)
        # Автоякоря (A8): файл вне каталога данных задаёт оператор, шлюз только дописывает.
        self.anchor_file, self.anchor_interval = anchor_file, anchor_interval
        self.pipeline, self.bans, self.limiter, self.audit = pipeline, bans, limiter, audit
        self.http_limits, self.ssl_ctx, self.host, self.port = http_limits, ssl_ctx, host, port
        self._malformed_log = RateLimiter(rate_per_sec=1.0, burst=5)  # защита журнала от флуда
        self._tls_log = RateLimiter(rate_per_sec=1.0, burst=5)
        # Глобальный потолок на те же записи: флуд с множества разных IP не должен залить журнал.
        self._malformed_log_all = RateLimiter(rate_per_sec=5.0, burst=20, max_keys=1)
        self._tls_log_all = RateLimiter(rate_per_sec=5.0, burst=20, max_keys=1)
        self._conn_tasks: set[asyncio.Task] = set()  # живые обработчики соединений
        # Слот рукопожатия берётся ДО start_tls и держится до его конца (успех или сбой):
        # один источник не может открыть много полуготовых рукопожатий (X-04).
        self._handshake_slots = _HandshakeSlots(limiter.max_total, max_handshaking_per_ip)
        # Что закрыть при штатной остановке (state.db: WAL сводится в основной файл).
        self._closers = list(closers)

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
            if self._tls_log.allow(normalize_ip(ip)) and self._tls_log_all.allow("*"):
                await asyncio.to_thread(self.audit.append, EventType.DENY_TLS_HANDSHAKE,
                                        {"reason": str(reason)[:64], "ip": ip})
            elif self.metrics is not None:
                self.metrics.inc("gk_events_suppressed_total",
                                 type=EventType.DENY_TLS_HANDSHAKE.value)
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
        # IPv6 учитывается сетью /64: адреса одной выдачи не занимают все слоты (C-13).
        conn_key = normalize_ip(ip)
        acquired = False
        # Всё до start_tls — синхронно: иначе ClientHello успеет попасть в буфер StreamReader.
        if not self._handshake_slots.try_acquire(conn_key):
            # Отказ без записи в журнал: иначе флуд рукопожатиями зальёт журнал.
            if self.metrics is not None:
                self.metrics.inc("gk_handshake_rejected_total", reason="no_slot")
            writer.close()
            return
        try:
            async with asyncio.timeout(_CONN_DEADLINE):
                try:
                    if not await self._handshake(writer, ip):
                        return
                finally:
                    # Слот нужен только на время рукопожатия. Держать его до конца соединения
                    # значило бы ограничивать не полуготовые рукопожатия, а число клиентов:
                    # три медленных клиента с одного IP заняли бы лимит навсегда (X-04).
                    self._handshake_slots.release(conn_key)
                if await asyncio.to_thread(self.bans.is_banned, ip):
                    return
                if not self.limiter.try_acquire(conn_key):
                    return
                acquired = True
                der = peer_cert_der(writer)
                try:
                    req = await read_request(reader, self.http_limits)
                except HttpError as exc:
                    rid = new_request_id()
                    if (self._malformed_log.allow(conn_key)
                            and self._malformed_log_all.allow("*")):
                        await asyncio.to_thread(self.audit.append, EventType.DENY_MALFORMED,
                                                {"reason": exc.reason, "ip": ip,
                                                 "rid": rid})
                    elif self.metrics is not None:
                        self.metrics.inc("gk_events_suppressed_total",
                                         type=EventType.DENY_MALFORMED.value)
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
                self.limiter.release(conn_key)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def _check_cert(self, *, initial: bool) -> None:
        """Предупредить оператора о близком истечении серверного сертификата.

        Продления нет: после истечения клиенты перестанут подключаться, поэтому кроме
        ежедневной проверки предупреждение дублируется в stderr при старте.
        """
        seconds = _cert_expiry_seconds(self.server_cert)
        self._cert_expiry = seconds
        if seconds is None or seconds > CERT_WARN_SECONDS:
            return
        days = seconds // 86400
        what = (f"server certificate expired {-days} day(s) ago" if seconds < 0
                else f"server certificate expires in {days} day(s)")
        if initial:
            print(f"gatekeeper: warning: {what}: run `gatekeeper renew-server`, then restart",
                  file=sys.stderr, flush=True)
        try:
            await asyncio.to_thread(
                self.audit.append, EventType.SERVER_CERT_EXPIRING,
                {"expires_in_seconds": seconds, "days": days,
                 "action": "run" if initial else "watch"}, Severity.WARNING)
        except Exception:  # срок не должен останавливать шлюз: оператор видел stderr
            print(f"gatekeeper: warning: {what}: the audit log was not updated",
                  file=sys.stderr, flush=True)

    async def _cert_watch(self) -> None:
        """Раз в сутки обновить срок сертификата и повторить предупреждение."""
        while True:
            await asyncio.sleep(_CERT_CHECK_INTERVAL)
            await self._check_cert(initial=False)

    async def _write_anchor(self) -> None:
        """Дописать якорь текущей головы цепочки в файл оператора (A8)."""
        if not self.anchor_file:
            return
        seq, digest = self.audit.head
        if seq < 0:
            return  # пустой журнал: якорей ещё нет
        anchor = Anchor(seq, digest, unix_now())
        try:
            await asyncio.to_thread(append_anchor, self.anchor_file, anchor)
        except Exception as exc:  # якорь не должен останавливать шлюз
            print(f"gatekeeper: warning: cannot write the audit anchor: {type(exc).__name__}",
                  file=sys.stderr, flush=True)
            with contextlib.suppress(Exception):
                await asyncio.to_thread(self.audit.append, "audit_anchor_failed",
                                        {"reason": type(exc).__name__}, Severity.ALERT)

    async def _anchor_watch(self) -> None:
        """Автоякорь по расписанию: хранение якорей вне шлюза — задача оператора."""
        while True:
            await asyncio.sleep(self.anchor_interval)
            await self._write_anchor()

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
        cert_task: asyncio.Future | None = None
        anchor_task: asyncio.Future | None = None
        try:
            async with server:
                # Сокет — до записи «server_started»: при ошибке журнал не должен врать о запуске.
                ops = await self._start_ops_socket()
                await self._check_cert(initial=True)
                await asyncio.to_thread(self.audit.append, EventType.SERVER_STARTED,
                                        {"action": "run", "listen": f"{self.host}:{self.port}"})
                if on_started is not None:
                    on_started()
                cert_task = asyncio.ensure_future(self._cert_watch())
                if self.anchor_file:
                    anchor_task = asyncio.ensure_future(self._anchor_watch())
                forever = asyncio.ensure_future(server.serve_forever())
                waiter = asyncio.ensure_future(stop.wait())
                try:
                    await asyncio.wait({forever, waiter}, return_when=asyncio.FIRST_COMPLETED)
                finally:
                    forever.cancel()
                    waiter.cancel()
                    await asyncio.gather(forever, waiter, return_exceptions=True)
        finally:
            for task in (cert_task, anchor_task):
                if task is not None:
                    task.cancel()
                    with contextlib.suppress(BaseException):
                        await task
            if sigterm_installed:
                with contextlib.suppress(Exception):
                    loop.remove_signal_handler(signal.SIGTERM)
            if ops is not None:
                ops.close()
                with contextlib.suppress(OSError):
                    _unlink_if_socket(self.metrics_socket)  # type: ignore[arg-type]
            await self._cancel_conn_tasks()
            await self._close_resources()

    async def _close_resources(self) -> None:
        """Закрыть state.db и прочие ресурсы: остановка службы не должна оставлять WAL.

        Без этого `systemctl restart` оставлял `state.db-wal` незавершённым, а sqlite
        сводил его при следующем открытии; при нехватке места на разделе это уже поздно.
        """
        while self._closers:
            close = self._closers.pop()  # обратный порядок создания
            try:
                await asyncio.to_thread(close)
            except Exception:  # уборка при остановке не должна мешать выходу
                continue

    def _gauges(self) -> dict[str, float]:
        nonces = self.pipeline.nonces
        gauges = {"gk_connections": float(self.limiter.total),
                  "gk_audit_next_seq": float(self.audit.next_seq),
                  "gk_nonce_cache_entries": float(len(nonces)),
                  "gk_nonce_cache_fill_ratio": nonces.fill()}
        if self.metrics is not None:
            # Заполненность по клиентам — с меткой client. Обход клиентов только при scrape.
            for cid, ratio in nonces.fills().items():
                self.metrics.gauge("gk_nonce_cache_client_fill_ratio", ratio, client=cid)
        if self._cert_expiry is not None:
            # Секунд до истечения серверного сертификата; < 0 = уже истёк.
            gauges["gk_server_cert_expiry_seconds"] = float(self._cert_expiry)
        return gauges

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


def _operator_public_key(cfg: Config):
    """Публичный ключ оператора для подписанных одобрений (B1).

    Шлюз держит только публичную часть: закрытый ключ остаётся на машине оператора.
    """
    if not cfg.confirm_operator_key:
        return None
    try:
        pem = Path(cfg.confirm_operator_key).read_bytes()
    except OSError as exc:
        raise ConfigError("[confirm] cannot read operator_public_key") from exc
    try:
        return load_operator_key(pem)
    except GatekeeperError as exc:
        raise ConfigError(f"[confirm] operator_public_key: {exc}") from exc


def _state_freezer(store: StateStore) -> Callable[[str], None]:
    """Автозаморозка в state.db (X-08): под systemd каталог конфигурации только для чтения."""

    def freeze(client_id: str) -> None:
        store.set_freeze(client_id, unix_now())

    return freeze


def _registry_freezer(registry: Registry) -> Callable[[str], None]:
    """Резерв при persist_state = false: заморозка в реестре, как было до 0.3.9."""

    def freeze(client_id: str) -> None:
        registry.set_status(client_id, "frozen")

    return freeze


def build_app(layout: Layout, cfg: Config) -> GatekeeperApp:
    # Существующие файлы данных: права 0600, владелец, не симлинк (создание даёт 0600 само).
    for private in (layout.audit_log, layout.audit_log.parent / "chain.head",
                    layout.approvals_file, layout.decoys_file):
        harden_private_file(private)
    harden_sqlite_files(layout.state_db)
    providers, upstreams = {}, {}
    response_budget = ResponseBudget(cfg.max_total_response_bytes)
    for pc in cfg.effective_providers():
        secret = load_secret(pc.secret_env, pc.secret_file)
        providers[pc.name] = create_provider(pc.name, secret, pc.upstream_host, pc.upstream_port)
        upstreams[pc.name] = Upstream(providers[pc.name].host, providers[pc.name].port,
                                      use_tls=pc.upstream_tls, max_response=pc.max_response_bytes,
                                      budget=response_budget)
    _validate_client_providers(registry_path=layout.clients_file, names=tuple(providers),
                               default=cfg.default_provider)
    all_secrets = tuple(s for pv in providers.values() for s in pv.known_secrets())
    # repair_tail: недописанная последняя строка отрезается с событием audit_tail_repaired (B-02).
    # max_bytes/keep: журнал ротируется вместо бесконечного роста (C-06).
    audit = AuditChain(FileSink(layout.audit_log), secrets=all_secrets, repair_tail=True,
                       max_bytes=cfg.audit_max_bytes, keep=cfg.audit_keep,
                       archive_command=cfg.audit_archive_command)
    store = StateStore(layout.state_db, cfg.state_synchronous) if cfg.persist_state else None
    metrics = Metrics()
    bans = IpBanList(store=store)
    ca_cert = pki_ca.load_cert_pem(layout.ca_cert.read_bytes())
    registry = Registry(layout.clients_file)
    registry.check_permissions()  # в файле лежат master_secret: группа/остальные не допускаются
    pipeline = Pipeline(
        identity=IdentityStore(registry, ca_cert,
                               state_frozen=store.is_frozen if store is not None else None),
        providers=providers, upstreams=upstreams,
        audit=audit, nonces=NonceCache(store=store), metrics=metrics,
        client_limiter=RateLimiter(cfg.rate_per_sec, cfg.burst),
        budget=DailyBudget(cfg.daily_budget, store=store), bans=bans,
        decoy_check=DecoyStore(layout.decoys_file).is_decoy, decoy_ban_seconds=cfg.decoy_ban_seconds,
        anomalies=AnomalyMonitor(cfg.autofreeze_threshold, cfg.autofreeze_window, store=store),
        # Автозаморозка пишется в state.db: каталог конфигурации под systemd только для чтения.
        freeze_client=(_state_freezer(store) if store is not None else _registry_freezer(registry)),
        approvals=(Approvals(layout.approvals_file, cfg.confirm_ttl,
                             require_signed=cfg.confirm_require_signed,
                             operator_key=_operator_public_key(cfg))
                   if cfg.confirm_apis or any(pc.confirm_apis for pc in cfg.effective_providers())
                   else None),
        confirm_apis=frozenset(cfg.confirm_apis),
        default_provider=cfg.default_provider or next(iter(providers)),
        provider_confirm={pc.name: frozenset(pc.confirm_apis) for pc in cfg.effective_providers()},
        max_inflight={pc.name: pc.max_inflight for pc in cfg.effective_providers()})
    return GatekeeperApp(
        pipeline=pipeline, bans=bans,
        limiter=ConnectionLimiter(cfg.max_connections, cfg.max_per_ip), audit=audit,
        http_limits=HttpLimits(max_body=cfg.max_body_bytes, max_json_body=cfg.max_json_body_bytes,
                               header_timeout=cfg.header_timeout, body_timeout=cfg.body_timeout),
        ssl_ctx=build_server_context(layout.ca_cert, layout.server_cert, layout.server_key),
        host=cfg.listen_host, port=cfg.listen_port,
        metrics=metrics, metrics_socket=cfg.metrics_socket,
        max_handshaking_per_ip=cfg.max_handshaking_per_ip,
        closers=(store.close,) if store is not None else (),
        server_cert=layout.server_cert,
        anchor_file=cfg.audit_anchor_file, anchor_interval=cfg.audit_anchor_interval)
