"""Конвейер обработки запроса: дешёвое раньше дорогого, любая ошибка = отказ.

Порядок: решение по приманке -> идентификация -> заголовки -> время -> подпись ->
nonce -> политика -> лимиты -> квота -> подтверждение -> запись намерения -> upstream ->
фильтр ответа -> запись результата. В журнал пишется всё, включая отказы; клиенту уходит
нейтральный ответ без причины.

Подписывается request-target как есть (например "/sendMessage") и HTTP-метод.

Запись намерения (`request_intent`) идёт ДО обращения к провайдеру (C-07): если журнал
недоступен, действие не выполняется и клиент получает ошибку, которую безопасно повторить.
SQLite-состояние (nonce, квота, баны, аномалии) пишется через `asyncio.to_thread` (B-04):
fsync-шторм не останавливает event loop.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import time
from collections.abc import Callable, Mapping

from gatekeeper.core import constants
from gatekeeper.core.errors import SigningError
from gatekeeper.core.events import EventType, Severity
from gatekeeper.core.kdf import derive_signing_key
from gatekeeper.core.signing import build_canonical_string, verify
from gatekeeper.core.timeutil import is_fresh, unix_now
from gatekeeper.server.anomaly import AnomalyMonitor
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.confirm_body import ConfirmBodyError, describe_params, parse_confirm_params
from gatekeeper.server.http_io import ParsedRequest
from gatekeeper.server.http_response import build_response, neutral_response
from gatekeeper.server.identity import IdentityStore
from gatekeeper.server.limits import DailyBudget, IpBanList, RateLimiter
from gatekeeper.server.nonce_cache import NonceCache
from gatekeeper.server.observe import Metrics, new_request_id, request_id, stamp
from gatekeeper.server.providers.base import Provider, ProviderError
from gatekeeper.server.upstream import Upstream, UpstreamError
from gatekeeper.store.approvals import Approvals

_H = {k: getattr(constants, f"HEADER_{k.upper()}").lower() for k in ("client", "epoch", "time", "nonce", "sig")}
_PASSTHROUGH = frozenset({400, 401, 403, 404, 409, 429, 500, 502, 503})


def _num(value: object) -> int | None:
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 12:
        return int(value)
    return None


class Pipeline:
    def __init__(self, *, identity: IdentityStore, provider: Provider | None = None,
                 upstream: Upstream | None = None,
                 providers: Mapping[str, Provider] | None = None,
                 upstreams: Mapping[str, Upstream] | None = None,
                 default_provider: str | None = None,
                 provider_confirm: Mapping[str, frozenset[str]] | None = None,
                 max_inflight: Mapping[str, int] | None = None,
                 audit: AuditChain, nonces: NonceCache, client_limiter: RateLimiter,
                 budget: DailyBudget, bans: IpBanList,
                 decoy_check: Callable[[str], bool] | None = None,
                 decoy_ban_seconds: int = 3600,
                 anomalies: AnomalyMonitor | None = None,
                 freeze_client: Callable[[str], None] | None = None,
                 approvals: Approvals | None = None,
                 confirm_apis: frozenset[str] = frozenset(),
                 clock: Callable[[], int] = unix_now,
                 metrics: Metrics | None = None) -> None:
        self.metrics = metrics
        # Один провайдер (provider/upstream) или несколько (providers/upstreams): клиент привязан
        # к своему провайдеру полем provider в реестре; без поля берётся default_provider.
        if providers is None:
            if provider is None or upstream is None:
                raise ValueError("provider and upstream (or providers and upstreams) are required")
            providers, upstreams = {provider.name: provider}, {provider.name: upstream}
        if not providers or upstreams is None or set(upstreams) != set(providers):
            raise ValueError("providers and upstreams must have the same non-empty set of names")
        self.providers, self.upstreams = dict(providers), dict(upstreams)
        self.default_provider = default_provider or next(iter(self.providers))
        if self.default_provider not in self.providers:
            raise ValueError("default_provider is not among providers")
        self.provider = self.providers[self.default_provider]  # по умолчанию (совместимость)
        self.upstream = self.upstreams[self.default_provider]
        # confirm_apis провайдера добавляются к общим; лимит одновременных запросов на провайдера
        self._provider_confirm = {k: frozenset(v) for k, v in (provider_confirm or {}).items()}
        self._inflight = {name: asyncio.Semaphore(max((max_inflight or {}).get(name, 32), 1))
                          for name in self.providers}
        self._all_secrets = tuple(s for pv in self.providers.values() for s in pv.known_secrets())
        self.identity, self.audit = identity, audit
        self.nonces, self.client_limiter, self.budget, self.bans = nonces, client_limiter, budget, bans
        self.decoy_check, self.decoy_ban_seconds, self.clock = decoy_check, decoy_ban_seconds, clock
        self.anomalies, self.freeze_client = anomalies, freeze_client
        self.approvals, self.confirm_apis = approvals, frozenset(confirm_apis)
        # Защита журнала от флуда отказов (аудит GK-03/M4): записи WARNING-отказов ограничены
        # на ключ (клиент или IP) и глобально; ALERT-события пишутся всегда. Счётчики аномалий и
        # автозаморозка от этого не зависят: считается каждый отказ, пропускается только запись.
        self._deny_log_key = RateLimiter(rate_per_sec=2.0, burst=20)
        self._deny_log_all = RateLimiter(rate_per_sec=50.0, burst=200, max_keys=1)

    async def _log(self, etype, data: dict, sev: Severity = Severity.INFO) -> None:
        rid = request_id.get()
        if rid is not None:
            data = {**data, "rid": rid}  # связь ответа клиента с записью журнала
        if self.metrics is not None:
            self.metrics.inc("gk_events_total", type=getattr(etype, "value", etype))
        await asyncio.to_thread(self.audit.append, etype, data, sev)

    async def _deny(self, etype: EventType, status: int, reason: str, ip: str,
                    client: str | None = None, sev: Severity = Severity.WARNING,
                    retry_after: int | None = None) -> bytes:
        if sev is Severity.ALERT or (self._deny_log_key.allow(client or ip)
                                     and self._deny_log_all.allow("*")):
            await self._log(etype, {"reason": reason, "ip": ip, "client": client}, sev)
        elif self.metrics is not None:
            self.metrics.inc("gk_events_suppressed_total", type=getattr(etype, "value", etype))
        anomalies = self.anomalies
        if client is not None and anomalies is not None:
            await self._maybe_autofreeze(client, etype, ip, anomalies)
        extra = {"Retry-After": str(retry_after)} if retry_after else None
        return neutral_response(status, extra)

    async def _maybe_autofreeze(self, client: str, etype, ip: str,
                                anomalies: AnomalyMonitor) -> None:
        """Порог аномалий достигнут: замораживаем клиента (как `gatekeeper freeze`)."""
        # StateStore пишет в SQLite: не в потоке event loop.
        count = await asyncio.to_thread(anomalies.record, client, etype)
        if count is None or self.freeze_client is None:
            return
        try:
            await asyncio.to_thread(self.freeze_client, client)
        except Exception as exc:  # уже frozen/revoked или сбой реестра: не ломаем ответ
            await self._log("autofreeze_failed", {"client": client, "error": type(exc).__name__},
                            Severity.ALERT)
            return
        await self._log(EventType.CLIENT_FROZEN,
                        {"client": client, "auto": True, "trigger": getattr(etype, "value", str(etype)),
                         "count": count, "window": anomalies.window, "ip": ip}, Severity.ALERT)

    def _upstream_metric(self, provider: str, status: str, started: float) -> None:
        if self.metrics is not None:
            self.metrics.inc("gk_upstream_requests_total", provider=provider, status=status)
            self.metrics.observe("gk_upstream_seconds", time.monotonic() - started,
                                 provider=provider)

    def _needs_confirm(self, api_name: str, pname: str | None = None) -> bool:
        """Сравнение без учёта регистра: Telegram принимает имена методов в любом регистре,
        поэтому правило `POST:sendmessage` не должно обходить `[confirm] apis = ["sendMessage"]`."""
        name = api_name.casefold()
        pool = self.confirm_apis | self._provider_confirm.get(pname or self.default_provider, frozenset())
        return any(name == a.casefold() for a in pool)

    async def _confirm(self, cid: str, decision, req: ParsedRequest, ip: str) -> tuple[str | None, bytes | None]:
        """Опасный метод: (id подтверждения, None) если подтверждён, иначе (None, ответ-отказ).

        Тело разбирается как строгое JSON (дубли ключей и NaN запрещены), оператору
        показываются параметры, а не первые байты тела (C-04). Подтверждение расходуется
        здесь же; квота проверяется до этого вызова, поэтому отказ по бюджету его не съедает.
        """
        approvals = self.approvals
        if approvals is None:  # вызывается только при включённых подтверждениях
            raise RuntimeError("approvals are not configured")
        api = decision.api_name
        try:
            params = await asyncio.to_thread(parse_confirm_params, req.body)
            preview = await asyncio.to_thread(describe_params, params, self._all_secrets)
        except ConfirmBodyError as exc:
            return None, await self._deny(EventType.DENY_MALFORMED, 400, str(exc), ip, cid)
        res = await asyncio.to_thread(
            approvals.request, cid, decision.rule.http_method, api, req.body, preview, ip)
        if res.state == "approved":
            return res.id, None
        reason = {"new": f"confirm_new:{res.id}", "pending": f"confirm_pending:{res.id}",
                  "full": "confirm_queue_full"}[res.state]
        sev = Severity.ALERT if res.state in ("new", "full") else Severity.WARNING
        return None, await self._deny(EventType.DENY_CONFIRM_REQUIRED, 403, reason, ip, cid, sev)

    async def handle(self, req: ParsedRequest, ip: str, peer_der: bytes | None) -> bytes:
        rid = new_request_id()
        token = request_id.set(rid)
        started = time.monotonic()
        try:
            try:
                resp = await self._handle(req, ip, peer_der)
            except Exception as exc:  # fail closed; только тип ошибки, без текста
                with contextlib.suppress(Exception):
                    await self._log("internal_error", {"error": type(exc).__name__, "ip": ip},
                                    Severity.ALERT)
                resp = neutral_response(500)
            if self.metrics is not None:
                self.metrics.inc("gk_requests_total", status=resp[9:12].decode("ascii", "replace"))
                self.metrics.observe("gk_request_seconds", time.monotonic() - started)
            return stamp(resp, rid)
        finally:
            request_id.reset(token)

    async def _handle(self, req: ParsedRequest, ip: str, peer_der: bytes | None) -> bytes:
        ident = self.identity.identify(peer_der)
        if ident.fingerprint and self.decoy_check and self.decoy_check(ident.fingerprint):
            await asyncio.to_thread(self.bans.ban, ip, self.decoy_ban_seconds)
            await self._log(EventType.DECOY_TRIGGERED,
                            {"ip": ip, "fingerprint": ident.fingerprint}, Severity.ALERT)
            return neutral_response(403)
        rec = ident.record
        if rec is None:
            return await self._deny(EventType.DENY_UNKNOWN_CLIENT, 403, ident.reason, ip, ident.client_id)
        cid, h = rec.client_id, req.headers

        epoch, ts = _num(h.get(_H["epoch"])), _num(h.get(_H["time"]))
        nonce, sig = h.get(_H["nonce"]), h.get(_H["sig"])
        if h.get(_H["client"]) != cid or epoch is None or ts is None or nonce is None or sig is None:
            return await self._deny(EventType.DENY_BAD_SIGNATURE, 403, "bad_auth_headers", ip, cid)
        if epoch != 0:  # MVP: только эпоха 0, ротация в v2
            return await self._deny(EventType.DENY_BAD_SIGNATURE, 403, "bad_epoch", ip, cid)
        if not is_fresh(ts, self.clock()):
            return await self._deny(EventType.DENY_STALE_TIME, 403, "stale_time", ip, cid)
        try:
            canonical = build_canonical_string(
                client_id=cid, cert_fingerprint=rec.fingerprint, epoch=epoch, timestamp=ts,
                nonce=nonce, method=req.method, path=req.target, body=req.body)
            good = verify(derive_signing_key(rec.master_secret, epoch), canonical, sig)
        except SigningError:
            good = False
        if not good:
            return await self._deny(EventType.DENY_BAD_SIGNATURE, 403, "bad_signature", ip, cid)
        # StateStore пишет в SQLite: выносим из event loop (B-04).
        if not await asyncio.to_thread(self.nonces.check_and_add, cid, nonce):
            return await self._deny(EventType.DENY_REPLAY, 403, "replay_or_cache_full", ip, cid)

        decision = rec.policy.check(req.method, req.target)
        if decision is None:
            return await self._deny(EventType.DENY_POLICY, 403, "not_allowed", ip, cid)
        pname = rec.provider or self.default_provider
        provider, upstream = self.providers.get(pname), self.upstreams.get(pname)
        if provider is None or upstream is None:  # провайдер клиента не настроен на этом шлюзе
            return await self._deny(EventType.DENY_POLICY, 403, "provider_unavailable", ip, cid)
        if not self.client_limiter.allow(cid):
            return await self._deny(EventType.DENY_RATE_LIMIT, 429, "rate", ip, cid,
                                    retry_after=self.client_limiter.retry_after(cid))
        # Квоту проверяем ДО подтверждения, а тратим после: отказ по бюджету не должен
        # «съедать» одобрение оператора (и подтверждение не должно тратиться впустую).
        if not self.budget.can_spend(cid):
            return await self._deny(EventType.DENY_BUDGET, 429, "daily_budget", ip, cid,
                                    retry_after=self.budget.seconds_until_reset())
        confirmed = None
        if self.approvals is not None and self._needs_confirm(decision.api_name, pname):
            confirmed, refusal = await self._confirm(cid, decision, req, ip)
            if refusal is not None:
                return refusal
        if not await asyncio.to_thread(self.budget.try_spend, cid):
            return await self._deny(EventType.DENY_BUDGET, 429, "daily_budget", ip, cid,
                                    retry_after=self.budget.seconds_until_reset())

        api = decision.api_name
        try:
            up_req = provider.build_request(
                api, decision.rule.http_method, req.body, req.headers.get("content-type"))
        except ProviderError as exc:
            return await self._deny(EventType.DENY_MALFORMED, 400, str(exc), ip, cid)
        sem = self._inflight[pname]
        if sem.locked():  # изоляция: медленный провайдер не занимает все слоты шлюза
            return await self._deny(EventType.DENY_RATE_LIMIT, 503, "provider_busy", ip, cid,
                                    retry_after=1)
        # Намерение в журнал ДО upstream (C-07): при сбое записи действие не выполняется,
        # поэтому клиент может безопасно повторить запрос.
        intent: dict = {"client": cid, "api": api, "provider": pname, "ip": ip,
                        "method": req.method, "bytes": len(req.body),
                        "body_sha256": hashlib.sha256(req.body).hexdigest()}
        if confirmed:
            intent["confirmed"] = confirmed
        await self._log(EventType.REQUEST_INTENT, intent)
        t0 = time.monotonic()
        try:
            async with sem:
                timeout = provider.upstream_timeout(api, req.body)
                if timeout is None:
                    up_resp = await upstream.fetch(up_req)
                else:
                    up_resp = await upstream.fetch(up_req, timeout=timeout)
        except UpstreamError as exc:
            self._upstream_metric(pname, "error", t0)
            await self._log("upstream_error", {"reason": str(exc), "client": cid, "api": api,
                                               "provider": pname, "ip": ip}, Severity.WARNING)
            return neutral_response(502)
        self._upstream_metric(pname, str(up_resp.status), t0)
        # фильтр разбирает тело до нескольких МБ: не в потоке event loop
        safe = await asyncio.to_thread(provider.filter_response, up_resp)
        if safe is None:
            await self._log(EventType.RESPONSE_SECRET_BLOCKED,
                            {"client": cid, "api": api, "ip": ip}, Severity.ALERT)
            return neutral_response(502)
        status = safe.status if (200 <= safe.status < 300 or safe.status in _PASSTHROUGH) else 502
        await self._log(EventType.REQUEST_OK,
                        {"client": cid, "api": api, "provider": pname, "ip": ip, "status": status,
                         "bytes": len(safe.body),
                         **({"confirmed": confirmed} if confirmed else {})})
        try:
            return build_response(status, safe.body, safe.content_type)
        except ValueError:
            return neutral_response(502)
