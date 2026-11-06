"""Конвейер обработки запроса: дешёвое раньше дорогого, любая ошибка = отказ.

Порядок: решение по приманке -> идентификация -> заголовки -> время -> подпись ->
nonce -> политика -> лимиты -> upstream -> фильтр ответа. В журнал пишется всё,
включая отказы; клиенту уходит нейтральный ответ без причины.

Подписывается request-target как есть (например "/sendMessage") и HTTP-метод.
"""
from __future__ import annotations

import asyncio
from typing import Callable

from gatekeeper.core import constants
from gatekeeper.core.errors import SigningError
from gatekeeper.core.events import EventType, Severity
from gatekeeper.core.kdf import derive_signing_key
from gatekeeper.core.signing import build_canonical_string, verify
from gatekeeper.core.timeutil import is_fresh, unix_now
from gatekeeper.server.anomaly import AnomalyMonitor
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.http_io import ParsedRequest
from gatekeeper.server.http_response import build_response, neutral_response
from gatekeeper.server.identity import IdentityStore
from gatekeeper.server.limits import DailyBudget, IpBanList, RateLimiter
from gatekeeper.server.nonce_cache import NonceCache
from gatekeeper.server.providers.base import Provider, ProviderError
from gatekeeper.server.upstream import Upstream, UpstreamError

_H = {k: getattr(constants, f"HEADER_{k.upper()}").lower() for k in ("client", "epoch", "time", "nonce", "sig")}
_PASSTHROUGH = frozenset({400, 401, 403, 404, 409, 429, 500, 502, 503})


def _num(value: object) -> int | None:
    if isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 12:
        return int(value)
    return None


class Pipeline:
    def __init__(self, *, identity: IdentityStore, provider: Provider, upstream: Upstream,
                 audit: AuditChain, nonces: NonceCache, client_limiter: RateLimiter,
                 budget: DailyBudget, bans: IpBanList,
                 decoy_check: Callable[[str], bool] | None = None,
                 decoy_ban_seconds: int = 3600,
                 anomalies: AnomalyMonitor | None = None,
                 freeze_client: Callable[[str], None] | None = None,
                 clock: Callable[[], int] = unix_now) -> None:
        self.identity, self.provider, self.upstream, self.audit = identity, provider, upstream, audit
        self.nonces, self.client_limiter, self.budget, self.bans = nonces, client_limiter, budget, bans
        self.decoy_check, self.decoy_ban_seconds, self.clock = decoy_check, decoy_ban_seconds, clock
        self.anomalies, self.freeze_client = anomalies, freeze_client

    async def _log(self, etype, data: dict, sev: Severity = Severity.INFO) -> None:
        await asyncio.to_thread(self.audit.append, etype, data, sev)

    async def _deny(self, etype: EventType, status: int, reason: str, ip: str,
                    client: str | None = None, sev: Severity = Severity.WARNING) -> bytes:
        await self._log(etype, {"reason": reason, "ip": ip, "client": client}, sev)
        if client is not None and self.anomalies is not None:
            await self._maybe_autofreeze(client, etype, ip)
        return neutral_response(status)

    async def _maybe_autofreeze(self, client: str, etype, ip: str) -> None:
        """Порог аномалий достигнут: замораживаем клиента (как `gatekeeper freeze`)."""
        count = self.anomalies.record(client, etype)
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
                         "count": count, "window": self.anomalies.window, "ip": ip}, Severity.ALERT)

    async def handle(self, req: ParsedRequest, ip: str, peer_der: bytes | None) -> bytes:
        try:
            return await self._handle(req, ip, peer_der)
        except Exception as exc:  # fail closed; только тип ошибки, без текста
            try:
                await self._log("internal_error", {"error": type(exc).__name__, "ip": ip}, Severity.ALERT)
            except Exception:
                pass
            return neutral_response(500)

    async def _handle(self, req: ParsedRequest, ip: str, peer_der: bytes | None) -> bytes:
        ident = self.identity.identify(peer_der)
        if ident.fingerprint and self.decoy_check and self.decoy_check(ident.fingerprint):
            self.bans.ban(ip, self.decoy_ban_seconds)
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
        if not self.nonces.check_and_add(cid, nonce):  # только после проверки подписи
            return await self._deny(EventType.DENY_REPLAY, 403, "replay_or_cache_full", ip, cid)

        decision = rec.policy.check(req.method, req.target)
        if decision is None:
            return await self._deny(EventType.DENY_POLICY, 403, "not_allowed", ip, cid)
        if not self.client_limiter.allow(cid):
            return await self._deny(EventType.DENY_RATE_LIMIT, 429, "rate", ip, cid)
        if not self.budget.try_spend(cid):
            return await self._deny(EventType.DENY_BUDGET, 429, "daily_budget", ip, cid)

        api = decision.api_name
        try:
            up_req = self.provider.build_request(
                api, decision.rule.http_method, req.body, req.headers.get("content-type"))
        except ProviderError as exc:
            return await self._deny(EventType.DENY_MALFORMED, 400, str(exc), ip, cid)
        try:
            timeout = self.provider.upstream_timeout(api, req.body)
            if timeout is None:
                up_resp = await self.upstream.fetch(up_req)
            else:
                up_resp = await self.upstream.fetch(up_req, timeout=timeout)
        except UpstreamError as exc:
            await self._log("upstream_error", {"reason": str(exc), "client": cid, "api": api, "ip": ip},
                            Severity.WARNING)
            return neutral_response(502)
        safe = self.provider.filter_response(up_resp)
        if safe is None:
            await self._log(EventType.RESPONSE_SECRET_BLOCKED,
                            {"client": cid, "api": api, "ip": ip}, Severity.ALERT)
            return neutral_response(502)
        status = safe.status if (200 <= safe.status < 300 or safe.status in _PASSTHROUGH) else 502
        await self._log(EventType.REQUEST_OK,
                        {"client": cid, "api": api, "ip": ip, "status": status, "bytes": len(safe.body)})
        try:
            return build_response(status, safe.body, safe.content_type)
        except ValueError:
            return neutral_response(502)
