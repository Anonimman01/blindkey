"""Типы событий безопасности: общий язык для журнала, аномалий и подтверждений."""
from __future__ import annotations

from enum import Enum


class EventType(str, Enum):
    # Запрос принят
    REQUEST_OK = "request_ok"
    # Отказы (причина только в журнале, клиенту ответ нейтральный)
    DENY_RATE_LIMIT = "deny_rate_limit"
    DENY_UNKNOWN_CLIENT = "deny_unknown_client"
    DENY_BAD_SIGNATURE = "deny_bad_signature"
    DENY_STALE_TIME = "deny_stale_time"
    DENY_REPLAY = "deny_replay"
    DENY_POLICY = "deny_policy"
    DENY_BUDGET = "deny_budget"
    DENY_MALFORMED = "deny_malformed"
    DENY_TLS_HANDSHAKE = "deny_tls_handshake"
    # Тревоги
    DECOY_TRIGGERED = "decoy_triggered"
    RESPONSE_SECRET_BLOCKED = "response_secret_blocked"
    # Управление
    CLIENT_ADDED = "client_added"
    CLIENT_FROZEN = "client_frozen"
    CLIENT_UNFROZEN = "client_unfrozen"
    CLIENT_REVOKED = "client_revoked"
    CLIENT_RENEWED = "client_renewed"
    SERVER_STARTED = "server_started"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ALERT = "alert"
