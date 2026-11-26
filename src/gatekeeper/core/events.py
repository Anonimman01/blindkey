"""Типы событий безопасности: общий язык для журнала, аномалий и подтверждений."""
from __future__ import annotations

from enum import StrEnum


class EventType(StrEnum):
    # Запрос принят
    REQUEST_OK = "request_ok"
    # Намерение выполнить запрос: пишется ДО обращения к upstream (C-07). Если запись не
    # удалась, запрос не уходит провайдеру и клиент получает ошибку, которую можно повторить.
    REQUEST_INTENT = "request_intent"
    # Итог намерения, которое НЕ было выполнено: отказ после записи `request_intent`
    # (например, подтверждение успел израсходовать параллельный запрос). Нужен, чтобы
    # журнал читался однозначно: «намерение без `request_ok`» больше не означает
    # «возможно выполнено». В `data` всегда есть `executed: false` и причина.
    REQUEST_ABORTED = "request_aborted"
    # Действие на upstream выполнено, но запись результата в журнал не удалась
    # (ограниченный повтор не помог). В `data` всегда есть `executed: true`.
    REQUEST_UNLOGGED = "request_unlogged"
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
    DENY_CONFIRM_REQUIRED = "deny_confirm_required"  # опасный метод ждёт подтверждения
    # Тревоги
    DECOY_TRIGGERED = "decoy_triggered"
    # Nonce-кэш заполнен на 80% и больше: исчерпание ёмкости отвергнет новые запросы.
    NONCE_CACHE_HIGH_WATER = "nonce_cache_high_water"
    RESPONSE_SECRET_BLOCKED = "response_secret_blocked"
    # Управление
    CLIENT_ADDED = "client_added"
    CLIENT_FROZEN = "client_frozen"
    CLIENT_UNFROZEN = "client_unfrozen"
    CLIENT_REVOKED = "client_revoked"
    CLIENT_RENEWED = "client_renewed"
    CLIENT_STATE_NOT_LOGGED = "client_state_not_logged"  # состояние изменено, журнал — нет
    CONFIRM_APPROVED = "confirm_approved"
    CONFIRM_REJECTED = "confirm_rejected"
    CONFIRM_ACTION_FAILED = "confirm_action_failed"  # действие не выполнено после записи
    REGISTRY_REKEYED = "registry_rekeyed"  # master_secret переведён на шифрование или обратно
    SERVER_STARTED = "server_started"
    SERVER_CERT_RENEWED = "server_cert_renewed"
    SERVER_CERT_EXPIRING = "server_cert_expiring"  # до истечения меньше 30 дней (или уже истёк)
    # Журнал
    AUDIT_TAIL_REPAIRED = "audit_tail_repaired"   # отрезана недописанная последняя строка
    AUDIT_SEGMENT_STARTED = "audit_segment_started"  # первая запись нового сегмента ротации


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    ALERT = "alert"
