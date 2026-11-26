"""Конфигурация шлюза из config.toml (tomllib). Неизвестные ключи = ошибка (опечатки опасны)."""
from __future__ import annotations

import ipaddress
import math
import tomllib
from dataclasses import dataclass, fields
from pathlib import Path

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.server.policy import is_valid_api_name
from gatekeeper.server.providers import KNOWN_PROVIDERS


class ConfigError(GatekeeperError):
    """Ошибка конфигурации."""


# Верхние границы: опечатка в конфиге не должна выключать защиту или разрешать OOM.
_MAX_BODY_BYTES = 16 * 1024 * 1024
_MAX_CONNECTIONS = 100_000
_MAX_BURST = 1_000_000
_MAX_DAILY_BUDGET = 100_000_000
_MAX_TIMEOUT = 3600.0
_MAX_RATE = 100_000.0
_MIN_AUDIT_BYTES = 1024 * 1024
_MAX_AUDIT_BYTES = 4 * 1024 * 1024 * 1024  # 4 ГиБ: журнал и суммарный объём ответов
_MAX_AUDIT_KEEP = 10_000


def _is_loopback_host(host: str | None) -> bool:
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class ProviderCfg:
    """Один провайдер upstream: у каждого свой секрет и (для тестов) свой адрес."""
    name: str
    secret_env: str | None = None
    secret_file: str | None = None
    upstream_host: str | None = None
    upstream_port: int = 443
    upstream_tls: bool = True
    confirm_apis: tuple[str, ...] = ()       # к общему [confirm] apis добавляются методы провайдера
    max_response_bytes: int = 21_000_000     # потолок размера ответа upstream (память на фильтр)
    max_inflight: int = 32                   # одновременных запросов к upstream этого провайдера


_PROVIDER_KEYS = {"secret_env": str, "secret_file": str, "upstream_host": str,
                  "upstream_port": int, "upstream_tls": bool, "confirm_apis": list,
                  "max_response_bytes": int, "max_inflight": int}
_MIN_RESPONSE, _MAX_RESPONSE, _MAX_INFLIGHT = 1024, 64 * 1024 * 1024, 1000


@dataclass(frozen=True)
class Config:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8443
    # Unix-сокет для /healthz и /metrics (None = выключено). Только локально, права 0600.
    metrics_socket: str | None = None
    # Хранить nonce, суточный бюджет, баны и счётчики аномалий в SQLite (переживают рестарт).
    persist_state: bool = True
    # PRAGMA synchronous для state.db: "normal" (по умолчанию, быстрее) или "full" (fsync
    # каждой транзакции). Журнал аудита пишется с fsync в обоих режимах.
    state_synchronous: str = "normal"
    provider: str = "telegram"
    secret_env: str | None = "GATEKEEPER_UPSTREAM_TOKEN"
    secret_file: str | None = None
    # Только для тестов с fake_telegram: переопределение адреса upstream.
    upstream_host: str | None = None
    upstream_port: int = 443
    upstream_tls: bool = True
    max_connections: int = 100
    max_per_ip: int = 10
    # Сколько одновременных TLS-рукопожатий допускается с одного IP (слот берётся до start_tls).
    max_handshaking_per_ip: int = 3
    # Ротация журнала: 0 = выключена (журнал растёт без границ).
    audit_max_bytes: int = 64 * 1024 * 1024
    audit_keep: int = 10  # сколько прошлых сегментов журнала хранить
    # Хук архивации закрытого сегмента: команда и аргументы списком (без shell).
    # Пусто = выключено; ошибка хука не останавливает шлюз, а пишется событием.
    audit_archive_command: tuple[str, ...] = ()
    # Автоматический якорь: раз в anchor_interval секунд дописать голову цепочки в
    # anchor_file. Пусто = выключено. Файл должен лежать ВНЕ каталога данных шлюза,
    # иначе взломщик с правом записи перепишет и его (это задача оператора).
    audit_anchor_file: str | None = None
    audit_anchor_interval: int = 3600
    # Общий потолок байт, которые одновременно буферизуются для ответов upstream (C-14).
    max_total_response_bytes: int = 256 * 1024 * 1024
    rate_per_sec: float = 5.0
    burst: int = 10
    daily_budget: int = 10000
    max_body_bytes: int = 1_048_576
    # Отдельный, меньший потолок тела для JSON-маршрутов: разбор JSON дорог по памяти.
    max_json_body_bytes: int = 262_144
    decoy_ban_seconds: int = 3600
    header_timeout: float = 10.0
    body_timeout: float = 30.0
    # Автозаморозка: 0 = выключена. Иначе N отказов (подпись/повтор/политика) за T секунд.
    autofreeze_threshold: int = 0
    autofreeze_window: int = 60
    # Подтверждение опасных действий: методы API, которые выполняются только после
    # `gatekeeper approve`. Пусто = выключено. ttl: сколько секунд живёт заявка/подтверждение.
    confirm_apis: tuple[str, ...] = ()
    confirm_ttl: int = 300
    # Подписанные одобрения (B1): одобрять может только владелец ключа оператора.
    # По умолчанию выключено: старое поведение не меняется.
    confirm_require_signed: bool = False
    confirm_operator_key: str | None = None  # путь к PEM-файлу публичного ключа Ed25519
    # Несколько провайдеров на одном шлюзе: таблицы [providers.<имя>]. Пусто = один провайдер
    # из [provider] (прежний формат).
    providers: tuple[ProviderCfg, ...] = ()
    # Провайдер для клиентов без поля provider. Не задан = первый в конфиге; при нескольких
    # провайдерах такие клиенты запрещены, пока default_provider не указан явно.
    default_provider: str | None = None

    def effective_providers(self) -> tuple[ProviderCfg, ...]:
        """Список провайдеров шлюза; первый используется для клиентов без поля provider."""
        if self.providers:
            return self.providers
        return (ProviderCfg(self.provider, self.secret_env, self.secret_file,
                            self.upstream_host, self.upstream_port, self.upstream_tls),)


_SCHEMA: dict[str, dict[str, type]] = {
    "server": {"listen_host": str, "listen_port": int, "metrics_socket": str,
               "persist_state": bool, "default_provider": str,
               "audit_max_bytes": int, "audit_keep": int, "max_total_response_bytes": int},
    "provider": {
        "name": str, "secret_env": str, "secret_file": str,
        "upstream_host": str, "upstream_port": int, "upstream_tls": bool,
    },
    "limits": {
        "max_connections": int, "max_per_ip": int, "max_handshaking_per_ip": int,
        "rate_per_sec": float, "burst": int,
        "daily_budget": int, "max_body_bytes": int, "max_json_body_bytes": int,
        "decoy_ban_seconds": int,
        "header_timeout": float, "body_timeout": float,
    },
    "anomaly": {"autofreeze_threshold": int, "autofreeze_window": int},
    "confirm": {"apis": list, "ttl": int, "require_signed_approvals": bool,
                "operator_public_key": str},
    "state": {"synchronous": str},
    "audit": {"archive_command": list, "anchor_file": str, "anchor_interval": int},
}
# (секция, ключ) -> поле Config, если имя отличается от ключа
_FIELD = {("provider", "name"): "provider", ("confirm", "apis"): "confirm_apis",
          ("confirm", "ttl"): "confirm_ttl",
          ("confirm", "require_signed_approvals"): "confirm_require_signed",
          ("confirm", "operator_public_key"): "confirm_operator_key",
          ("state", "synchronous"): "state_synchronous",
          ("audit", "archive_command"): "audit_archive_command",
          ("audit", "anchor_file"): "audit_anchor_file",
          ("audit", "anchor_interval"): "audit_anchor_interval"}
_SYNCHRONOUS = ("normal", "full")


def _check_type(section: str, key: str, value: object, typ: type) -> object:
    if typ is list:
        if isinstance(value, list) and all(isinstance(x, str) for x in value):
            return tuple(value)
        ok = False
    elif typ is float:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return float(value)
        ok = False
    elif typ is int:
        ok = isinstance(value, int) and not isinstance(value, bool)
    else:
        ok = isinstance(value, typ)
    if not ok:
        raise ConfigError(f"[{section}] {key}: expected {typ.__name__}")
    return value


def _parse_providers(raw: object, *, has_single: bool) -> tuple[ProviderCfg, ...]:
    """[providers.telegram], [providers.github]: порядок в файле = приоритет по умолчанию."""
    if raw is None:
        return ()
    if has_single:
        raise ConfigError("use either [provider] or [providers.<name>], not both")
    if not isinstance(raw, dict) or not raw:
        raise ConfigError("[providers] must contain at least one table")
    out: list[ProviderCfg] = []
    for name, sec in raw.items():
        if name not in KNOWN_PROVIDERS:
            raise ConfigError(f"[providers.{name}]: unknown provider (known: {list(KNOWN_PROVIDERS)})")
        if not isinstance(sec, dict):
            raise ConfigError(f"[providers.{name}] must be a table")
        extra = set(sec) - set(_PROVIDER_KEYS)
        if extra:
            raise ConfigError(f"[providers.{name}] unknown key(s): {sorted(extra)}")
        vals = {k: _check_type(f"providers.{name}", k, sec[k], t)
                for k, t in _PROVIDER_KEYS.items() if k in sec}
        if "secret_env" not in vals and "secret_file" not in vals:
            vals["secret_env"] = f"GATEKEEPER_{name.upper()}_TOKEN"
        out.append(ProviderCfg(name, **vals))  # type: ignore[arg-type]
    return tuple(out)


def _build(flat: dict[str, object]) -> Config:
    """Config(**flat) с проверкой имён: типы значений уже проверены в _check_type."""
    names = {f.name for f in fields(Config)}
    if not set(flat) <= names:
        raise ConfigError("internal: unknown config field")
    return Config(**flat)  # type: ignore[arg-type]


def load_config(path: str | Path) -> Config:
    try:
        doc = tomllib.loads(Path(path).read_text("utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"config not found: {path}") from exc
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError("config is not valid TOML") from exc
    providers = _parse_providers(doc.pop("providers", None), has_single=bool(doc.get("provider")))
    unknown = set(doc) - set(_SCHEMA)
    if unknown:
        raise ConfigError(f"unknown section(s): {sorted(unknown)}")
    flat: dict[str, object] = {}
    for section, keys in _SCHEMA.items():
        sec = doc.get(section, {})
        if not isinstance(sec, dict):
            raise ConfigError(f"[{section}] must be a table")
        extra = set(sec) - set(keys)
        if extra:
            raise ConfigError(f"[{section}] unknown key(s): {sorted(extra)}")
        for key, typ in keys.items():
            if key in sec:
                flat[_FIELD.get((section, key), key)] = _check_type(section, key, sec[key], typ)
    if providers:
        flat["providers"] = providers
    cfg = _build(flat)
    if not 1 <= cfg.listen_port <= 65535 or not 1 <= cfg.upstream_port <= 65535:
        raise ConfigError("port out of range")
    for name in ("rate_per_sec", "header_timeout", "body_timeout"):
        if not math.isfinite(getattr(cfg, name)):
            raise ConfigError(f"{name} must be a finite number")
    upper = {"max_connections": _MAX_CONNECTIONS, "max_per_ip": _MAX_CONNECTIONS,
             "max_handshaking_per_ip": _MAX_CONNECTIONS,
             "burst": _MAX_BURST, "daily_budget": _MAX_DAILY_BUDGET,
             "max_body_bytes": _MAX_BODY_BYTES, "max_json_body_bytes": _MAX_BODY_BYTES}
    for name, high in upper.items():
        if not 1 <= getattr(cfg, name) <= high:
            raise ConfigError(f"{name} must be between 1 and {high}")
    # max_json_body_bytes больше max_body_bytes — не ошибка: старый конфиг с малым общим
    # потолком должен продолжать работать. Эффективный потолок JSON = min (см. http_io).
    if not 0 < cfg.header_timeout <= _MAX_TIMEOUT or not 0 < cfg.body_timeout <= _MAX_TIMEOUT:
        raise ConfigError(f"timeouts must be in (0, {_MAX_TIMEOUT:g}] seconds")
    if not 0 < cfg.rate_per_sec <= _MAX_RATE:
        raise ConfigError(f"rate_per_sec must be in (0, {_MAX_RATE:g}]")
    if cfg.audit_max_bytes != 0 and not (
            _MIN_AUDIT_BYTES <= cfg.audit_max_bytes <= _MAX_AUDIT_BYTES):
        raise ConfigError(
            f"audit_max_bytes must be 0 (no rotation) or between {_MIN_AUDIT_BYTES} "
            f"and {_MAX_AUDIT_BYTES}")
    if not 1 <= cfg.audit_keep <= _MAX_AUDIT_KEEP:
        raise ConfigError(f"audit_keep must be between 1 and {_MAX_AUDIT_KEEP}")
    if not _MIN_AUDIT_BYTES <= cfg.max_total_response_bytes <= _MAX_AUDIT_BYTES:
        raise ConfigError(
            f"max_total_response_bytes must be between {_MIN_AUDIT_BYTES} "
            f"and {_MAX_AUDIT_BYTES}")
    if cfg.max_total_response_bytes < max(
            pc.max_response_bytes for pc in cfg.effective_providers()):
        raise ConfigError(
            "max_total_response_bytes must not be smaller than a provider's max_response_bytes")
    if cfg.decoy_ban_seconds < 0:
        raise ConfigError("decoy_ban_seconds must be >= 0")
    if cfg.autofreeze_threshold < 0 or cfg.autofreeze_window <= 0:
        raise ConfigError("autofreeze_threshold must be >= 0 and autofreeze_window > 0")
    names = [pc.name for pc in cfg.effective_providers()]
    if cfg.default_provider is not None and cfg.default_provider not in names:
        raise ConfigError(f"default_provider {cfg.default_provider!r} is not a configured provider")
    for pc in cfg.effective_providers():
        if not _MIN_RESPONSE <= pc.max_response_bytes <= _MAX_RESPONSE:
            raise ConfigError(f"[providers.{pc.name}] max_response_bytes must be between "
                              f"{_MIN_RESPONSE} and {_MAX_RESPONSE}")
        if not 1 <= pc.max_inflight <= _MAX_INFLIGHT:
            raise ConfigError(f"[providers.{pc.name}] max_inflight must be between 1 and {_MAX_INFLIGHT}")
        if not all(is_valid_api_name(a) for a in pc.confirm_apis):
            raise ConfigError(f"[providers.{pc.name}] confirm_apis contains an invalid API name")
        if not 1 <= pc.upstream_port <= 65535:
            raise ConfigError("port out of range")
        if not pc.upstream_tls and not _is_loopback_host(pc.upstream_host):
            # без TLS токен ушёл бы по сети открытым текстом; для тестов хватает loopback
            raise ConfigError("upstream_tls=false is allowed only with a loopback upstream_host")
    if not all(is_valid_api_name(a) for a in cfg.confirm_apis):
        raise ConfigError("[confirm] apis: invalid api name")
    if not 1 <= cfg.confirm_ttl <= 86400:
        raise ConfigError("[confirm] ttl must be between 1 and 86400")
    if cfg.confirm_require_signed and not cfg.confirm_operator_key:
        raise ConfigError("[confirm] require_signed_approvals needs operator_public_key")
    if cfg.state_synchronous not in _SYNCHRONOUS:
        raise ConfigError(f"[state] synchronous must be one of {list(_SYNCHRONOUS)}")
    if cfg.audit_archive_command:
        if len(cfg.audit_archive_command) > 64:
            raise ConfigError("[audit] archive_command: too many arguments (max 64)")
        if not all(isinstance(a, str) and a and len(a) <= 4096
                   for a in cfg.audit_archive_command):
            raise ConfigError("[audit] archive_command: every argument must be a non-empty string")
    if cfg.audit_anchor_file is not None and not cfg.audit_anchor_file:
        raise ConfigError("[audit] anchor_file must not be empty")
    if not 60 <= cfg.audit_anchor_interval <= 7 * 86400:
        raise ConfigError("[audit] anchor_interval must be between 60 and 604800 seconds")
    return cfg
