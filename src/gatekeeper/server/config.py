"""Конфигурация шлюза из config.toml (tomllib). Неизвестные ключи = ошибка (опечатки опасны)."""
from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, fields
from pathlib import Path

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.server.policy import is_valid_api_name


class ConfigError(GatekeeperError):
    """Ошибка конфигурации."""


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
class Config:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8443
    # Unix-сокет для /healthz и /metrics (None = выключено). Только локально, права 0600.
    metrics_socket: str | None = None
    # Хранить nonce, суточный бюджет, баны и счётчики аномалий в SQLite (переживают рестарт).
    persist_state: bool = True
    provider: str = "telegram"
    secret_env: str | None = "GATEKEEPER_UPSTREAM_TOKEN"
    secret_file: str | None = None
    # Только для тестов с fake_telegram: переопределение адреса upstream.
    upstream_host: str | None = None
    upstream_port: int = 443
    upstream_tls: bool = True
    max_connections: int = 100
    max_per_ip: int = 10
    rate_per_sec: float = 5.0
    burst: int = 10
    daily_budget: int = 10000
    max_body_bytes: int = 1_048_576
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


_SCHEMA: dict[str, dict[str, type]] = {
    "server": {"listen_host": str, "listen_port": int, "metrics_socket": str,
               "persist_state": bool},
    "provider": {
        "name": str, "secret_env": str, "secret_file": str,
        "upstream_host": str, "upstream_port": int, "upstream_tls": bool,
    },
    "limits": {
        "max_connections": int, "max_per_ip": int, "rate_per_sec": float, "burst": int,
        "daily_budget": int, "max_body_bytes": int, "decoy_ban_seconds": int,
        "header_timeout": float, "body_timeout": float,
    },
    "anomaly": {"autofreeze_threshold": int, "autofreeze_window": int},
    "confirm": {"apis": list, "ttl": int},
}
# (секция, ключ) -> поле Config, если имя отличается от ключа
_FIELD = {("provider", "name"): "provider", ("confirm", "apis"): "confirm_apis",
          ("confirm", "ttl"): "confirm_ttl"}


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
    cfg = _build(flat)
    if not 1 <= cfg.listen_port <= 65535 or not 1 <= cfg.upstream_port <= 65535:
        raise ConfigError("port out of range")
    for name in ("max_connections", "max_per_ip", "burst", "daily_budget", "max_body_bytes"):
        if getattr(cfg, name) <= 0:
            raise ConfigError(f"{name} must be positive")
    if cfg.header_timeout <= 0 or cfg.body_timeout <= 0:
        raise ConfigError("timeouts must be positive")
    if cfg.rate_per_sec <= 0 or cfg.decoy_ban_seconds < 0:
        raise ConfigError("invalid rate_per_sec or decoy_ban_seconds")
    if cfg.autofreeze_threshold < 0 or cfg.autofreeze_window <= 0:
        raise ConfigError("autofreeze_threshold must be >= 0 and autofreeze_window > 0")
    if not cfg.upstream_tls and not _is_loopback_host(cfg.upstream_host):
        # без TLS токен ушёл бы по сети открытым текстом; для тестов хватает loopback
        raise ConfigError("upstream_tls=false is allowed only with a loopback upstream_host")
    if not all(is_valid_api_name(a) for a in cfg.confirm_apis):
        raise ConfigError("[confirm] apis: invalid api name")
    if not 1 <= cfg.confirm_ttl <= 86400:
        raise ConfigError("[confirm] ttl must be between 1 and 86400")
    return cfg
