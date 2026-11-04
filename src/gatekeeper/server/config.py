"""Конфигурация шлюза из config.toml (tomllib). Неизвестные ключи = ошибка (опечатки опасны)."""
from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from gatekeeper.core.errors import GatekeeperError


class ConfigError(GatekeeperError):
    """Ошибка конфигурации."""


@dataclass(frozen=True)
class Config:
    listen_host: str = "127.0.0.1"
    listen_port: int = 8443
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


_SCHEMA = {
    "server": {"listen_host": str, "listen_port": int},
    "provider": {
        "name": str, "secret_env": str, "secret_file": str,
        "upstream_host": str, "upstream_port": int, "upstream_tls": bool,
    },
    "limits": {
        "max_connections": int, "max_per_ip": int, "rate_per_sec": float, "burst": int,
        "daily_budget": int, "max_body_bytes": int, "decoy_ban_seconds": int,
        "header_timeout": float, "body_timeout": float,
    },
}


def _check_type(section: str, key: str, value: object, typ: type) -> object:
    if typ is float:
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    elif typ is int:
        ok = isinstance(value, int) and not isinstance(value, bool)
    else:
        ok = isinstance(value, typ)
    if not ok:
        raise ConfigError(f"[{section}] {key}: expected {typ.__name__}")
    return float(value) if typ is float else value


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
                flat["provider" if (section, key) == ("provider", "name") else key] = (
                    _check_type(section, key, sec[key], typ)
                )
    cfg = Config(**flat)
    if not 1 <= cfg.listen_port <= 65535 or not 1 <= cfg.upstream_port <= 65535:
        raise ConfigError("port out of range")
    for name in ("max_connections", "max_per_ip", "burst", "daily_budget", "max_body_bytes"):
        if getattr(cfg, name) <= 0:
            raise ConfigError(f"{name} must be positive")
    if cfg.header_timeout <= 0 or cfg.body_timeout <= 0:
        raise ConfigError("timeouts must be positive")
    if cfg.rate_per_sec <= 0 or cfg.decoy_ban_seconds < 0:
        raise ConfigError("invalid rate_per_sec or decoy_ban_seconds")
    return cfg
