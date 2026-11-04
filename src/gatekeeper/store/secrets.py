"""Секреты провайдеров: переменная окружения или файл (на POSIX права не шире 0600)."""
from __future__ import annotations

import os
import stat

from gatekeeper.core.errors import GatekeeperError


class SecretError(GatekeeperError):
    """Секрет не найден или хранится небезопасно (текст без значения секрета)."""


def load_secret(env_name: str | None, file_path: str | None) -> str:
    if env_name:
        value = os.environ.get(env_name, "").strip()
        if value:
            return value
    if file_path:
        try:
            st = os.stat(file_path)
            if os.name != "nt" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise SecretError("secret file must not be accessible to group/others (chmod 0400)")
            with open(file_path, "r", encoding="utf-8") as fh:
                value = fh.read().strip()
        except OSError as exc:
            raise SecretError("cannot read secret file") from exc
        if value:
            return value
    raise SecretError("upstream secret not found (env variable or secret_file)")
