"""Вывод CLI. Секреты сюда не передаём: только идентификаторы, отпечатки, пути."""
from __future__ import annotations

import sys


def info(msg: str) -> None:
    print(msg)


def error(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
