"""Политика клиента: белый список «МЕТОД:путь».

Главное свойство (защита от SSRF): путь к upstream берётся из правила,
а не из запроса клиента. Запрос клиента только выбирает правило, причём
точным сравнением строк после строгой проверки символов.
Любая неясность = отказ.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from gatekeeper.core.errors import PolicyError

ALLOWED_HTTP_METHODS = frozenset({"GET", "POST"})
# Имя метода API (Telegram: латиница и цифры, начинается с буквы).
_API_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
_MAX_TARGET_LEN = 128


def is_valid_api_name(name: object) -> bool:
    return isinstance(name, str) and _API_NAME_RE.fullmatch(name) is not None


@dataclass(frozen=True)
class Rule:
    http_method: str
    api_name: str

    def __str__(self) -> str:
        return f"{self.http_method}:{self.api_name}"


def parse_rule(text: object) -> Rule:
    """Разбирает "POST:sendMessage". Строго; при любой ошибке PolicyError."""
    if not isinstance(text, str):
        raise PolicyError("rule must be a string")
    method, sep, name = text.partition(":")
    if not sep or method not in ALLOWED_HTTP_METHODS:
        raise PolicyError("rule has unsupported method")
    if not _API_NAME_RE.fullmatch(name):
        raise PolicyError("rule has invalid api name")
    return Rule(method, name)


@dataclass(frozen=True)
class PolicyDecision:
    rule: Rule
    # Единственное, что провайдер использует для сборки URL upstream.
    api_name: str


class Policy:
    def __init__(self, rules: Iterable[Rule]):
        self._rules = frozenset(rules)
        # Индекс по (метод, имя). Имя сравнивается точно (с учётом регистра).
        self._index = {(r.http_method, r.api_name): r for r in self._rules}

    @classmethod
    def from_strings(cls, rules: object) -> "Policy":
        if not isinstance(rules, (list, tuple)):
            raise PolicyError("allow must be a list")
        return cls(parse_rule(r) for r in rules)

    @property
    def rules(self) -> frozenset[Rule]:
        return self._rules

    def check(self, http_method: object, target: object) -> PolicyDecision | None:
        """Возвращает решение, если запрос разрешён, иначе None.

        target: request-target как есть, ожидается "/<api_name>".
        Запрещено всё лишнее: query, фрагмент, процент-кодирование, точки,
        двойные слэши, вложенные пути, управляющие и не-ASCII символы.
        """
        if not isinstance(http_method, str) or not isinstance(target, str):
            return None
        if len(target) > _MAX_TARGET_LEN or not target.isascii():
            return None
        if not target.startswith("/"):
            return None
        name = target[1:]
        if not _API_NAME_RE.fullmatch(name):
            return None
        rule = self._index.get((http_method, name))
        if rule is None:
            return None
        return PolicyDecision(rule=rule, api_name=rule.api_name)
