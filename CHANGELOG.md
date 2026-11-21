# Changelog

Формат: [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/). Протокол не менялся.

## [Unreleased]

### Added
- Group commit журнала: один fsync на пачку одновременных записей.
- `state.db` (SQLite, WAL): nonce, суточный бюджет, баны и счётчики аномалий переживают перезапуск.
- `X-Request-Id` в каждом ответе и `rid` в записях журнала; `Date`, `Cache-Control: no-store`;
  `Retry-After` в ответах 429.
- `[server] metrics_socket`: `GET /healthz` и `GET /metrics` на Unix-сокете.
- `gatekeeper status`.
- Лимит nonce на клиента (один клиент не заполняет весь кэш), LRU-границы для лимитеров и банов.
- `py.typed`, `readme` и `[project.urls]` в pyproject, CI с матрицей 3.11–3.14, ruff, mypy, pip-audit, CodeQL, Dependabot.

### Changed
- `license` в pyproject: SPDX-строка; убран устаревший classifier.
- systemd-юнит: `MemoryDenyWriteExecute`, `ProtectProc`, `ProcSubset`, `StartLimitBurst`, `AF_UNIX`.
- mypy: 0 ошибок в `src`.

## [0.2.0]
