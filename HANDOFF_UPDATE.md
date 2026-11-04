# gatekeeper: актуальный статус (замена разделов 11 и 13 в HANDOFF.md)

Проверено чтением кода, тесты не запускались.

## Статус
Шаги 1-6 из раздела 11 выполнены: core, audit, pki, CLI (init, add-client, list-clients,
audit-verify, decoy-create, run), mTLS-сервер, pipeline, провайдер telegram, upstream,
config, app, клиент (Session, Transport, BotApi), приманки, интеграционные тесты
(fake_telegram). README заявляет 293 passed, 2 skipped. Нужна проверка на стороне владельца.

## Выполнено после этого обзора
- Пункт 1 (фильтр ответа): сделан, тесты у владельца прошли (314 passed).
- Пункт 2 (замок журнала): сделан, ждёт прогона тестов у владельца. FileSink.locked(), пересинхронизация
  хвоста в AuditChain.append, verify_file читает снимок под замком.

## Обновление от 2026-11-04 (чтение кода и README, тесты не запускались)
- Пункт 3 (getUpdates): в коде есть (providers/telegram.py, client/botapi.py, README). Тесты у владельца: не подтверждено.
- Пункт 4 (freeze / unfreeze / revoke / renew): в коде есть (cli/commands/client_status.py, renew.py, main.py, README).
  Сквозной тест «после revoke 403 без перезапуска»: проверить, есть ли в tests/integration/test_end_to_end.py.
- Пункт 5, часть без кода сделана: .gitignore, deploy/gatekeeper.service (не проверен на сервере),
  SECURITY.md (в нём TODO: контакт), docs/threat-model.md.
- Пункт 5, осталось: негативные тесты (просроченный и отозванный сертификат, верный сертификат с чужой подписью
  и наоборот, откат на TLS 1.2), запись неудачных TLS-рукопожатий в журнал, LICENSE, CI, блокировка в Registry._save.
- Файлы step2/step3/step4 *.patch уже применены, их можно удалить.
- Исходного HANDOFF.md в этом архиве нет, только HANDOFF_UPDATE.md.

## Обновление от 2026-11-04 (вечер, тесты не запускались)
- Негативные TLS-тесты уже были: tests/integration/test_tls_negative.py (7 тестов) + revoke в test_end_to_end.py.
- Запись неудачных рукопожатий в журнал уже есть (DENY_TLS_HANDSHAKE в server/app.py).
- Блокировка Registry уже есть (_locked в add/set_status/renew); добавлен тест параллельных add.
- LICENSE, NOTICE перенесены в корень, SECURITY.md без TODO (private vulnerability reporting),
  pyproject.toml с license/authors. Папка lic/ удалена.
- Добавлен .github/workflows/ci.yml (ubuntu + windows, Python 3.13 и 3.14, requirements.lock с хэшами).
- Пункт 5 закрыт при условии зелёного pytest и CI. Дальше: пункт 6 (v2) или остановка (вопрос учебный/реальный).

## Найденные проблемы (по убыванию важности; пункты 1-4 ниже уже закрыты, список исторический)
1. Фильтр ответа (providers/telegram.py: filter_response) использует шаблоны redact.
   Блокирует нормальный текст: `/bothelp` (шаблон `(?<=/bot)...`), «Bearer authentication».
   Следствия: 502 после реально доставленного sendMessage (дубли при повторе), «отравленный»
   апдейт блокирует весь getUpdates.
   Исправление: блокировать только по точным секретам (токен, его части, JSON-экранирование)
   и полному шаблону токена `\d+:[\w-]{30,}`; остальные шаблоны только для журнала.
2. Журнал не безопасен между процессами. Сервер держит _next_seq/_last_hash в памяти,
   add-client и decoy-create пишут своим AuditChain. Итог: ложная «подмена» в audit-verify
   и отказ шлюза стартовать (verify_on_open).
   Исправление: межпроцессная блокировка + пересинхронизация хвоста журнала под замком.
   Делать до новых команд CLI, пишущих в журнал.
3. Нет getUpdates: таймауты upstream и клиента по 30 с рвут long polling.
   MVP-вариант: таймаут upstream = параметр timeout запроса + запас, BotApi.get_updates(),
   getUpdates разрешать одному клиенту. Опрос на стороне шлюза с очередями это v2.
4. Нет freeze/unfreeze/revoke/renew (Registry.set_status и события CLIENT_FROZEN/REVOKED
   уже есть, но не используются). Сертификат 90 дней, продлить или удалить клиента нельзя.
5. Мелочи: нет .gitignore (в архиве .venv и .pytest_cache), LICENSE, SECURITY.md,
   docs/threat-model, deploy/gatekeeper.service, CI. Нет сквозных тестов: просроченный и
   отозванный сертификат, верный сертификат с чужой подписью. Неудачные TLS-рукопожатия
   не пишутся в журнал. Registry._save без блокировки.

## Порядок работ (один пункт = один небольшой шаг)
1. Фильтр ответа + тесты (`/bothelp`, «Bearer authentication», токен в теле).
2. Блокировка журнала между процессами + тест с двумя AuditChain.
3. getUpdates (минимальный вариант).
4. freeze / unfreeze / revoke / renew + сквозной тест «после revoke 403 без перезапуска».
5. Недостающие негативные тесты, .gitignore, systemd-юнит, SECURITY.md, threat-model.
6. v2: автозаморозка, подтверждения, якоря журнала, ротация ключей, провайдер bearer.

## Открытый вопрос
Проект учебный или под реальную задачу? От ответа зависит, останавливаться ли на пункте 5.

## Следующий шаг
Пункт 5: негативные сквозные тесты (сертификаты и TLS), затем запись неудачных рукопожатий в журнал.
Сначала владелец прогоняет pytest на текущем состоянии (после пунктов 2-4) и присылает итог.
