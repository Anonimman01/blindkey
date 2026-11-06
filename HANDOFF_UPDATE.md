gatekeeper: актуальный статус (замена разделов 11 и 13 в HANDOFF.md)
Проверено чтением кода и README (архив + github.com/Anonimman01/blindkey), тесты не запускались.
Дата обновления: 2026-11-06.

Статус
Шаги 1-5 выполнены. Пункт 6 (v2) не начат.
Тесты у владельца (2026-11-05): python -m pytest -q, 346 passed за 42.34 с, без пропусков и падений. Запуск на Windows/WSL.
CI на GitHub: зелёный на коммитах be99046 (#5) и 95c553a (#4), ubuntu + windows, Python 3.13 и 3.14.

Выполнено
- Шаги 1-6 исходного плана (раздел 11): core, audit, pki, CLI (init, add-client, list-clients, audit-verify, decoy-create, run), mTLS-сервер, pipeline, провайдер telegram, upstream, config, app, клиент (Session, Transport, BotApi), приманки, интеграционные тесты (fake_telegram).
- Пункт 1: фильтр ответа. Блокировка только по точным секретам и полному шаблону токена \d+:[\w-]{30,}; остальные шаблоны redact только для журнала. Явный лимит глубины JSON (fail closed без RecursionError). Тесты у владельца прошли (314 passed).
- Пункт 2: замок журнала между процессами (FileSink.locked(), пересинхронизация хвоста в AuditChain.append, verify_file читает снимок под замком).
- Пункт 3: getUpdates (providers/telegram.py, client/botapi.py, README). Таймаут upstream = timeout запроса + запас; метод разрешается одному клиенту.
- Пункт 4: freeze / unfreeze / revoke / renew (cli/commands/client_status.py, renew.py, main.py, README). Действуют сразу, перезапуск шлюза не нужен. Сквозной тест «после revoke 403 без перезапуска» есть в tests/integration/test_end_to_end.py.
- Пункт 5: негативные TLS-тесты (tests/integration/test_tls_negative.py, 7 тестов), запись неудачных рукопожатий в журнал (DENY_TLS_HANDSHAKE в server/app.py), блокировка Registry (_locked в add/set_status/renew) и тест параллельных add, LICENSE и NOTICE в корне, SECURITY.md (private vulnerability reporting), docs/threat-model.md, deploy/gatekeeper.service, .gitignore, pyproject.toml (license, authors), CI (.github/workflows/ci.yml: ubuntu + windows, Python 3.13 и 3.14, requirements.lock с хэшами, actions на Node 24).
- Коммит be99046: исправлена модель угроз; policy: fullmatch для имени API (parse_rule и check); правки .gitignore.

Проверено на реальном сервере (2026-11-06)
- freeze / unfreeze / revoke: поведение совпало с ожидаемым (после freeze и revoke клиент получает 403, после unfreeze работа возобновляется), перезапуск шлюза не потребовался. Подтверждено владельцем вручную.
- Ручной сценарий check_gw.py хранится локально и в репозиторий не коммитится (в нём адрес сервера и локальный путь).

Пункт 6 (v2): не начат
Ни в архиве, ни в репозитории нет кода или заготовок v2. Состав:
- автозаморозка по аномалиям;
- подтверждение опасных действий;
- якоря журнала (сейчас удаление хвоста вместе с chain.head не обнаруживается);
- ротация ключей;
- провайдер bearer;
- очереди getUpdates на стороне шлюза.

Не проверено
- deploy/gatekeeper.service под systemd (запуск, Restart=on-failure, права EnvironmentFile 0600). Живая проверка выше шла отдельно от unit-файла.

Перед стартом v2
- Тесты на завершающий \n и \r в tests/unit/test_policy.py (имя API в check и правило в parse_rule). После добавления обновить число тестов в README.
- Тег v0.1.0 (в репозитории пока нет ни тегов, ни релизов).

Долги в документации
- Закрыто: строка про TLS-рукопожатия в docs/threat-model.md исправлена (коммит be99046).
- Закрыто: число тестов в README обновлено до «346 passed» и закоммичено.
- Файлов step2/step3/step4 *.patch в индексе git нет.
- Исходного HANDOFF.md в архиве нет, только HANDOFF_UPDATE.md.

Следующий шаг
Выбрать первый подпункт v2 или остановиться на пункте 5. Открытый вопрос: проект учебный или под реальную задачу? От ответа зависит, нужен ли v2. Если под реальную задачу, первыми разумно брать якоря журнала и автозаморозку.