# gatekeeper

Лёгкий API-шлюз для Telegram Bot API. Настоящий токен хранится только на шлюзе, боты
получают отзываемые сертификаты с белым списком методов. Шлюз проверяет подпись каждого
запроса, ведёт журнал с цепочкой хешей и ловит использование приманок.

## Установка

    python -m venv .venv
    pip install --require-hashes -r requirements.lock
    pip install -e .
    python -m pytest          # 293 passed, 2 skipped

## Запуск на сервере (Linux)

Боевой запуск только на Linux: на Windows права 0600/0700 не применяются, годится для разработки.

    useradd --system --create-home gatekeeper && su - gatekeeper
    export GATEKEEPER_CONFIG_DIR=$HOME/etc GATEKEEPER_DATA_DIR=$HOME/data

    # 1. CA и сертификат шлюза. --host: адреса, по которым к шлюзу ходят клиенты.
    gatekeeper init --host 203.0.113.10 --host gw.example.com --ca-key-out /safe/ca.key
    #    ca.key унесите офлайн: на шлюзе он не нужен.

    # 2. Клиент: пакет появится в --out, права только из --allow.
    gatekeeper add-client --id mybot --ca-key /safe/ca.key --out ./mybot-bundle \
        --allow GET:getMe --allow POST:sendMessage --allow POST:getFile --allow POST:downloadFile
    #    Передайте mybot-bundle на машину бота безопасным каналом. client.key и master.secret секретны.

    # 3. Токен бота и запуск.
    export GATEKEEPER_UPSTREAM_TOKEN='123456:ABC...'    # или secret_file в config.toml (0400)
    gatekeeper run                                      # настройки: examples/config.example.toml

Long polling: добавьте клиенту `--allow POST:getUpdates` (Telegram допускает одного потребителя
getUpdates на бота, выдавайте правило одному клиенту) и вызывайте `BotApi.get_updates(offset, timeout=30)`.
Шлюз держит запрос к Telegram `timeout` секунд (не больше 50) плюс 10 с запаса; каждый вызов тратит
дневной бюджет и лимит частоты клиента. Очереди на стороне шлюза: v2.

Управление клиентами (действует сразу, перезапуск шлюза не нужен):

    gatekeeper freeze   --id mybot      # временно заблокировать
    gatekeeper unfreeze --id mybot
    gatekeeper revoke   --id mybot      # навсегда; вернуть нельзя, выпустите нового клиента
    gatekeeper renew    --id mybot --ca-key /safe/ca.key --out ./mybot-bundle-new [--days 90]
    #    новый сертификат и ключ, права и статус сохраняются, старый пакет перестаёт работать сразу

Для systemd: `EnvironmentFile=` с файлом 0600, содержащим `GATEKEEPER_UPSTREAM_TOKEN=...`,
`User=gatekeeper`, `ExecStart=/путь/к/.venv/bin/gatekeeper run`, `Restart=on-failure`.

## Клиент

    from gatekeeper.client.botapi import BotApi
    bot = BotApi("./mybot-bundle", "gw.example.com", 8443)
    bot.send_message(chat_id, "привет")

Полный пример: `examples/client_send_message.py`. Скачивание файлов идёт через метод
`downloadFile` (правило `POST:downloadFile`): ссылки с токеном клиент не получает.

## Приманки

    gatekeeper decoy-create --name old-backup --ca-key /safe/ca.key --out ./decoy --hint "~/old/"

Положите `./decoy` туда, где вор будет искать секреты. Любой запрос с этим сертификатом даёт
запись `decoy_triggered` в журнале и бан IP на `decoy_ban_seconds`.

## Журнал

    gatekeeper audit-verify     # проверка цепочки хешей: правка, удаление или перестановка записей ломают её
    gatekeeper list-clients

Причины отказов (подпись, повтор, политика, лимиты, приманка) есть только в журнале; клиент
получает нейтральный ответ (403/429) без причины.

## Что клиенту не отдаётся

Токен бота, пути upstream, причины отказов. Ответ upstream с токеном блокируется (502) и
пишется как `response_secret_blocked`.

## Известные ограничения MVP

- Лимиты, nonce и баны хранятся в памяти и сбрасываются при перезапуске.
- Журнал можно писать из нескольких процессов (шлюз, add-client, decoy-create): запись идёт под
  файловым замком `audit.log.lock`, хвост журнала подхватывается под замком. Замок рекомендательный
  и на сетевых ФС (NFS) не гарантирован; запускайте один шлюз на один каталог данных.
- Тело запроса до 1 МБ по умолчанию (`max_body_bytes`); большие загрузки пока не поддерживаются.
- Бан приманки действует на IP целиком (и на настоящих клиентов с того же адреса).
- Неудачные TLS-рукопожатия в журнал не попадают.
- Удаление хвоста журнала вместе с `chain.head` не обнаруживается (нужны внешние якоря, v2).
- v2: автозаморозка по аномалиям, подтверждение опасных действий, ротация ключей, другие провайдеры.
