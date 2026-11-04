"""Пример: бот отправляет сообщение через шлюз. Токена Telegram у клиента нет.

Запуск:  python client_send_message.py <каталог_пакета> <адрес_шлюза> <chat_id> "текст"
Пакет (ca.pem, client.pem, client.key, master.secret) выдаёт `gatekeeper add-client`.
Адрес шлюза должен входить в --host, указанные при `gatekeeper init` (иначе проверка имени не пройдёт).
"""
import sys

from gatekeeper.client.botapi import BotApi, GatewayError

bundle, host, chat_id, text = sys.argv[1:5]
bot = BotApi(bundle, host, 8443)
try:
    print(bot.get_me()["result"]["username"])
    print(bot.send_message(int(chat_id), text)["result"]["message_id"])
except GatewayError as exc:
    # 403 = отказ шлюза (подпись, права, политика), 429 = лимиты, 502 = проблема на стороне Telegram.
    # Причину шлюз клиенту не сообщает: смотрите журнал на шлюзе.
    print(f"gateway refused: HTTP {exc.status}")
