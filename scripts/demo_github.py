"""Демо: клиент ходит к шлюзу, настоящего токена у него нет."""
import json
import os
import sys

from gatekeeper.client.session import Session
from gatekeeper.client.transport import Transport

bundle, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])


def show(title: str, resp) -> None:
    print(f"{title:<42} -> HTTP {resp.status}")


# 1. легитимный запрос
t = Transport(Session(bundle), host, port)
r = t.request("GET", "/getUser")
show("GET /getUser (в белом списке)", r)
if r.status == 200:
    try:
        print("   login:", json.loads(r.body).get("login"))
    except ValueError:
        pass

# 2. ещё один разрешённый метод
show("GET /getRateLimit (в белом списке)", t.request("GET", "/getRateLimit"))

# 3. неверная подпись: ключ подписи подменён случайным
bad = Session(bundle)
bad._key = os.urandom(len(bad._key))
show("GET /getUser, неверная подпись", Transport(bad, host, port).request("GET", "/getUser"))

# 4. метод вне белого списка (правило есть у провайдера, у клиента нет)
show("GET /listRepos (нет в белом списке)", t.request("GET", "/listRepos"))