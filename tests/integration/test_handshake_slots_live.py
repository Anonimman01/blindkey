"""Живой шлюз: лишние полуготовые рукопожатия с одного IP закрываются, обычные клиенты живут."""
import socket
import time

from support import api

PER_IP = 3


def _fill_slots(gw, deadline: float) -> list[socket.socket]:
    """Держать PER_IP холостых соединений, пока шлюз не посчитает их все как слоты.

    Под нагрузкой часть соединений успевает сброситься до того, как обработчик возьмёт слот
    (в журнале это `deny_tls_handshake` с `ConnectionAbortedError`), поэтому набираем заново.
    """
    slots = gw.app._handshake_slots
    idle: list[socket.socket] = []
    while time.monotonic() < deadline:
        while len(idle) < PER_IP:
            idle.append(socket.create_connection(("127.0.0.1", gw.port), timeout=5))
        if slots._by_ip.get("127.0.0.1", 0) >= PER_IP:
            return idle
        for sock in idle:
            sock.close()
        idle = []
        time.sleep(0.05)
    for sock in idle:
        sock.close()
    raise AssertionError(f"gateway did not take {PER_IP} handshake slots: "
                         f"used={slots._used} by_ip={dict(slots._by_ip)}")


def test_extra_handshakes_from_one_ip_are_rejected(gw):
    idle = _fill_slots(gw, time.monotonic() + 15)
    try:
        extra = socket.create_connection(("127.0.0.1", gw.port), timeout=5)
        extra.settimeout(3)
        assert extra.recv(1) == b""  # соединение закрыто сразу, без ответа и без записи в журнал
        extra.close()
    finally:
        for sock in idle:
            sock.close()
    # Слоты освобождаются по закрытию соединения или по таймауту рукопожатия (5 с).
    deadline = time.monotonic() + 10
    while True:
        try:
            assert api(gw).get_me()["ok"] is True
            break
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.2)
