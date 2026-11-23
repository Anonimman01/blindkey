"""Живой шлюз: лишние полуготовые рукопожатия с одного IP закрываются, обычные клиенты живут."""
import socket
import time

from support import api

PER_IP = 3


def _still_open(sock: socket.socket) -> bool:
    """Шлюз не закрыл холостое соединение (данных нет, но и EOF нет)."""
    sock.setblocking(False)
    try:
        return sock.recv(1, socket.MSG_PEEK) != b""
    except BlockingIOError:
        return True
    except OSError:
        return False
    finally:
        sock.setblocking(True)


def _fill_slots(gw, deadline: float) -> list[socket.socket]:
    """Держать PER_IP холостых соединений, которые шлюз принял и посчитал слотами.

    Нельзя проверять счётчик сразу после `connect()` (шлюз берёт слот позже, в своём потоке)
    и нельзя считать, что слоты свободны: стартовая проба фикстуры `gw` (connect и сразу close)
    может ещё держать слот, и тогда шлюз вправе отказать одному из наших соединений. Поэтому:
    держим соединения открытыми, выбрасываем те, что шлюз закрыл, и доливаем недостающие.
    """
    slots = gw.app._handshake_slots
    idle: list[socket.socket] = []
    while time.monotonic() < deadline:
        alive = []
        for sock in idle:
            if _still_open(sock):
                alive.append(sock)
            else:
                sock.close()
        idle = alive
        while len(idle) < PER_IP:
            idle.append(socket.create_connection(("127.0.0.1", gw.port), timeout=5))
        time.sleep(0.05)
        if slots._by_ip.get("127.0.0.1", 0) >= PER_IP and all(_still_open(s) for s in idle):
            return idle
    used, by_ip = slots._used, dict(slots._by_ip)
    for sock in idle:
        sock.close()
    raise AssertionError(f"gateway did not take {PER_IP} handshake slots: used={used} by_ip={by_ip}")


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
