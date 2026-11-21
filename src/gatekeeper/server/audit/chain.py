"""Журнал с цепочкой хешей: hash_i = SHA256(hash_{i-1} || запись_i).

Каждая строка файла журнала это одна JSON-запись в каноническом виде:
    {"data":{...},"hash":"<hex>","prev":"<hex>","seq":N,"sev":"info","ts":T,"type":"..."}

Правка, удаление или перестановка записей ломает цепочку. Ограничение:
взломщик, имеющий доступ на запись к журналу и к chain.head, может переписать
всё целиком; от этого защищают внешние якоря (v2).
"""
from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from gatekeeper.core.errors import AuditError
from gatekeeper.core.events import EventType, Severity
from gatekeeper.core.redact import redact_obj
from gatekeeper.core.timeutil import unix_now
from gatekeeper.server.audit.sink import FileSink

GENESIS_HASH = "0" * 64
RECORD_KEYS = frozenset({"seq", "ts", "type", "sev", "data", "prev", "hash"})


def _dumps(obj: Any) -> bytes:
    try:
        return json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
        ).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise AuditError("record is not JSON-serializable") from exc


def canonical_body(seq: int, ts: int, event_type: str, sev: str, data: dict) -> bytes:
    """Часть записи, которая хешируется (всё, кроме prev и hash)."""
    return _dumps({"seq": seq, "ts": ts, "type": event_type, "sev": sev, "data": data})


def compute_hash(prev_hash: str, body: bytes) -> str:
    return hashlib.sha256(bytes.fromhex(prev_hash) + body).hexdigest()


def serialize_record(
    seq: int, ts: int, event_type: str, sev: str, data: dict, prev: str
) -> tuple[bytes, str]:
    """Вернуть (строка записи без перевода строки, hash записи)."""
    h = compute_hash(prev, canonical_body(seq, ts, event_type, sev, data))
    line = _dumps(
        {
            "seq": seq, "ts": ts, "type": event_type, "sev": sev,
            "data": data, "prev": prev, "hash": h,
        }
    )
    return line, h


class AuditChain:
    """Запись в журнал. Потокобезопасна и безопасна между процессами.

    Между процессами: запись идёт под файловым замком (FileSink.locked); внутри замка
    хвост журнала пересинхронизируется, чтобы подхватить записи, добавленные другими
    процессами (шлюз, add-client, decoy-create), и цепочка не раздваивалась.
    """

    def __init__(
        self,
        sink: FileSink,
        *,
        clock: Callable[[], int] = unix_now,
        verify_on_open: bool = True,
        secrets: tuple = (),
    ) -> None:
        from gatekeeper.server.audit.verify import verify_file  # избегаем цикла

        self._sink = sink
        self._clock = clock
        self._lock = threading.Lock()  # замок записи: один «лидер» сбрасывает пачку
        self._pending_lock = threading.Lock()
        self._pending: list[_Pending] = []
        self._secrets = tuple(secrets)  # известные секреты: маскируются в data
        self._next_seq = 0
        self._last_hash = GENESIS_HASH
        self._offset = 0  # сколько байт журнала уже учтено (проверено) этим процессом
        if verify_on_open:
            with sink.locked():
                # замок уже наш: verify_file не должен брать его второй раз
                res = verify_file(sink.path, sink.head_path, lock=False)
                if not res.ok:
                    raise AuditError(f"audit log failed verification: {res.error}")
                self._next_seq = res.last_seq + 1
                self._last_hash = res.last_hash
                self._offset = sink.size()

    @property
    def next_seq(self) -> int:
        return self._next_seq

    def _sync_tail(self) -> None:
        """Под замком: учесть записи других процессов (проверяя их цепочку)."""
        from gatekeeper.server.audit.verify import verify_lines  # избегаем цикла

        size = self._sink.size()
        if size == self._offset:
            return
        if size < self._offset:
            raise AuditError("audit log was truncated")
        data = self._sink.read_range(self._offset, size)
        if not data.endswith(b"\n"):
            raise AuditError("audit log ends with an incomplete line")
        res, _ = verify_lines(data.split(b"\n")[:-1], self._last_hash, self._next_seq)
        if not res.ok:
            raise AuditError(f"audit log failed verification: {res.error}")
        self._next_seq = res.last_seq + 1
        self._last_hash = res.last_hash
        self._offset = size

    def append(
        self,
        event_type: EventType | str,
        data: dict | None = None,
        severity: Severity | str = Severity.INFO,
    ) -> dict:
        """Добавить запись и вернуть {"seq", "hash"} после fsync.

        Group commit: запись ставится в очередь, а поток, который первым взял замок записи,
        сбрасывает на диск всю накопившуюся пачку одним write и одним fsync. Пока идёт fsync,
        остальные потоки копят записи, поэтому лишней задержки в простое нет, а под нагрузкой
        на пачку приходится один fsync. Каждый вызывающий возвращается только после fsync
        своей записи (durability не меняется).
        """
        etype = event_type.value if isinstance(event_type, EventType) else str(event_type)
        sev = severity.value if isinstance(severity, Severity) else str(severity)
        payload = {} if data is None else data
        if not isinstance(payload, dict):
            raise AuditError("data must be a dict")
        item = _Pending(etype, sev, redact_obj(payload, self._secrets))
        with self._pending_lock:
            self._pending.append(item)
        with self._lock:
            if not item.done:  # иначе нас уже записал другой поток в своей пачке
                self._flush()
        if item.error is not None:
            raise item.error
        assert item.result is not None
        return item.result

    def _flush(self) -> None:
        """Под self._lock: записать все ожидающие записи одной пачкой."""
        with self._pending_lock:
            batch, self._pending = self._pending, []
        if not batch:
            return
        try:
            with self._sink.locked():
                self._sync_tail()
                seq, prev = self._next_seq, self._last_hash
                lines: list[bytes] = []
                written: list[tuple[_Pending, dict]] = []
                for item in batch:
                    try:  # сбой сериализации одной записи не должен ронять всю пачку
                        line, h = serialize_record(
                            seq, self._clock(), item.etype, item.sev, item.data, prev)
                    except AuditError as exc:
                        item.error, item.done = exc, True
                        continue
                    lines.append(line)
                    written.append((item, {"seq": seq, "hash": h}))
                    seq, prev = seq + 1, h
                if lines:
                    self._sink.append_lines(lines)
                    self._sink.write_head(seq - 1, prev)
                    self._offset += sum(len(ln) + 1 for ln in lines)
                    self._next_seq, self._last_hash = seq, prev
            for item, res in written:
                item.result, item.done = res, True
        except BaseException as exc:
            for item in batch:
                if not item.done:
                    item.error, item.done = exc, True
            if not isinstance(exc, Exception):
                raise


@dataclass
class _Pending:
    etype: str
    sev: str
    data: dict
    result: dict | None = None
    error: BaseException | None = None
    done: bool = field(default=False)
