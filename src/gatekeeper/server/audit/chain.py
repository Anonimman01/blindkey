"""Журнал с цепочкой хешей: hash_i = SHA256(hash_{i-1} || запись_i).

Каждая строка файла журнала это одна JSON-запись в каноническом виде:
    {"data":{...},"hash":"<hex>","prev":"<hex>","seq":N,"sev":"info","ts":T,"type":"..."}

Правка, удаление или перестановка записей ломает цепочку. Ограничение:
взломщик, имеющий доступ на запись к журналу и к chain.head, может переписать
всё целиком; от этого защищают внешние якоря (v2).

Журнал ограничен по размеру: при `max_bytes > 0` запись ротируется (см. rotate.py), а
оборванная последняя строка при `repair_tail=True` отрезается с событием
`audit_tail_repaired` (см. repair.py). Ротация и починка идут под тем же файловым замком.
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
from gatekeeper.server.audit.repair import TailRepair, truncate_incomplete_tail
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
        repair_tail: bool = False,
        max_bytes: int = 0,
        keep: int = 10,
    ) -> None:
        from gatekeeper.server.audit.rotate import recover_pending_rotation
        from gatekeeper.server.audit.verify import verify_file  # избегаем цикла

        if max_bytes < 0:
            raise ValueError("max_bytes must be >= 0")
        if max_bytes > 0 and keep < 1:
            raise ValueError("keep must be >= 1 when rotation is enabled")
        self._sink = sink
        self._clock = clock
        self._lock = threading.Lock()  # замок записи: один «лидер» сбрасывает пачку
        self._pending_lock = threading.Lock()
        self._pending: list[_Pending] = []
        self._secrets = tuple(secrets)  # известные секреты: маскируются в data
        self._next_seq = 0
        self._last_hash = GENESIS_HASH
        self._offset = 0  # сколько байт журнала уже учтено (проверено) этим процессом
        self._inode: int | None = None  # идентичность файла: ротация подменяет inode
        self._repair_tail = bool(repair_tail)
        self._max_bytes = int(max_bytes)
        self._keep = int(keep)
        self._pending_repair: TailRepair | None = None
        if verify_on_open:
            with sink.locked():
                recover_pending_rotation(sink)  # подобрать сегмент после сбоя ротации
                # замок уже наш: verify_file не должен брать его второй раз
                res = verify_file(sink.path, sink.head_path, lock=False)
                if not res.ok and self._repair_tail and res.code == "incomplete_tail":
                    self._pending_repair = truncate_incomplete_tail(sink)
                    res = verify_file(sink.path, sink.head_path, lock=False)
                if not res.ok:
                    raise AuditError(f"audit log failed verification: {res.error}")
                self._next_seq = res.last_seq + 1
                self._last_hash = res.last_hash
                self._offset = sink.size()
                self._inode = self._inode_of()
        if self._pending_repair is not None:
            repair = self._pending_repair
            self._pending_repair = None
            self.append(EventType.AUDIT_TAIL_REPAIRED,
                        {"removed_bytes": repair.removed_bytes,
                         "removed_sha256": repair.removed_sha256},
                        Severity.WARNING)

    @property
    def next_seq(self) -> int:
        return self._next_seq

    def _inode_of(self) -> int | None:
        try:
            return self._sink.path.stat().st_ino
        except FileNotFoundError:
            return None

    def _reverify(self) -> None:
        """Под замком: перечитать журнал целиком (например, после ротации другим процессом)."""
        from gatekeeper.server.audit.verify import verify_file  # избегаем цикла

        res = verify_file(self._sink.path, self._sink.head_path, lock=False)
        if not res.ok:
            # Журнал стал короче без ротации: хвост удалён или файл переписан.
            raise AuditError(f"audit log was truncated or fails verification: {res.error}")
        self._next_seq = res.last_seq + 1
        self._last_hash = res.last_hash
        self._offset = self._sink.size()
        self._inode = self._inode_of()

    def _sync_tail(self) -> None:
        """Под замком: учесть записи других процессов (проверяя их цепочку)."""
        from gatekeeper.server.audit.verify import verify_lines  # избегаем цикла

        inode = self._inode_of()
        size = self._sink.size()
        if inode is None:
            if size == 0:
                return  # журнала ещё нет: первая запись создаст файл
            raise AuditError("audit log is missing")
        if self._inode is None:
            self._inode = inode  # журнал создан другим процессом после нашего открытия
        elif inode != self._inode:
            self._reverify()  # журнал ротирован другим процессом
            return
        if size == self._offset:
            return
        if size < self._offset:  # журнал укорочен или переписан
            self._reverify()
            return
        data = self._sink.read_range(self._offset, size)
        if not data.endswith(b"\n"):
            if not self._repair_tail:
                raise AuditError("audit log ends with an incomplete line")
            cut = data.rfind(b"\n") + 1
            if cut == 0:
                raise AuditError("audit log ends with an incomplete line")
            self._sink.truncate(self._offset + cut)
            removed = data[cut:]
            self._pending_repair = TailRepair(len(removed), hashlib.sha256(removed).hexdigest())
            data = data[:cut]
            size = self._offset + cut
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

    def _rotate_if_needed(self) -> None:
        """Под замком: сегмент перерос лимит — начать новый."""
        from gatekeeper.server.audit.rotate import rotate_audit_locked  # избегаем цикла

        if self._max_bytes <= 0 or self._sink.size() <= self._max_bytes:
            return
        seg = rotate_audit_locked(self._sink, keep=self._keep, clock=self._clock)
        self._next_seq, self._last_hash = seg.seq + 1, seg.hash
        self._offset = self._sink.size()
        self._inode = self._inode_of()

    def _flush(self) -> None:
        """Под self._lock: записать все ожидающие записи одной пачкой."""
        with self._pending_lock:
            batch, self._pending = self._pending, []
        if not batch:
            return
        try:
            with self._sink.locked():
                self._rotate_if_needed()
                self._sync_tail()
                if self._pending_repair is not None:
                    repair, self._pending_repair = self._pending_repair, None
                    batch.append(_Pending(
                        EventType.AUDIT_TAIL_REPAIRED.value, Severity.WARNING.value,
                        {"removed_bytes": repair.removed_bytes,
                         "removed_sha256": repair.removed_sha256}))
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
