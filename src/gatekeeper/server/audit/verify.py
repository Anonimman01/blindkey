"""Проверка целостности всей цепочки журнала (без сети, только чтение)."""
from __future__ import annotations

import json
import os
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Sequence

from gatekeeper.core.errors import AuditError
from gatekeeper.server.audit.anchor import Anchor, check_anchors
from gatekeeper.server.audit.chain import (
    GENESIS_HASH,
    RECORD_KEYS,
    canonical_body,
    compute_hash,
    serialize_record,
)
from gatekeeper.server.audit.sink import FileSink


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    count: int = 0
    last_seq: int = -1
    last_hash: str = GENESIS_HASH
    error: str | None = None
    line_no: int | None = None  # номер строки с первой ошибкой (с 1)
    head_checked: bool = False  # сверена ли голова из chain.head
    anchors_checked: int = 0  # сколько внешних якорей сошлось с журналом


def _fail(msg: str, line_no: int | None, count: int = 0, **kw) -> VerifyResult:
    return VerifyResult(ok=False, count=count, error=msg, line_no=line_no, **kw)


def verify_lines(
    lines: list[bytes], expected_prev: str = GENESIS_HASH, start_seq: int = 0
) -> tuple[VerifyResult, list[str]]:
    """Проверить список строк. Возвращает (результат, список хешей по порядку)."""
    prev = expected_prev
    hashes: list[str] = []
    for i, line in enumerate(lines):
        n = i + 1
        try:
            rec = json.loads(line.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return _fail("line is not valid JSON", n, i), hashes
        if not isinstance(rec, dict) or set(rec) != RECORD_KEYS:
            return _fail("record has wrong fields", n, i), hashes
        seq, ts, etype, sev = rec["seq"], rec["ts"], rec["type"], rec["sev"]
        data, rprev, rhash = rec["data"], rec["prev"], rec["hash"]
        if (
            isinstance(seq, bool) or not isinstance(seq, int)
            or isinstance(ts, bool) or not isinstance(ts, int)
            or not isinstance(etype, str) or not isinstance(sev, str)
            or not isinstance(data, dict)
            or not isinstance(rprev, str) or not isinstance(rhash, str)
        ):
            return _fail("record has wrong field types", n, i), hashes
        if seq != start_seq + i:
            return _fail("sequence number mismatch (record removed or reordered)", n, i), hashes
        if rprev != prev:
            return _fail("prev hash does not match previous record", n, i), hashes
        try:
            expected_hash = compute_hash(prev, canonical_body(seq, ts, etype, sev, data))
        except (ValueError, AuditError):
            return _fail("record cannot be hashed", n, i), hashes
        if rhash != expected_hash:
            return _fail("record hash mismatch (record was modified)", n, i), hashes
        canon_line, _ = serialize_record(seq, ts, etype, sev, data, prev)
        if canon_line != line:
            return _fail("record is not in canonical form", n, i), hashes
        prev = rhash
        hashes.append(rhash)
    last_seq = start_seq + len(lines) - 1 if lines else start_seq - 1
    return VerifyResult(True, len(lines), last_seq, prev), hashes


def verify_file(
    path: str | os.PathLike,
    head_path: str | os.PathLike | None = None,
    *,
    lock: bool = True,
    anchors: Sequence[Anchor] | None = None,
) -> VerifyResult:
    """Проверить файл журнала, голову из chain.head (если есть) и внешние якоря (если даны).

    lock=True: журнал и голова читаются одним снимком под замком, поэтому запись шлюза
    посреди проверки не даёт ложной «подмены». Замок только на чтение файлов; сама проверка
    идёт без замка и запись не блокирует. Если замок взять нельзя (нет прав на запись
    в каталог журнала), читаем без него, голову раньше журнала: журнал пишется первым,
    поэтому он всегда не короче головы. lock=False нужен вызывающему, который уже держит замок.
    """
    sink = FileSink(path, head_path)
    head_exc: AuditError | None = None
    head = None
    with sink.locked(required=False) if lock else nullcontext():
        try:
            head = sink.read_head()
        except AuditError as exc:
            head_exc = exc
        data = sink.read_bytes()
    if data and not data.endswith(b"\n"):
        return _fail("log ends with an incomplete line", len(data.split(b"\n")))
    lines = data.split(b"\n")[:-1] if data else []
    result, hashes = verify_lines(lines)
    if not result.ok:
        return result
    if head_exc is not None:
        return _fail(str(head_exc), None, result.count)
    head_checked = False
    if head is not None:
        hseq, hhash = head
        if hseq > result.last_seq:
            return _fail("log is shorter than chain.head (tail removed)", None, result.count)
        if hashes[hseq] != hhash:
            return _fail("chain.head does not match log", None, result.count)
        # hseq < last_seq допустимо: сбой между записью строки и обновлением head.
        head_checked = True
    if anchors:
        err = check_anchors(list(anchors), hashes)
        if err is not None:
            return _fail(err, None, result.count)
    return VerifyResult(
        True, result.count, result.last_seq, result.last_hash,
        head_checked=head_checked, anchors_checked=len(anchors or ()),
    )
