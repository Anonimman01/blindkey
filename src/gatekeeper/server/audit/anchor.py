"""Внешние якоря журнала: (seq, hash, ts) головы цепочки, сохранённые вне шлюза.

Цепочка хешей и chain.head лежат рядом с журналом, поэтому взломщик с правом записи в каталог
данных может обрезать хвост или переписать журнал целиком вместе с chain.head. Якорь это копия
головы цепочки в месте, куда он дотянуться не может (другой хост, append-only носитель, git,
почта). `audit-verify --anchors` сверяет журнал с якорями:
  * якорь с seq больше длины журнала: хвост удалён;
  * хеш записи с таким seq не совпал с якорем: журнал переписан.
Якорь не содержит секретов (только номер, хеш и время). Защита работает, только если файл
якорей хранится вне каталога данных шлюза.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from gatekeeper.core.errors import AuditError

_HEX = frozenset("0123456789abcdef")
ANCHOR_KEYS = frozenset({"seq", "ts", "hash"})


@dataclass(frozen=True)
class Anchor:
    seq: int
    hash: str
    ts: int


def _is_hash(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def serialize_anchor(anchor: Anchor) -> str:
    """Одна строка якоря (JSON в каноническом виде, без перевода строки)."""
    return json.dumps(
        {"seq": anchor.seq, "ts": anchor.ts, "hash": anchor.hash},
        sort_keys=True, separators=(",", ":"),
    )


def parse_anchors(text: str) -> list[Anchor]:
    """Разобрать файл якорей (по одному JSON-объекту в строке; пустые строки пропускаются).

    Любая некорректная строка или пустой файл = AuditError: молчаливо пропущенный якорь
    дал бы ложное чувство проверенности.
    """
    anchors: list[Anchor] = []
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except ValueError:
            raise AuditError(f"anchor file line {n}: not valid JSON") from None
        if not isinstance(obj, dict) or set(obj) != ANCHOR_KEYS:
            raise AuditError(f"anchor file line {n}: wrong fields")
        seq, ts, h = obj["seq"], obj["ts"], obj["hash"]
        if (
            isinstance(seq, bool) or not isinstance(seq, int) or seq < 0
            or isinstance(ts, bool) or not isinstance(ts, int) or ts < 0
            or not _is_hash(h)
        ):
            raise AuditError(f"anchor file line {n}: wrong field values")
        anchors.append(Anchor(seq, h, ts))
    if not anchors:
        raise AuditError("anchor file has no anchors")
    return anchors


def load_anchors(path: str | os.PathLike) -> list[Anchor]:
    try:
        text = Path(path).read_text("ascii")
    except (OSError, UnicodeDecodeError) as exc:
        raise AuditError("cannot read anchor file") from exc
    return parse_anchors(text)


def append_anchor(path: str | os.PathLike, anchor: Anchor) -> None:
    """Дописать якорь в файл (права 0600, fsync)."""
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise AuditError("cannot open anchor file for writing") from exc
    try:
        os.write(fd, serialize_anchor(anchor).encode("ascii") + b"\n")
        os.fsync(fd)
    finally:
        os.close(fd)


def check_anchors(anchors: list[Anchor], hashes: list[str]) -> str | None:
    """Сверить якоря с хешами записей журнала (hashes[i] = хеш записи seq=i).

    None = все якоря сошлись, иначе текст первой ошибки.
    """
    for a in anchors:
        if a.seq >= len(hashes):
            return f"log is shorter than anchor (seq {a.seq}): tail removed"
        if hashes[a.seq] != a.hash:
            return f"log does not match anchor (seq {a.seq}): log was rewritten"
    return None
