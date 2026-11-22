"""Сверка requirements-*.in и requirements-*.lock без сети (B-07, B-13).

Проверяет для каждой пары (.in, .lock):
  * каждое требование из .in есть в lock;
  * версия в lock удовлетворяет ограничению (`==`, `>=`, `>`, `~=` по числовым частям);
  * у каждого пакета в lock есть хотя бы один `--hash=sha256:`.

Запуск: python scripts/check_lock.py requirements.in requirements.lock [...]
Код возврата 0 = всё сходится, 1 = дрейф или отсутствие хешей.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

_REQ = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<op>===|==|>=|~=|>)?\s*"
                  r"(?P<version>[0-9][0-9A-Za-z.*+!-]*)?$")
_PIN = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^\s\\]+)\s*\\?\s*$")


def _key(version: str) -> tuple[int, ...]:
    """Грубый числовой ключ версии: для верхних/нижних границ этого достаточно."""
    parts = tuple(int(p) for p in re.findall(r"\d+", version))
    return parts or (0,)


def parse_requirements(path: Path) -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for raw in path.read_text("utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _REQ.match(line)
        if match is None:
            raise SystemExit(f"{path}: cannot parse requirement: {raw!r}")
        out.append((match.group("name").lower(), match.group("op") or "",
                    match.group("version") or ""))
    return out


def parse_lock(path: Path) -> dict[str, tuple[str, int]]:
    """name -> (version, число хешей)."""
    locked: dict[str, tuple[str, int]] = {}
    current: str | None = None
    hashes = 0
    for raw in path.read_text("utf-8").splitlines():
        match = _PIN.match(raw)
        if match is not None:
            if current is not None:
                locked[current] = (locked[current][0], hashes)
            name = match.group("name").lower()
            if name in locked:
                raise SystemExit(f"{path}: duplicate package in lock: {name}")
            current = name
            hashes = 0
            locked[name] = (match.group("version"), 0)
            continue
        if current is not None and "--hash=sha256:" in raw:
            hashes += 1
        elif current is not None and raw.strip() and not raw.lstrip().startswith("--hash="):
            locked[current] = (locked[current][0], hashes)
            current, hashes = None, 0
    if current is not None:
        locked[current] = (locked[current][0], hashes)
    return locked


def check(in_path: Path, lock_path: Path) -> list[str]:
    problems: list[str] = []
    locked = parse_lock(lock_path)
    for name, op, version in parse_requirements(in_path):
        if name not in locked:
            problems.append(f"{in_path.name}: {name} is missing from {lock_path.name}")
            continue
        pinned, hashes = locked[name]
        if hashes == 0:
            problems.append(f"{lock_path.name}: {name} has no --hash=sha256 entries")
        if not op:
            continue
        if op == "==" and pinned != version:
            problems.append(f"{lock_path.name}: {name}=={pinned}, {in_path.name} wants =={version}")
        elif op == ">=" and _key(pinned) < _key(version):
            problems.append(f"{lock_path.name}: {name}=={pinned}, {in_path.name} wants >={version}")
        elif op == ">" and _key(pinned) <= _key(version):
            problems.append(f"{lock_path.name}: {name}=={pinned}, {in_path.name} wants >{version}")
        elif op == "~=" and not (
                _key(pinned) >= _key(version)
                and _key(pinned)[: max(1, len(_key(version)) - 1)]
                == _key(version)[: max(1, len(_key(version)) - 1)]):
            problems.append(f"{lock_path.name}: {name}=={pinned}, {in_path.name} wants ~={version}")
    for name, (_version, hashes) in locked.items():
        if hashes == 0:
            problems.append(f"{lock_path.name}: {name} has no --hash=sha256 entries")
    return problems


def main(argv: list[str]) -> int:
    if not argv or len(argv) % 2:
        print("usage: python scripts/check_lock.py requirements.in requirements.lock [...]",
              file=sys.stderr)
        return 2
    problems: list[str] = []
    for in_name, lock_name in zip(argv[0::2], argv[1::2], strict=True):
        problems += check(Path(in_name), Path(lock_name))
    if problems:
        for problem in sorted(set(problems)):
            print(f"error: {problem}", file=sys.stderr)
        return 1
    print("lockfiles are in sync with their .in files and fully hashed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
