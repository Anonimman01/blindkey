"""Пакет клиента на диске: запись с откатом и удаление (общее для add-client и renew)."""
from __future__ import annotations

from contextlib import suppress
from pathlib import Path

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.pki import ca

BUNDLE_FILES = ("ca.pem", "client.pem", "client.key", "master.secret")


def write_bundle(out: Path, files: dict[str, bytes]) -> None:
    """Записать файлы пакета. При сбое удаляется только то, что записано этим вызовом.

    Каталог убирается, только если его создал этот вызов и он пуст: чужой пакет в существующем
    `--out` (запись падает на первом же файле) остаётся нетронутым.
    """
    existed = out.exists()
    written: list[Path] = []
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        for name, data in files.items():
            path = out / name
            ca.write_private_file(path, data)
            written.append(path)
    except (GatekeeperError, OSError):
        for path in written:
            with suppress(OSError):
                path.unlink()
        if not existed:
            with suppress(OSError):
                out.rmdir()
        raise


def discard_bundle(out: Path, out_existed: bool) -> None:
    """Убрать пакет, который не должен остаться (реестр не принял изменение)."""
    for name in BUNDLE_FILES:
        with suppress(OSError):
            (out / name).unlink()
    if not out_existed:
        with suppress(OSError):
            out.rmdir()
