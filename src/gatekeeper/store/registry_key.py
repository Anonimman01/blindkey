"""Шифрование `master_secret` в clients.json (B2, по умолчанию выключено).

Что защищает: копию файла вне шлюза (бэкап, snapshot, `cp` без прав, случайная выкладка
в репозиторий). Без ключа ciphertext бесполезен.

Чего НЕ защищает: взломанный процесс шлюза. Ключ лежит в памяти процесса и в файле,
который читает шлюз, поэтому атакующий с правами процесса получает и ключ, и секреты.
Шифрование не заменяет отдельную машину, непривилегированного пользователя и права 0600.

Ключ: 32 байта в файле (сырые байты или 64 hex-символа), путь — в переменной окружения
`GATEKEEPER_REGISTRY_KEY_FILE`. Так работает и systemd `LoadCredential=registry-key:...`:
служба получает файл в /run/credentials, значение в окружение не попадает.
"""
from __future__ import annotations

import base64
import os
import stat
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from gatekeeper.core.errors import GatekeeperError

ENV_KEY_FILE = "GATEKEEPER_REGISTRY_KEY_FILE"
KEY_LEN = 32
_NONCE_LEN = 12
_HEX = frozenset("0123456789abcdefABCDEF")


class RegistryKeyError(GatekeeperError):
    """Ключ шифрования реестра не найден, небезопасен или не подходит к файлу."""


def _aad(client_id: str) -> bytes:
    """Привязка шифротекста к клиенту: запись нельзя переставить другому клиенту."""
    return f"gatekeeper/registry/v1/{client_id}".encode("ascii")


def load_key_file(path: str | os.PathLike) -> bytes:
    """Прочитать ключ из файла. Значение ключа наружу не выводится и не логируется."""
    try:
        st = os.stat(path)
    except OSError as exc:
        raise RegistryKeyError("cannot read the registry key file") from exc
    if os.name != "nt" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise RegistryKeyError("the registry key file must not be accessible to group/others "
                               "(chmod 0400)")
    try:
        data = Path(path).read_bytes()
    except OSError as exc:
        raise RegistryKeyError("cannot read the registry key file") from exc
    stripped = data.strip()
    if len(stripped) == 2 * KEY_LEN and set(stripped.decode("ascii", "replace")) <= _HEX:
        return bytes.fromhex(stripped.decode("ascii"))
    if len(data) == KEY_LEN:
        return data
    raise RegistryKeyError("the registry key must be 32 raw bytes or 64 hex characters")


def load_key_from_env() -> bytes:
    path = os.environ.get(ENV_KEY_FILE, "")
    if not path:
        raise RegistryKeyError(
            f"master_secret encryption is enabled but {ENV_KEY_FILE} is not set "
            "(point it at a 32-byte key file, for example a systemd credential)")
    return load_key_file(path)


def seal(key: bytes, plaintext: str, client_id: str) -> str:
    """Зашифровать секрет клиента: base64(nonce || ciphertext+tag)."""
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), _aad(client_id))
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def unseal(key: bytes, blob: str, client_id: str) -> str:
    """Расшифровать секрет клиента. Ошибка = неверный ключ или испорченный файл."""
    if not isinstance(blob, str) or not blob:
        raise RegistryKeyError("master_secret_enc is not a string")
    try:
        raw = base64.b64decode(blob, validate=True)
    except (ValueError, TypeError) as exc:
        raise RegistryKeyError("master_secret_enc is not valid base64") from exc
    if len(raw) <= _NONCE_LEN:
        raise RegistryKeyError("master_secret_enc is too short")
    try:
        plaintext = AESGCM(key).decrypt(raw[:_NONCE_LEN], raw[_NONCE_LEN:], _aad(client_id))
    except InvalidTag as exc:
        raise RegistryKeyError("cannot decrypt master_secret: wrong key or a modified file") from exc
    return plaintext.decode("utf-8")
