"""Каноническая строка запроса и HMAC-SHA256 подпись.

Формат канонической строки (поля через "\\n", порядок фиксирован):

    v1
    client_id
    cert_fingerprint   (SHA-256 клиентского сертификата, 64 hex, нижний регистр)
    epoch
    timestamp          (unix-секунды)
    nonce
    METHOD
    path_or_api_method
    sha256(body)       (hex)

Отпечаток сертификата входит в подпись: украденный ключ подписи без сертификата
бесполезен, и наоборот. Проверка соответствия отпечатка реальному сертификату
из TLS-соединения делается в server/identity.py, а не здесь.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets

from gatekeeper.core import constants
from gatekeeper.core.errors import SigningError

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")
_NONCE_RE = re.compile(r"^[0-9A-Za-z_-]{16,64}$")
_CLIENT_ID_RE = re.compile(r"^[0-9A-Za-z][0-9A-Za-z_.-]{0,63}$")
_METHOD_RE = re.compile(r"^[A-Z]{3,10}$")
_SIG_RE = re.compile(r"^[0-9a-f]{64}$")
# Путь или имя метода API: печатаемый ASCII без пробелов и переводов строк.
_PATH_RE = re.compile(r"^[\x21-\x7e]{1,2048}$")


def is_valid_client_id(client_id: object) -> bool:
    return isinstance(client_id, str) and bool(_CLIENT_ID_RE.match(client_id))


def new_nonce() -> str:
    """Случайный одноразовый идентификатор (32 hex-символа)."""
    return secrets.token_hex(16)


def body_sha256_hex(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def build_canonical_string(
    *,
    client_id: str,
    cert_fingerprint: str,
    epoch: int,
    timestamp: int,
    nonce: str,
    method: str,
    path: str,
    body: bytes,
) -> bytes:
    """Собрать каноническую строку. Любое некорректное поле -> SigningError."""
    if not isinstance(client_id, str) or not _CLIENT_ID_RE.match(client_id):
        raise SigningError("invalid client_id")
    if not isinstance(cert_fingerprint, str) or not _FINGERPRINT_RE.match(
        cert_fingerprint
    ):
        raise SigningError("invalid cert_fingerprint")
    for name, value in (("epoch", epoch), ("timestamp", timestamp)):
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise SigningError(f"invalid {name}")
    if not isinstance(nonce, str) or not _NONCE_RE.match(nonce):
        raise SigningError("invalid nonce")
    if not isinstance(method, str) or not _METHOD_RE.match(method):
        raise SigningError("invalid method")
    if not isinstance(path, str) or not _PATH_RE.match(path):
        raise SigningError("invalid path")
    if not isinstance(body, (bytes, bytearray)):
        raise SigningError("body must be bytes")

    parts = [
        constants.PROTOCOL_VERSION,
        client_id,
        cert_fingerprint,
        str(epoch),
        str(timestamp),
        nonce,
        method,
        path,
        body_sha256_hex(bytes(body)),
    ]
    return "\n".join(parts).encode("ascii")


def sign(key: bytes, canonical: bytes) -> str:
    """HMAC-SHA256, результат в hex."""
    if not isinstance(key, (bytes, bytearray)) or len(key) != constants.DERIVED_KEY_LEN:
        raise SigningError("invalid signing key")
    return hmac.new(bytes(key), canonical, hashlib.sha256).hexdigest()


def verify(key: bytes, canonical: bytes, signature_hex: str) -> bool:
    """Проверка подписи за постоянное время. Некорректный формат -> False."""
    if not isinstance(signature_hex, str) or not _SIG_RE.match(signature_hex):
        return False
    expected = sign(key, canonical)
    return hmac.compare_digest(expected, signature_hex)


def build_headers(
    *,
    key: bytes,
    client_id: str,
    cert_fingerprint: str,
    epoch: int,
    timestamp: int,
    nonce: str,
    method: str,
    path: str,
    body: bytes,
) -> dict[str, str]:
    """Заголовки X-GK-* для клиента."""
    canonical = build_canonical_string(
        client_id=client_id,
        cert_fingerprint=cert_fingerprint,
        epoch=epoch,
        timestamp=timestamp,
        nonce=nonce,
        method=method,
        path=path,
        body=body,
    )
    return {
        constants.HEADER_CLIENT: client_id,
        constants.HEADER_EPOCH: str(epoch),
        constants.HEADER_TIME: str(timestamp),
        constants.HEADER_NONCE: nonce,
        constants.HEADER_SIG: sign(key, canonical),
    }
