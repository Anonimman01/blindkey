"""Вывод ключей через HKDF (RFC 5869, SHA-256).

Реализацию берём из библиотеки cryptography: свою криптографию не пишем.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from gatekeeper.core import constants
from gatekeeper.core.errors import KdfError


def hkdf_sha256(
    ikm: bytes,
    info: bytes,
    length: int = constants.DERIVED_KEY_LEN,
    salt: bytes | None = None,
) -> bytes:
    """HKDF-Extract + Expand с SHA-256. salt=None означает нулевую соль (как в RFC)."""
    if not isinstance(ikm, (bytes, bytearray)) or not ikm:
        raise KdfError("ikm must be non-empty bytes")
    if not isinstance(info, (bytes, bytearray)):
        raise KdfError("info must be bytes")
    if not 1 <= length <= 255 * 32:
        raise KdfError("invalid output length")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=bytes(info),
    ).derive(bytes(ikm))


def derive_signing_key(master_secret: bytes, epoch: int = 0) -> bytes:
    """Ключ подписи для эпохи N: HKDF(master, info="sign|epoch=N").

    В MVP эпоха всегда 0, но поле остаётся в протоколе, чтобы формат не менялся в v2.
    """
    if len(master_secret) != constants.MASTER_SECRET_LEN:
        raise KdfError(f"master secret must be {constants.MASTER_SECRET_LEN} bytes")
    if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 0:
        raise KdfError("epoch must be a non-negative integer")
    info = f"{constants.INFO_SIGN_PREFIX}{epoch}".encode("ascii")
    return hkdf_sha256(
        master_secret, info, constants.DERIVED_KEY_LEN, constants.HKDF_SALT
    )
