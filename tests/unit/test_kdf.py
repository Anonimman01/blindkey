"""Тесты HKDF: официальные векторы RFC 5869 (Appendix A, SHA-256) + свойства."""
import pytest

from gatekeeper.core.errors import KdfError
from gatekeeper.core.kdf import derive_signing_key, hkdf_sha256

H = bytes.fromhex


def test_rfc5869_case1():
    okm = hkdf_sha256(
        ikm=H("0b" * 22),
        salt=H("000102030405060708090a0b0c"),
        info=H("f0f1f2f3f4f5f6f7f8f9"),
        length=42,
    )
    assert okm == H(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_rfc5869_case2_long_inputs():
    okm = hkdf_sha256(
        ikm=bytes(range(0x00, 0x50)),
        salt=bytes(range(0x60, 0xB0)),
        info=bytes(range(0xB0, 0x100)),
        length=82,
    )
    assert okm == H(
        "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c"
        "59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71"
        "cc30c58179ec3e87c14c01d5c1f3434f1d87"
    )


def test_rfc5869_case3_empty_salt_and_info():
    okm = hkdf_sha256(ikm=H("0b" * 22), salt=None, info=b"", length=42)
    assert okm == H(
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        "9d201395faa4b61a96c8"
    )


def test_invalid_params():
    with pytest.raises(KdfError):
        hkdf_sha256(b"", b"x")
    with pytest.raises(KdfError):
        hkdf_sha256(b"k", b"x", length=0)
    with pytest.raises(KdfError):
        hkdf_sha256(b"k", b"x", length=255 * 32 + 1)


MASTER = bytes(range(32))


def test_signing_key_deterministic_and_32_bytes():
    k = derive_signing_key(MASTER, 0)
    assert k == derive_signing_key(MASTER, 0)
    assert len(k) == 32


def test_signing_key_differs_per_epoch_and_master():
    assert derive_signing_key(MASTER, 0) != derive_signing_key(MASTER, 1)
    assert derive_signing_key(MASTER, 0) != derive_signing_key(bytes(32), 0)


def test_signing_key_not_equal_to_master():
    assert derive_signing_key(MASTER, 0) != MASTER


@pytest.mark.parametrize("bad", [-1, 1.5, "0", None, True])
def test_signing_key_bad_epoch(bad):
    with pytest.raises(KdfError):
        derive_signing_key(MASTER, bad)


@pytest.mark.parametrize("bad", [b"", b"short", bytes(31), bytes(33)])
def test_signing_key_bad_master_length(bad):
    with pytest.raises(KdfError):
        derive_signing_key(bad, 0)
