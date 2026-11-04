import hashlib
import hmac

import pytest

from gatekeeper.core import constants
from gatekeeper.core.errors import SigningError
from gatekeeper.core.kdf import derive_signing_key
from gatekeeper.core.signing import (
    body_sha256_hex,
    build_canonical_string,
    build_headers,
    new_nonce,
    sign,
    verify,
)
from gatekeeper.core.timeutil import is_fresh

FP = "ab" * 32
NONCE = "0123456789abcdef0123456789abcdef"
KEY = derive_signing_key(bytes(range(32)), 0)

BASE = dict(
    client_id="bot-1",
    cert_fingerprint=FP,
    epoch=0,
    timestamp=1_700_000_000,
    nonce=NONCE,
    method="POST",
    path="sendMessage",
    body=b'{"chat_id":1,"text":"hi"}',
)


def canon(**over):
    return build_canonical_string(**{**BASE, **over})


def test_canonical_format_is_fixed():
    expected = "\n".join(
        [
            "v1", "bot-1", FP, "0", "1700000000", NONCE, "POST", "sendMessage",
            hashlib.sha256(BASE["body"]).hexdigest(),
        ]
    ).encode()
    assert canon() == expected


def test_sign_matches_independent_hmac():
    c = canon()
    assert sign(KEY, c) == hmac.new(KEY, c, hashlib.sha256).hexdigest()


def test_roundtrip_ok():
    c = canon()
    assert verify(KEY, c, sign(KEY, c)) is True


@pytest.mark.parametrize(
    "field,value",
    [
        ("client_id", "bot-2"),
        ("cert_fingerprint", "cd" * 32),
        ("epoch", 1),
        ("timestamp", 1_700_000_001),
        ("nonce", "f" * 32),
        ("method", "GET"),
        ("path", "getMe"),
        ("body", b"{}"),
    ],
)
def test_any_field_change_breaks_signature(field, value):
    sig = sign(KEY, canon())
    assert verify(KEY, canon(**{field: value}), sig) is False


def test_wrong_key_fails():
    c = canon()
    other = derive_signing_key(bytes(32), 0)
    assert verify(other, c, sign(KEY, c)) is False


def test_key_of_other_epoch_fails():
    c = canon()
    other = derive_signing_key(bytes(range(32)), 1)
    assert verify(other, c, sign(KEY, c)) is False


def test_cert_signature_mismatch_both_directions():
    # Подпись, сделанная для отпечатка A, не проходит для отпечатка B.
    sig_a = sign(KEY, canon(cert_fingerprint="aa" * 32))
    assert verify(KEY, canon(cert_fingerprint="bb" * 32), sig_a) is False


@pytest.mark.parametrize(
    "bad", ["", "zz" * 32, "AB" * 32, "ab" * 31, "ab" * 33, None, 123, b"ab" * 32]
)
def test_malformed_signature_returns_false(bad):
    assert verify(KEY, canon(), bad) is False


@pytest.mark.parametrize(
    "field,value",
    [
        ("client_id", "a\nb"),
        ("client_id", ""),
        ("cert_fingerprint", "AB" * 32),
        ("cert_fingerprint", "ab" * 31),
        ("epoch", -1),
        ("epoch", True),
        ("timestamp", "1700000000"),
        ("nonce", "short"),
        ("nonce", "a" * 15 + "\n"),
        ("method", "post"),
        ("method", "PO\nST"),
        ("path", "a\nb"),
        ("path", "a b"),
        ("path", ""),
        ("body", "text"),
    ],
)
def test_invalid_fields_rejected(field, value):
    with pytest.raises(SigningError):
        canon(**{field: value})


def test_newline_injection_cannot_shift_fields():
    with pytest.raises(SigningError):
        canon(path="x\nPOST\nsendMessage")


def test_bad_key_rejected():
    with pytest.raises(SigningError):
        sign(b"short", canon())


def test_body_hash():
    assert body_sha256_hex(b"") == hashlib.sha256(b"").hexdigest()


def test_new_nonce_unique_and_valid():
    nonces = {new_nonce() for _ in range(100)}
    assert len(nonces) == 100
    for n in nonces:
        canon(nonce=n)


def test_build_headers():
    h = build_headers(key=KEY, **BASE)
    assert h[constants.HEADER_CLIENT] == "bot-1"
    assert h[constants.HEADER_EPOCH] == "0"
    assert h[constants.HEADER_TIME] == "1700000000"
    assert h[constants.HEADER_NONCE] == NONCE
    assert verify(KEY, canon(), h[constants.HEADER_SIG])


def test_is_fresh():
    assert is_fresh(1000, now=1000)
    assert is_fresh(1000, now=1030)
    assert is_fresh(1030, now=1000)
    assert not is_fresh(1000, now=1031)
    assert not is_fresh(1031, now=1000)
    assert not is_fresh("1000", now=1000)
    assert not is_fresh(True, now=1)
