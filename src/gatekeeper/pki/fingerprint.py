"""Отпечаток сертификата: SHA-256 от DER-представления, 64 hex-символа, нижний регистр.

По этому отпечатку шлюз опознаёт клиента (а не по User-Agent и подобному).
"""
from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from gatekeeper.core.errors import PkiError


def fingerprint_from_der(der: bytes) -> str:
    if not isinstance(der, (bytes, bytearray)) or not der:
        raise PkiError("certificate DER must be non-empty bytes")
    return hashlib.sha256(bytes(der)).hexdigest()


def cert_fingerprint(cert: x509.Certificate) -> str:
    return fingerprint_from_der(cert.public_bytes(Encoding.DER))


def fingerprint_from_pem(pem: bytes) -> str:
    try:
        cert = x509.load_pem_x509_certificate(pem)
    except ValueError as exc:
        raise PkiError("invalid PEM certificate") from exc
    return cert_fingerprint(cert)
