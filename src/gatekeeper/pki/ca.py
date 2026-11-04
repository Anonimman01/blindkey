"""Собственный CA: выпуск серверного и клиентских сертификатов.

Алгоритм: ECDSA P-256 + SHA-256. Свою криптографию не пишем: всё через cryptography.
Корневой ключ CA (ca.key) должен храниться офлайн, вне сервера; на шлюзе нужен
только ca.pem. Здесь только логика, файлы пишет CLI.
"""
from __future__ import annotations

import ipaddress
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from gatekeeper.core.errors import PkiError
from gatekeeper.core.signing import is_valid_client_id

_BACKDATE = timedelta(minutes=5)  # запас на расхождение часов
_BINARY = getattr(os, "O_BINARY", 0)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _new_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _name(cn: str) -> x509.Name:
    if not cn or len(cn) > 64:  # лимит X.509 на длину CN
        raise PkiError("common name must be 1..64 characters")
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _not_after(cert: x509.Certificate) -> datetime:
    return getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after.replace(
        tzinfo=timezone.utc
    )


def _not_before(cert: x509.Certificate) -> datetime:
    return getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before.replace(
        tzinfo=timezone.utc
    )


def _builder(subject: x509.Name, issuer: x509.Name, pub, days: int, now: datetime):
    if isinstance(days, bool) or not isinstance(days, int) or days < 1:
        raise PkiError("days must be a positive integer")
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - _BACKDATE)
        .not_valid_after(now + timedelta(days=days))
    )


def create_ca(
    common_name: str = "gatekeeper CA", days: int = 3650, now: datetime | None = None
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    now = now or _now()
    key = _new_key()
    name = _name(common_name)
    cert = (
        _builder(name, name, key.public_key(), days, now)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _leaf_common(builder, ca_cert, eku, key):
    return (
        builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )


def issue_server_cert(
    ca_cert: x509.Certificate,
    ca_key: ec.EllipticCurvePrivateKey,
    hosts: list[str],
    days: int = 365,
    now: datetime | None = None,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Серверный сертификат. hosts: DNS-имена и/или IP-адреса (для SAN)."""
    if not hosts:
        raise PkiError("at least one host is required")
    sans: list[x509.GeneralName] = []
    for h in hosts:
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            if not isinstance(h, str) or not h or any(c in h for c in " \n\r/"):
                raise PkiError("invalid host name") from None
            sans.append(x509.DNSName(h))
    key = _new_key()
    b = _builder(_name(str(hosts[0])), ca_cert.subject, key.public_key(), days, now or _now())
    b = _leaf_common(b, ca_cert, ExtendedKeyUsageOID.SERVER_AUTH, key)
    b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return b.sign(ca_key, hashes.SHA256()), key


def issue_client_cert(
    ca_cert: x509.Certificate,
    ca_key: ec.EllipticCurvePrivateKey,
    client_id: str,
    days: int = 90,
    now: datetime | None = None,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Клиентский сертификат (CN = client_id). Срок короткий: ротация проще отзыва."""
    if not is_valid_client_id(client_id):
        raise PkiError("invalid client_id")
    key = _new_key()
    b = _builder(_name(client_id), ca_cert.subject, key.public_key(), days, now or _now())
    b = _leaf_common(b, ca_cert, ExtendedKeyUsageOID.CLIENT_AUTH, key)
    return b.sign(ca_key, hashes.SHA256()), key


def validate_client_cert(
    cert: x509.Certificate, ca_cert: x509.Certificate, now: datetime | None = None
) -> bool:
    """Повторная проверка клиентского сертификата уже внутри шлюза (поверх TLS).

    Подпись CA, срок действия, не CA, EKU = clientAuth. Любая ошибка -> False.
    """
    now = now or _now()
    try:
        cert.verify_directly_issued_by(ca_cert)
        if not (_not_before(cert) <= now <= _not_after(cert)):
            return False
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        if bc.ca:
            return False
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        return ExtendedKeyUsageOID.CLIENT_AUTH in eku
    except (ValueError, TypeError, InvalidSignature, x509.ExtensionNotFound):
        return False


# --- сериализация -----------------------------------------------------------

def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_to_pem(key: ec.EllipticCurvePrivateKey, password: bytes | None = None) -> bytes:
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc
    )


def load_cert_pem(pem: bytes) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(pem)
    except ValueError as exc:
        raise PkiError("invalid PEM certificate") from exc


def load_key_pem(pem: bytes, password: bytes | None = None) -> ec.EllipticCurvePrivateKey:
    try:
        key = serialization.load_pem_private_key(pem, password)
    except (ValueError, TypeError) as exc:
        raise PkiError("cannot load private key (bad PEM or password)") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise PkiError("unexpected key type")
    return key


def write_private_file(path: str | os.PathLike, data: bytes, overwrite: bool = False) -> None:
    """Записать секретный файл с правами 0600; по умолчанию не перезаписывает."""
    flags = os.O_WRONLY | os.O_CREAT | _BINARY | (os.O_TRUNC if overwrite else os.O_EXCL)
    try:
        fd = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise PkiError(f"file already exists: {path}") from exc
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
