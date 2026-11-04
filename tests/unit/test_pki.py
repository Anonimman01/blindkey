import hashlib
import os
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from gatekeeper.core.errors import PkiError
from gatekeeper.pki import ca as pki
from gatekeeper.pki.fingerprint import cert_fingerprint, fingerprint_from_der, fingerprint_from_pem


@pytest.fixture(scope="module")
def authority():
    return pki.create_ca()


def eku(cert):
    return cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value


# --- fingerprint ---

def test_fingerprint_format_and_value(authority):
    cert, _ = authority
    fp = cert_fingerprint(cert)
    assert len(fp) == 64 and fp == fp.lower() and int(fp, 16) >= 0
    der = cert.public_bytes(pki.serialization.Encoding.DER)
    assert fp == hashlib.sha256(der).hexdigest() == fingerprint_from_der(der)


def test_fingerprint_pem_equals_cert(authority):
    cert, _ = authority
    assert fingerprint_from_pem(pki.cert_to_pem(cert)) == cert_fingerprint(cert)


def test_fingerprints_differ_between_certs(authority):
    ca, key = authority
    a, _ = pki.issue_client_cert(ca, key, "bot-1")
    b, _ = pki.issue_client_cert(ca, key, "bot-1")
    assert cert_fingerprint(a) != cert_fingerprint(b)


def test_fingerprint_bad_input():
    with pytest.raises(PkiError):
        fingerprint_from_der(b"")
    with pytest.raises(PkiError):
        fingerprint_from_pem(b"garbage")


# --- CA ---

def test_ca_properties(authority):
    ca, _ = authority
    bc = ca.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca and bc.value.path_length == 0
    ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign and ku.crl_sign and not ku.digital_signature
    assert ca.subject == ca.issuer
    ca.verify_directly_issued_by(ca)


# --- server cert ---

def test_server_cert(authority):
    ca, key = authority
    cert, _ = pki.issue_server_cert(ca, key, ["gw.example.com", "127.0.0.1", "::1"])
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["gw.example.com"]
    assert len(san.get_values_for_type(x509.IPAddress)) == 2
    assert list(eku(cert)) == [ExtendedKeyUsageOID.SERVER_AUTH]
    cert.verify_directly_issued_by(ca)


def test_server_cert_needs_hosts(authority):
    ca, key = authority
    with pytest.raises(PkiError):
        pki.issue_server_cert(ca, key, [])
    with pytest.raises(PkiError):
        pki.issue_server_cert(ca, key, ["bad host"])


# --- client cert ---

def test_client_cert_properties(authority):
    ca, key = authority
    cert, _ = pki.issue_client_cert(ca, key, "bot-1", days=30)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "bot-1"
    assert list(eku(cert)) == [ExtendedKeyUsageOID.CLIENT_AUTH]
    bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert not bc.ca
    life = pki._not_after(cert) - pki._not_before(cert)
    assert timedelta(days=30) <= life <= timedelta(days=30, minutes=10)


@pytest.mark.parametrize("bad", ["", "a\nb", "a b", "x" * 65, None, 5])
def test_client_cert_bad_id(authority, bad):
    ca, key = authority
    with pytest.raises(PkiError):
        pki.issue_client_cert(ca, key, bad)


@pytest.mark.parametrize("days", [0, -1, 1.5, True])
def test_bad_days(authority, days):
    ca, key = authority
    with pytest.raises(PkiError):
        pki.issue_client_cert(ca, key, "bot-1", days=days)


# --- validate_client_cert (negative scenarios) ---

def test_validate_ok(authority):
    ca, key = authority
    cert, _ = pki.issue_client_cert(ca, key, "bot-1")
    assert pki.validate_client_cert(cert, ca)


def test_validate_foreign_ca(authority):
    ca, key = authority
    other_ca, other_key = pki.create_ca("evil CA")
    cert, _ = pki.issue_client_cert(other_ca, other_key, "bot-1")
    assert not pki.validate_client_cert(cert, ca)


def test_validate_same_name_foreign_ca(authority):
    # CA с тем же именем, но другим ключом: подпись не сойдётся.
    ca, _ = authority
    fake_ca, fake_key = pki.create_ca("gatekeeper CA")
    cert, _ = pki.issue_client_cert(fake_ca, fake_key, "bot-1")
    assert not pki.validate_client_cert(cert, ca)


def test_validate_expired(authority):
    ca, key = authority
    cert, _ = pki.issue_client_cert(ca, key, "bot-1", days=1)
    later = pki._not_after(cert) + timedelta(seconds=1)
    assert not pki.validate_client_cert(cert, ca, now=later)


def test_validate_not_yet_valid(authority):
    ca, key = authority
    cert, _ = pki.issue_client_cert(ca, key, "bot-1")
    assert not pki.validate_client_cert(cert, ca, now=pki._not_before(cert) - timedelta(hours=1))


def test_validate_server_cert_not_accepted_as_client(authority):
    ca, key = authority
    cert, _ = pki.issue_server_cert(ca, key, ["localhost"])
    assert not pki.validate_client_cert(cert, ca)


def test_validate_ca_cert_not_accepted_as_client(authority):
    ca, _ = authority
    assert not pki.validate_client_cert(ca, ca)


# --- сериализация и файлы ---

def test_pem_roundtrip(authority):
    ca, key = authority
    assert cert_fingerprint(pki.load_cert_pem(pki.cert_to_pem(ca))) == cert_fingerprint(ca)
    k2 = pki.load_key_pem(pki.key_to_pem(key))
    assert k2.public_key().public_numbers() == key.public_key().public_numbers()


def test_encrypted_key_roundtrip_and_wrong_password(authority):
    _, key = authority
    pem = pki.key_to_pem(key, b"correct horse")
    assert b"ENCRYPTED" in pem
    pki.load_key_pem(pem, b"correct horse")
    with pytest.raises(PkiError):
        pki.load_key_pem(pem, b"wrong")
    with pytest.raises(PkiError):
        pki.load_key_pem(pem)


def test_load_garbage():
    with pytest.raises(PkiError):
        pki.load_cert_pem(b"nope")
    with pytest.raises(PkiError):
        pki.load_key_pem(b"nope")


def test_write_private_file_no_overwrite(tmp_path):
    p = tmp_path / "k.pem"
    pki.write_private_file(p, b"one")
    with pytest.raises(PkiError):
        pki.write_private_file(p, b"two")
    assert p.read_bytes() == b"one"
    pki.write_private_file(p, b"three", overwrite=True)
    assert p.read_bytes() == b"three"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_private_file_is_0600(tmp_path):
    p = tmp_path / "k.pem"
    pki.write_private_file(p, b"x")
    assert oct(p.stat().st_mode & 0o777) == "0o600"
