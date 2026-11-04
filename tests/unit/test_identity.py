from cryptography.hazmat.primitives.serialization import Encoding

from gatekeeper.pki import ca
from gatekeeper.pki.fingerprint import cert_fingerprint
from gatekeeper.server.identity import IdentityStore
from gatekeeper.store.registry import Registry

NOW = 1_800_000_000


def setup(tmp_path, status="active", expires=NOW + 1000, cn="alice", allow=("POST:sendMessage",)):
    ca_cert, ca_key = ca.create_ca()
    cert, _ = ca.issue_client_cert(ca_cert, ca_key, cn)
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    reg.add("alice", {"fingerprint": cert_fingerprint(cert), "master_secret": "11" * 32,
                      "status": status, "created": NOW, "expires": expires, "allow": list(allow)})
    store = IdentityStore(reg, ca_cert, clock=lambda: NOW)
    return store, cert, ca_cert, ca_key


def der(cert):
    return cert.public_bytes(Encoding.DER)


def test_ok(tmp_path):
    store, cert, *_ = setup(tmp_path)
    ident = store.identify(der(cert))
    assert ident.reason == "ok" and ident.record.client_id == "alice"
    assert ident.record.policy.check("POST", "/sendMessage") is not None


def test_no_cert(tmp_path):
    store, *_ = setup(tmp_path)
    assert store.identify(None).reason == "no_cert"
    assert store.identify(b"garbage").reason == "bad_cert"


def test_foreign_ca_rejected(tmp_path):
    store, *_ = setup(tmp_path)
    other_ca, other_key = ca.create_ca()
    cert, _ = ca.issue_client_cert(other_ca, other_key, "alice")
    ident = store.identify(der(cert))
    assert ident.reason == "bad_cert" and ident.record is None


def test_unknown_fingerprint(tmp_path):
    store, _, ca_cert, ca_key = setup(tmp_path)
    cert, _ = ca.issue_client_cert(ca_cert, ca_key, "bob")
    ident = store.identify(der(cert))
    assert ident.reason == "unknown" and ident.fingerprint == cert_fingerprint(cert)


def test_frozen_and_revoked(tmp_path):
    for status in ("frozen", "revoked"):
        sub = tmp_path / status
        sub.mkdir()
        store, cert, *_ = setup(sub, status=status)
        assert store.identify(der(cert)).reason == "inactive"


def test_expired(tmp_path):
    store, cert, *_ = setup(tmp_path, expires=NOW - 1)
    assert store.identify(der(cert)).reason == "expired"


def test_cn_mismatch(tmp_path):
    store, cert, *_ = setup(tmp_path, cn="mallory")
    assert store.identify(der(cert)).reason == "cn_mismatch"


def test_broken_entry_is_unusable(tmp_path):
    store, cert, *_ = setup(tmp_path, allow=("POST:bad/path",))
    assert store.identify(der(cert)).reason == "unknown"
    assert store.invalid_entries == 1
