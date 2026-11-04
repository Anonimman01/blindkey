"""Негативные сквозные тесты mTLS: плохие сертификаты и версии TLS не доходят до обработчика."""
import ssl
from datetime import timedelta

from test_end_to_end import attempt, gw, tls_ctx  # noqa: F401  (gw - фикстура)

from gatekeeper.pki import ca


def _ca(gw):
    return ca.load_cert_pem(gw.layout.ca_cert.read_bytes()), ca.load_key_pem(gw.cakey.read_bytes())


def _write(gw, name, cert, key):
    c, k = gw.tmp / f"{name}.pem", gw.tmp / f"{name}.key"
    c.write_bytes(ca.cert_to_pem(cert))
    k.write_bytes(ca.key_to_pem(key))
    return c, k


def _http_status(resp):
    return int(resp.split(b" ", 2)[1]) if isinstance(resp, bytes) and resp.startswith(b"HTTP/") else None


def test_valid_certificate_baseline(gw):
    ctx = tls_ctx(gw, gw.bundle / "client.pem", gw.bundle / "client.key")
    assert _http_status(attempt(gw, ctx)) is not None  # шлюз ответил по HTTP


def test_no_client_certificate_refused(gw):
    assert attempt(gw, tls_ctx(gw)) == "refused"


def test_expired_certificate_refused(gw):
    ca_cert, ca_key = _ca(gw)
    cert, key = ca.issue_client_cert(ca_cert, ca_key, "alice", days=90, now=ca._now() - timedelta(days=200))
    c, k = _write(gw, "expired", cert, key)
    assert attempt(gw, tls_ctx(gw, c, k)) == "refused"


def test_foreign_ca_with_same_cn_refused(gw):
    """CN = alice, но подпись чужого CA."""
    fca, fkey = ca.create_ca("evil CA")
    cert, key = ca.issue_client_cert(fca, fkey, "alice")
    c, k = _write(gw, "foreign", cert, key)
    assert attempt(gw, tls_ctx(gw, c, k)) == "refused"


def test_valid_signature_but_unregistered_client_denied(gw):
    """Подпись нашего CA верна, но клиента нет в реестре: TLS проходит, запрос - нет."""
    ca_cert, ca_key = _ca(gw)
    cert, key = ca.issue_client_cert(ca_cert, ca_key, "mallory")
    c, k = _write(gw, "mallory", cert, key)
    resp = attempt(gw, tls_ctx(gw, c, k))
    assert resp != "refused" and _http_status(resp) in (401, 403, 404)


def test_tls12_downgrade_refused(gw):
    ctx = tls_ctx(gw, gw.bundle / "client.pem", gw.bundle / "client.key", maxv=ssl.TLSVersion.TLSv1_2)
    assert attempt(gw, ctx) == "refused"


def _events(gw, name):
    import json
    return [json.loads(l) for l in gw.layout.audit_log.read_text().splitlines() if name in l]


def test_failed_handshakes_are_audited_without_flooding(gw):
    import time
    fca, fkey = ca.create_ca("evil CA")
    cert, key = ca.issue_client_cert(fca, fkey, "alice")
    c, k = _write(gw, "foreign2", cert, key)
    for _ in range(30):  # флуд с одного IP
        assert attempt(gw, tls_ctx(gw, c, k)) == "refused"
    assert attempt(gw, tls_ctx(gw)) == "refused"
    time.sleep(0.3)
    ev = _events(gw, "deny_tls_handshake")
    assert 1 <= len(ev) <= 10  # записи есть, но лимит частоты работает
    assert all("127.0.0.1" in json.dumps(e) for e in ev) if (json := __import__("json")) else True
    ok = tls_ctx(gw, gw.bundle / "client.pem", gw.bundle / "client.key")
    assert _http_status(attempt(gw, ok)) is not None  # шлюз жив
    ok_api = __import__("gatekeeper.client.botapi", fromlist=["BotApi"]).BotApi(str(gw.bundle), "127.0.0.1", gw.port)
    assert ok_api.get_me()["ok"]
