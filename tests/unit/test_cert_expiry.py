"""A5: срок серверного сертификата — гейдж, предупреждение в stderr и событие в журнале.

Продления нет: единственный сигнал оператору — заблаговременное предупреждение. Проверяем,
что оно появляется только когда до истечения меньше 30 дней, что гейдж всегда отражает
реальный срок и что отсутствие/битый сертификат не ломают проверку.
"""
import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from gatekeeper.core.events import EventType
from gatekeeper.pki import ca
from gatekeeper.server.app import CERT_WARN_SECONDS, GatekeeperApp, _cert_expiry_seconds
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.http_io import HttpLimits
from gatekeeper.server.limits import ConnectionLimiter
from gatekeeper.server.nonce_cache import NonceCache

_DAY = 86400


def make_app(tmp_path, *, days=10, now=None, cert=True):
    ca_cert, ca_key = ca.create_ca()
    cert_obj, _key = ca.issue_server_cert(ca_cert, ca_key, ["gw.example"], days=days, now=now)
    path = tmp_path / "server.pem"
    if cert:
        path.write_bytes(ca.cert_to_pem(cert_obj))
    audit = AuditChain(FileSink(tmp_path / "audit.log"))
    app = GatekeeperApp(
        pipeline=SimpleNamespace(nonces=NonceCache()), bans=SimpleNamespace(),
        limiter=ConnectionLimiter(10, 10), audit=audit,
        http_limits=HttpLimits(), ssl_ctx=None, host="127.0.0.1", port=0,
        server_cert=path if cert else None)
    return app, tmp_path / "audit.log"


def test_expiry_helper_counts_seconds(tmp_path):
    ca_cert, ca_key = ca.create_ca()
    cert, _key = ca.issue_server_cert(ca_cert, ca_key, ["gw.example"], days=10)
    path = tmp_path / "server.pem"
    path.write_bytes(ca.cert_to_pem(cert))
    seconds = _cert_expiry_seconds(path)
    assert seconds is not None and 9 * _DAY < seconds <= 10 * _DAY
    assert _cert_expiry_seconds(tmp_path / "missing.pem") is None


def test_near_expiry_warns_on_stderr_and_in_the_journal(tmp_path, capsys):
    app, audit_path = make_app(tmp_path, days=10)
    asyncio.run(app._check_cert(initial=True))
    err = capsys.readouterr().err
    assert "server certificate expires in 9 day(s)" in err and "renew-server" in err
    log = audit_path.read_text()
    assert EventType.SERVER_CERT_EXPIRING.value in log
    assert '"action":"run"' in log.replace(" ", "")
    # Гейдж отдаёт тот же срок, что и предупреждение (в секундах, не дней).
    gauge = app._gauges()["gk_server_cert_expiry_seconds"]
    assert 9 * _DAY < gauge <= 10 * _DAY
    assert gauge <= CERT_WARN_SECONDS


def _audit_text(path):
    return path.read_text() if path.exists() else ""


def test_far_expiry_keeps_quiet_but_still_reports_the_gauge(tmp_path, capsys):
    app, audit_path = make_app(tmp_path, days=100)
    asyncio.run(app._check_cert(initial=True))
    assert "warning" not in capsys.readouterr().err
    assert EventType.SERVER_CERT_EXPIRING.value not in _audit_text(audit_path)
    assert app._gauges()["gk_server_cert_expiry_seconds"] > CERT_WARN_SECONDS


def test_already_expired_certificate_is_reported(tmp_path, capsys):
    old = datetime.now(UTC) - timedelta(days=40)
    app, audit_path = make_app(tmp_path, days=1, now=old)
    asyncio.run(app._check_cert(initial=True))
    assert "expired" in capsys.readouterr().err
    assert EventType.SERVER_CERT_EXPIRING.value in audit_path.read_text()
    assert app._gauges()["gk_server_cert_expiry_seconds"] < 0


def test_daily_check_repeats_the_event_without_stderr(tmp_path, capsys):
    """Периодическая проверка пишет событие с action=watch и не шумит в stderr."""
    app, audit_path = make_app(tmp_path, days=10)
    asyncio.run(app._check_cert(initial=False))
    assert capsys.readouterr().err == ""
    assert '"action":"watch"' in audit_path.read_text().replace(" ", "")


def test_missing_certificate_does_not_break_the_start(tmp_path, capsys):
    app, _audit_path = make_app(tmp_path, cert=False)
    asyncio.run(app._check_cert(initial=True))
    assert capsys.readouterr().err == ""
    assert "gk_server_cert_expiry_seconds" not in app._gauges()


def test_broken_certificate_does_not_break_the_gauges(tmp_path):
    path = tmp_path / "server.pem"
    path.write_bytes(b"not a certificate")
    app, _audit_path = make_app(tmp_path, cert=False)
    app.server_cert = path
    asyncio.run(app._check_cert(initial=True))
    assert "gk_server_cert_expiry_seconds" not in app._gauges()
