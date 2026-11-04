import asyncio
from types import SimpleNamespace

from cryptography.hazmat.primitives.serialization import Encoding

from gatekeeper.core.kdf import derive_signing_key
from gatekeeper.core.signing import build_headers, new_nonce
from gatekeeper.core.timeutil import unix_now
from gatekeeper.pki import ca
from gatekeeper.pki.fingerprint import cert_fingerprint
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.http_io import ParsedRequest
from gatekeeper.server.identity import IdentityStore
from gatekeeper.server.limits import DailyBudget, IpBanList, RateLimiter
from gatekeeper.server.nonce_cache import NonceCache
from gatekeeper.server.pipeline import Pipeline
from gatekeeper.server.providers.base import UpstreamResponse
from gatekeeper.server.providers.telegram import TelegramProvider
from gatekeeper.server.upstream import UpstreamError
from gatekeeper.store.registry import Registry

TOKEN = "123456789:AAH-fakeFAKEfakeFAKEfakeFAKEfake12345"
MASTER = bytes.fromhex("22" * 32)
IP = "203.0.113.7"


class FakeUpstream:
    def __init__(self):
        self.calls = []
        self.response = UpstreamResponse(200, "application/json", b'{"ok":true}')

    async def fetch(self, req):
        self.calls.append(req)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def make_env(tmp_path, burst=10, budget=100, decoy=False):
    ca_cert, ca_key = ca.create_ca()
    cert, _ = ca.issue_client_cert(ca_cert, ca_key, "alice")
    fp = cert_fingerprint(cert)
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    reg.add("alice", {"fingerprint": fp, "master_secret": MASTER.hex(), "status": "active",
                      "created": 0, "expires": unix_now() + 10_000,
                      "allow": ["POST:sendMessage", "GET:getMe"]})
    prov = TelegramProvider(TOKEN)
    up = FakeUpstream()
    audit_path = tmp_path / "audit.log"
    bans = IpBanList()
    p = Pipeline(
        identity=IdentityStore(reg, ca_cert), provider=prov, upstream=up,
        audit=AuditChain(FileSink(audit_path), secrets=prov.known_secrets()),
        nonces=NonceCache(), client_limiter=RateLimiter(0.001, burst), budget=DailyBudget(budget),
        bans=bans, decoy_check=(lambda f: f == fp) if decoy else None)
    return SimpleNamespace(p=p, up=up, fp=fp, der=cert.public_bytes(Encoding.DER),
                           bans=bans, audit_path=audit_path, ca=(ca_cert, ca_key))


def make_req(fp, method="POST", target="/sendMessage", body=b'{"chat_id":1,"text":"hi"}', *,
             ts=None, nonce=None, key=None, client="alice"):
    key = key or derive_signing_key(MASTER)
    hdr = build_headers(key=key, client_id="alice", cert_fingerprint=fp, epoch=0,
                        timestamp=unix_now() if ts is None else ts, nonce=nonce or new_nonce(),
                        method=method, path=target, body=body)
    headers = {k.lower(): v for k, v in hdr.items()}
    headers["x-gk-client"] = client
    headers.update({"content-type": "application/json", "host": "gw"})
    return ParsedRequest(method, target, headers, body)


def call(env, req, der=None):
    resp = asyncio.run(env.p.handle(req, IP, env.der if der is None else der))
    return int(resp.split(b" ", 2)[1]), resp


def audit_text(env):
    return env.audit_path.read_text()


def test_ok_request_reaches_upstream_with_token(tmp_path):
    env = make_env(tmp_path)
    status, _ = call(env, make_req(env.fp))
    assert status == 200
    assert env.up.calls[0].path == f"/bot{TOKEN}/sendMessage"
    assert "request_ok" in audit_text(env) and TOKEN not in audit_text(env)


def test_bad_signature(tmp_path):
    env = make_env(tmp_path)
    status, _ = call(env, make_req(env.fp, key=bytes(32)))
    assert status == 403 and not env.up.calls and "deny_bad_signature" in audit_text(env)


def test_tampered_body_rejected(tmp_path):
    env = make_env(tmp_path)
    req = make_req(env.fp)
    bad = ParsedRequest(req.method, req.target, req.headers, b'{"chat_id":2,"text":"evil"}')
    assert call(env, bad)[0] == 403 and not env.up.calls


def test_replay(tmp_path):
    env = make_env(tmp_path)
    req = make_req(env.fp)
    assert call(env, req)[0] == 200
    assert call(env, req)[0] == 403 and len(env.up.calls) == 1
    assert "deny_replay" in audit_text(env)


def test_stale_time(tmp_path):
    env = make_env(tmp_path)
    assert call(env, make_req(env.fp, ts=unix_now() - 600))[0] == 403
    assert "deny_stale_time" in audit_text(env)


def test_client_header_mismatch(tmp_path):
    env = make_env(tmp_path)
    assert call(env, make_req(env.fp, client="bob"))[0] == 403 and not env.up.calls


def test_policy_denies_unlisted_method(tmp_path):
    env = make_env(tmp_path)
    assert call(env, make_req(env.fp, target="/deleteWebhook"))[0] == 403
    assert call(env, make_req(env.fp, method="GET", target="/sendMessage", body=b""))[0] == 403
    assert not env.up.calls and "deny_policy" in audit_text(env)


def test_unknown_and_missing_cert(tmp_path):
    env = make_env(tmp_path)
    other_ca, other_key = ca.create_ca()
    foreign, _ = ca.issue_client_cert(other_ca, other_key, "alice")
    assert call(env, make_req(env.fp), der=foreign.public_bytes(Encoding.DER))[0] == 403
    assert call(env, make_req(env.fp), der=b"")[0] == 403
    assert not env.up.calls and "deny_unknown_client" in audit_text(env)


def test_decoy_bans_ip(tmp_path):
    env = make_env(tmp_path, decoy=True)
    assert call(env, make_req(env.fp))[0] == 403
    assert env.bans.is_banned(IP) and not env.up.calls
    assert "decoy_triggered" in audit_text(env)


def test_rate_limit(tmp_path):
    env = make_env(tmp_path, burst=1)
    assert call(env, make_req(env.fp))[0] == 200
    assert call(env, make_req(env.fp))[0] == 429


def test_daily_budget(tmp_path):
    env = make_env(tmp_path, budget=1)
    assert call(env, make_req(env.fp))[0] == 200
    assert call(env, make_req(env.fp))[0] == 429 and "deny_budget" in audit_text(env)


def test_upstream_secret_leak_blocked(tmp_path):
    env = make_env(tmp_path)
    env.up.response = UpstreamResponse(200, "application/json", b'{"x":"' + TOKEN.encode() + b'"}')
    status, resp = call(env, make_req(env.fp))
    assert status == 502 and TOKEN.encode() not in resp
    assert "response_secret_blocked" in audit_text(env) and TOKEN not in audit_text(env)


def test_upstream_failure_is_neutral_502(tmp_path):
    env = make_env(tmp_path)
    env.up.response = UpstreamError("timeout")
    status, resp = call(env, make_req(env.fp))
    assert status == 502 and resp.endswith(b'{"ok":false}')


def test_bad_content_type_is_400(tmp_path):
    env = make_env(tmp_path)
    req = make_req(env.fp)
    req.headers["content-type"] = "text/html"
    assert call(env, req)[0] == 400 and not env.up.calls
