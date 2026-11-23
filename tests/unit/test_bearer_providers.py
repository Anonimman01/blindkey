"""Провайдеры OpenAI, Vercel и Cloudflare (общая основа bearer.py)."""
import asyncio
import json
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from test_pipeline import IP, MASTER

from gatekeeper.core.kdf import derive_signing_key
from gatekeeper.core.signing import build_headers, new_nonce
from gatekeeper.core.timeutil import unix_now
from gatekeeper.pki import ca
from gatekeeper.pki.fingerprint import cert_fingerprint
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.config import load_config
from gatekeeper.server.http_io import ParsedRequest
from gatekeeper.server.identity import IdentityStore
from gatekeeper.server.limits import DailyBudget, IpBanList, RateLimiter
from gatekeeper.server.nonce_cache import NonceCache
from gatekeeper.server.pipeline import Pipeline
from gatekeeper.server.policy import is_valid_api_name
from gatekeeper.server.providers import KNOWN_PROVIDERS, create_provider
from gatekeeper.server.providers.base import ProviderError, UpstreamResponse
from gatekeeper.server.providers.bearer import Route
from gatekeeper.server.providers.cloudflare import CloudflareProvider
from gatekeeper.server.providers.openai import OpenAIProvider
from gatekeeper.server.providers.vercel import VercelProvider
from gatekeeper.store.registry import Registry

JSON = "application/json"
OAI = "sk-proj-" + "A1b2C3d4E5" * 4
VCL = "vcp_" + "A1b2C3d4E5" * 3
CF = "cfut_" + "A1b2C3d4E5" * 5 + "1a2b3c4d"
ZONE = "0123456789abcdef0123456789abcdef"

TOKENS = {"openai": OAI, "vercel": VCL, "cloudflare": CF}
CLASSES = {"openai": OpenAIProvider, "vercel": VercelProvider, "cloudflare": CloudflareProvider}
HOSTS = {"openai": "api.openai.com", "vercel": "api.vercel.com", "cloudflare": "api.cloudflare.com"}


def _p(name):
    return create_provider(name, TOKENS[name])


def _body(**kw):
    return json.dumps(kw).encode()


# --- реестр и формат токена ---

def test_known_providers_listed():
    assert KNOWN_PROVIDERS == ("telegram", "github", "openai", "vercel", "cloudflare")


@pytest.mark.parametrize("name", TOKENS)
def test_registry_creates_provider(name):
    p = _p(name)
    assert isinstance(p, CLASSES[name]) and p.name == name
    assert p.host == HOSTS[name] and p.port == 443
    assert p.known_secrets() == (TOKENS[name],)


def test_registry_host_override():
    p = create_provider("openai", OAI, host="127.0.0.1", port=9999)
    assert (p.host, p.port) == ("127.0.0.1", 9999)


@pytest.mark.parametrize("name", TOKENS)
@pytest.mark.parametrize("bad", ["", "abc", "123:ABC", "sk-", None, 5, "ghp_" + "a" * 40])
def test_invalid_token_rejected(name, bad):
    with pytest.raises(ProviderError):
        CLASSES[name](bad)


@pytest.mark.parametrize("name", TOKENS)
def test_token_with_newline_rejected(name):
    with pytest.raises(ProviderError):
        CLASSES[name](TOKENS[name] + "\n")


def test_old_format_tokens_accepted():
    VercelProvider("a" * 24)
    CloudflareProvider("A" * 40)
    CloudflareProvider("cfat_" + "a" * 40 + "deadbeef")
    OpenAIProvider("sk-" + "a" * 48)


# --- таблицы маршрутов ---

@pytest.mark.parametrize("name", TOKENS)
def test_every_api_name_is_valid_for_policy(name):
    assert CLASSES[name].ROUTES
    for api in CLASSES[name].ROUTES:
        assert is_valid_api_name(api), api


@pytest.mark.parametrize("name", TOKENS)
def test_every_route_builds_with_valid_input(name):
    p = _p(name)
    for api, r in p.ROUTES.items():
        body = b""
        if r.params or r.body:
            body = _body(**dict.fromkeys(r.params, ZONE if name == "cloudflare" else "dpl_abc.def-1"))
        req = p.build_request(api, r.client_method, body, JSON if body else None)
        assert req.method == r.method
        assert TOKENS[name] not in req.path


@pytest.mark.parametrize("kw", [
    {"client_method": "PUT", "method": "GET", "path": "/x"},
    {"client_method": "GET", "method": "DELETE", "path": "/x"},
    {"client_method": "GET", "method": "GET", "path": "/x/{a}"},                          # нет params
    {"client_method": "GET", "method": "GET", "path": "/x/{a}", "params": ("a",)},        # params при GET
    {"client_method": "POST", "method": "GET", "path": "/x", "body": True},               # тело при GET upstream
    {"client_method": "GET", "method": "GET", "path": "/x", "body": True},
])
def test_route_validation(kw):
    with pytest.raises(ValueError):
        Route(**kw)


# --- общие проверки сборки запроса ---

@pytest.mark.parametrize("name", TOKENS)
def test_token_only_in_authorization_header(name):
    p = _p(name)
    req = p.build_request(*_first_simple(p))
    assert ("Authorization", f"Bearer {TOKENS[name]}") in req.headers
    assert ("Host", HOSTS[name]) in req.headers
    assert ("Accept-Encoding", "identity") in req.headers
    assert TOKENS[name] not in req.path
    assert all(TOKENS[name] not in v for k, v in req.headers if k != "Authorization")


def _first_simple(p):
    for api, r in p.ROUTES.items():
        if not r.params and not r.body:
            return api, r.client_method, b"", None
    raise AssertionError


@pytest.mark.parametrize("name", TOKENS)
def test_unknown_api_rejected(name):
    with pytest.raises(ProviderError):
        _p(name).build_request("deleteEverything", "GET", b"", None)


@pytest.mark.parametrize("name", TOKENS)
def test_wrong_client_method_rejected(name):
    p = _p(name)
    api, method, _, _ = _first_simple(p)
    with pytest.raises(ProviderError):
        p.build_request(api, "POST" if method == "GET" else "GET", b"", None)


@pytest.mark.parametrize("name", TOKENS)
def test_body_on_bodyless_route_rejected(name):
    p = _p(name)
    api, method, _, _ = _first_simple(p)
    with pytest.raises(ProviderError):
        p.build_request(api, method, b"{}", JSON)


# --- параметры пути (Vercel, Cloudflare) ---

def test_vercel_param_goes_into_path_and_upstream_is_get():
    req = VercelProvider(VCL).build_request("getDeployment", "POST", _body(id="dpl_89qyp1.cskz"), JSON)
    assert (req.method, req.path, req.body) == ("GET", "/v13/deployments/dpl_89qyp1.cskz", b"")
    assert not any(k == "Content-Type" for k, _ in req.headers)


def test_cloudflare_zone_id_in_path():
    req = CloudflareProvider(CF).build_request("listDnsRecords", "POST", _body(zone_id=ZONE), JSON)
    assert req.method == "GET"
    assert req.path == f"/client/v4/zones/{ZONE}/dns_records"


@pytest.mark.parametrize("bad", [
    "..", "../x", "a/b", "a%2fb", "a?b=1", "a#b", "a b", "a\nb", "", ".hidden", "x..y",
    "é", "a" * 129, 5, None, ["a"],
])
def test_vercel_bad_param_rejected(bad):
    with pytest.raises(ProviderError):
        VercelProvider(VCL).build_request("getProject", "POST", _body(id=bad), JSON)


@pytest.mark.parametrize("bad", [ZONE.upper(), ZONE[:-1], ZONE + "0", "../" + ZONE[3:], "x" * 32, 7])
def test_cloudflare_bad_zone_rejected(bad):
    with pytest.raises(ProviderError):
        CloudflareProvider(CF).build_request("getZone", "POST", _body(zone_id=bad), JSON)


def test_missing_param_rejected():
    with pytest.raises(ProviderError):
        CloudflareProvider(CF).build_request("getZone", "POST", _body(), JSON)


def test_extra_fields_rejected_on_param_only_route():
    with pytest.raises(ProviderError):
        CloudflareProvider(CF).build_request("getZone", "POST", _body(zone_id=ZONE, x=1), JSON)


# --- разбор JSON-тела ---

@pytest.mark.parametrize("body,ct", [
    (b"", JSON),
    (b"[]", JSON),
    (b"123", JSON),
    (b"not json", JSON),
    (b'{"a":1,"a":2}', JSON),                      # дубли ключей
    (b'{"a":NaN}', JSON),
    (b'{"a":Infinity}', JSON),
    (b"\xff\xfe", JSON),
    (b'{"a":' + b"[" * 200 + b"]" * 200 + b"}", JSON),
    (b'{"a":1}', None),
    (b'{"a":1}', "text/plain"),
    (b'{"a":1}', "application/x-www-form-urlencoded"),
    (b'{"a":1}', "application/json\r\nX: y"),
    (b'{"a":1}', "application/jsonx"),
])
def test_bad_body_rejected(body, ct):
    with pytest.raises(ProviderError):
        OpenAIProvider(OAI).build_request("chatCompletions", "POST", body, ct)


def test_duplicate_param_key_rejected():
    body = f'{{"zone_id":"{ZONE}","zone_id":"{"f" * 32}"}}'.encode()
    with pytest.raises(ProviderError):
        CloudflareProvider(CF).build_request("getZone", "POST", body, JSON)


def test_content_type_with_charset_accepted():
    OpenAIProvider(OAI).build_request("chatCompletions", "POST", _body(model="m"), "application/json; charset=utf-8")


# --- OpenAI ---

def test_openai_body_is_reserialized_not_forwarded_raw():
    raw = b'{ "model" : "gpt-x",\n "messages":[{"role":"user","content":"\xd0\xbf\xd1\x80\xd0\xb8\xd0\xb2\xd0\xb5\xd1\x82"}] }'
    req = OpenAIProvider(OAI).build_request("chatCompletions", "POST", raw, JSON)
    assert req.path == "/v1/chat/completions" and req.method == "POST"
    assert req.body != raw and req.body.isascii()
    assert json.loads(req.body) == json.loads(raw)
    assert ("Content-Length", str(len(req.body))) in req.headers
    assert ("Content-Type", "application/json") in req.headers


def test_openai_lone_surrogate_does_not_crash():
    req = OpenAIProvider(OAI).build_request("chatCompletions", "POST", b'{"a":"\\ud800"}', JSON)
    assert req.body == b'{"a":"\\ud800"}'


@pytest.mark.parametrize("stream", [True, 1, "true", "yes", [1]])
def test_openai_streaming_rejected(stream):
    with pytest.raises(ProviderError, match="streaming"):
        OpenAIProvider(OAI).build_request("createResponse", "POST", _body(model="m", stream=stream), JSON)


@pytest.mark.parametrize("stream", [False, None])
def test_openai_stream_false_allowed(stream):
    OpenAIProvider(OAI).build_request("createResponse", "POST", _body(model="m", stream=stream), JSON)


def test_openai_long_timeout():
    assert OpenAIProvider(OAI).upstream_timeout("chatCompletions", b"") == 120.0
    assert VercelProvider(VCL).upstream_timeout("getUser", b"") is None


# --- Cloudflare: параметр + тело ---

def test_cloudflare_create_record_forwards_body_without_zone_id():
    rec = {"type": "A", "name": "x.example.com", "content": "203.0.113.1", "ttl": 120}
    req = CloudflareProvider(CF).build_request("createDnsRecord", "POST", _body(zone_id=ZONE, **rec), JSON)
    assert (req.method, req.path) == ("POST", f"/client/v4/zones/{ZONE}/dns_records")
    assert json.loads(req.body) == rec


def test_cloudflare_cannot_redirect_zone_via_body_field():
    other = "f" * 32
    req = CloudflareProvider(CF).build_request(
        "purgeCache", "POST", _body(zone_id=ZONE, purge_everything=True, zone=other), JSON)
    assert req.path == f"/client/v4/zones/{ZONE}/purge_cache"
    assert other not in req.path


# --- фильтр ответа ---

@pytest.mark.parametrize("name", TOKENS)
def test_filter_passes_normal_response(name):
    resp = UpstreamResponse(200, JSON, b'{"success": true, "result": []}')
    assert _p(name).filter_response(resp) is resp


@pytest.mark.parametrize("name", TOKENS)
def test_filter_blocks_token_raw_escaped_and_dup_keys(name):
    p, tok = _p(name), TOKENS[name]
    assert p.filter_response(UpstreamResponse(200, JSON, f'{{"x": "{tok}"}}'.encode())) is None
    escaped = "".join(f"\\u{ord(c):04x}" for c in tok)
    assert p.filter_response(UpstreamResponse(200, JSON, f'{{"x": "{escaped}"}}'.encode())) is None
    assert p.filter_response(UpstreamResponse(200, JSON, f'{{"a":"{tok}","a":"ok"}}'.encode())) is None
    assert p.filter_response(UpstreamResponse(200, None, tok.encode())) is None


# --- конфиг и сквозной запрос через Pipeline ---

def _cfg(tmp_path, text):
    f = tmp_path / "config.toml"
    f.write_text(text, "utf-8")
    return load_config(f)


def test_config_accepts_new_providers(tmp_path):
    cfg = _cfg(tmp_path, "[providers.openai]\n[providers.vercel]\n[providers.cloudflare]\n"
                         "max_response_bytes = 1048576\n")
    names = [(c.name, c.secret_env) for c in cfg.effective_providers()]
    assert names == [("openai", "GATEKEEPER_OPENAI_TOKEN"), ("vercel", "GATEKEEPER_VERCEL_TOKEN"),
                     ("cloudflare", "GATEKEEPER_CLOUDFLARE_TOKEN")]


class _Up:
    def __init__(self):
        self.calls = []
        self.response = UpstreamResponse(200, JSON, b'{"ok":true}')

    def begin_filter(self, resp):
        return True

    def release_response(self, resp):
        return None

    async def fetch(self, req, timeout=None, *, hold=False):
        self.calls.append((req, timeout))
        return self.response


def _pipeline_env(tmp_path, provider_name, allow):
    ca_cert, ca_key = ca.create_ca()
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    cert, _ = ca.issue_client_cert(ca_cert, ca_key, "bot")
    entry = {"fingerprint": cert_fingerprint(cert), "master_secret": MASTER.hex(), "status": "active",
             "created": 0, "expires": unix_now() + 10_000, "allow": allow, "provider": provider_name}
    reg.add("bot", entry)
    prov = _p(provider_name)
    up = _Up()
    pipe = Pipeline(
        identity=IdentityStore(reg, ca_cert), providers={provider_name: prov},
        upstreams={provider_name: up},
        audit=AuditChain(FileSink(tmp_path / "audit.log"), secrets=prov.known_secrets()),
        nonces=NonceCache(), client_limiter=RateLimiter(0.001, 10), budget=DailyBudget(100),
        bans=IpBanList())
    return SimpleNamespace(pipe=pipe, up=up, fp=entry["fingerprint"],
                           der=cert.public_bytes(Encoding.DER))


def _post(env, target, method, body, ct=JSON):
    hdr = build_headers(key=derive_signing_key(MASTER), client_id="bot", cert_fingerprint=env.fp,
                        epoch=0, timestamp=unix_now(), nonce=new_nonce(), method=method,
                        path=target, body=body)
    headers = {k.lower(): v for k, v in hdr.items()}
    headers["host"] = "gw"
    if body:
        headers["content-type"] = ct
    resp = asyncio.run(env.pipe.handle(ParsedRequest(method, target, headers, body), IP, env.der))
    return int(resp.split(b" ", 2)[1])


def test_pipeline_openai_chat_end_to_end(tmp_path):
    env = _pipeline_env(tmp_path, "openai", ["POST:chatCompletions"])
    assert _post(env, "/chatCompletions", "POST", _body(model="m", messages=[])) == 200
    (req, timeout), = env.up.calls
    assert req.path == "/v1/chat/completions" and timeout == 120.0
    assert (("Authorization", f"Bearer {OAI}")) in req.headers
    # стриминг отклоняется до обращения к upstream
    assert _post(env, "/chatCompletions", "POST", _body(model="m", stream=True)) == 400
    assert len(env.up.calls) == 1


def test_pipeline_cloudflare_zone_param_end_to_end(tmp_path):
    env = _pipeline_env(tmp_path, "cloudflare", ["POST:listDnsRecords"])
    assert _post(env, "/listDnsRecords", "POST", _body(zone_id=ZONE)) == 200
    (req, _), = env.up.calls
    assert (req.method, req.path) == ("GET", f"/client/v4/zones/{ZONE}/dns_records")
    assert _post(env, "/listDnsRecords", "POST", _body(zone_id="../../user")) == 400
    assert len(env.up.calls) == 1
    # метод, которого нет в правилах клиента, до провайдера не доходит
    assert _post(env, "/purgeCache", "POST", _body(zone_id=ZONE, purge_everything=True)) == 403
    assert len(env.up.calls) == 1


def test_pipeline_vercel_secret_in_response_blocked(tmp_path):
    env = _pipeline_env(tmp_path, "vercel", ["GET:getUser"])
    env.up.response = UpstreamResponse(200, JSON, f'{{"leak":"{VCL}"}}'.encode())
    assert _post(env, "/getUser", "GET", b"") == 502


# --- маскирование в журнале ---

@pytest.mark.parametrize("secret", [OAI, VCL, CF])
def test_generic_patterns_mask_foreign_tokens(secret):
    from gatekeeper.core.redact import redact_text
    out = redact_text(f"error for key {secret} end")
    assert secret not in out
