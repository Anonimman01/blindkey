"""Несколько провайдеров на одном шлюзе: клиент привязан к своему провайдеру."""
import asyncio
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from test_pipeline import IP, MASTER, FakeUpstream

from gatekeeper.core.kdf import derive_signing_key
from gatekeeper.core.signing import build_headers, new_nonce
from gatekeeper.core.timeutil import unix_now
from gatekeeper.pki import ca
from gatekeeper.pki.fingerprint import cert_fingerprint
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.server.config import ConfigError, load_config
from gatekeeper.server.http_io import ParsedRequest
from gatekeeper.server.identity import IdentityStore
from gatekeeper.server.limits import DailyBudget, IpBanList, RateLimiter
from gatekeeper.server.nonce_cache import NonceCache
from gatekeeper.server.pipeline import Pipeline
from gatekeeper.server.providers.base import UpstreamResponse
from gatekeeper.server.providers.github import GitHubProvider
from gatekeeper.server.providers.telegram import TelegramProvider
from gatekeeper.store.registry import Registry

TG_TOKEN = "123456789:AAH-fakeFAKEfakeFAKEfakeFAKEfake12345"
GH_TOKEN = "ghp_" + "A1b2C3d4E5" * 4


def _env(tmp_path, github_client_provider="github"):
    ca_cert, ca_key = ca.create_ca()
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    clients = {}
    for cid, prov, allow in (("tgbot", "telegram", ["GET:getMe"]),
                             ("ghbot", github_client_provider, ["GET:getUser"])):
        cert, _ = ca.issue_client_cert(ca_cert, ca_key, cid)
        entry = {"fingerprint": cert_fingerprint(cert), "master_secret": MASTER.hex(),
                 "status": "active", "created": 0, "expires": unix_now() + 10_000, "allow": allow}
        if prov is not None:
            entry["provider"] = prov
        reg.add(cid, entry)
        clients[cid] = SimpleNamespace(fp=entry["fingerprint"], der=cert.public_bytes(Encoding.DER))
    tg, gh = TelegramProvider(TG_TOKEN), GitHubProvider(GH_TOKEN)
    ups = {"telegram": FakeUpstream(), "github": FakeUpstream()}
    audit_path = tmp_path / "audit.log"
    p = Pipeline(
        identity=IdentityStore(reg, ca_cert), providers={"telegram": tg, "github": gh},
        upstreams=ups,
        audit=AuditChain(FileSink(audit_path), secrets=tg.known_secrets() + gh.known_secrets()),
        nonces=NonceCache(), client_limiter=RateLimiter(0.001, 10), budget=DailyBudget(100),
        bans=IpBanList())
    return SimpleNamespace(p=p, ups=ups, clients=clients, audit_path=audit_path)


def _call(env, cid, target):
    c = env.clients[cid]
    hdr = build_headers(key=derive_signing_key(MASTER), client_id=cid, cert_fingerprint=c.fp,
                        epoch=0, timestamp=unix_now(), nonce=new_nonce(), method="GET",
                        path=target, body=b"")
    headers = {k.lower(): v for k, v in hdr.items()}
    headers["host"] = "gw"
    resp = asyncio.run(env.p.handle(ParsedRequest("GET", target, headers, b""), IP, c.der))
    return int(resp.split(b" ", 2)[1])


def test_each_client_goes_to_its_own_provider(tmp_path):
    env = _env(tmp_path)
    assert _call(env, "tgbot", "/getMe") == 200
    assert _call(env, "ghbot", "/getUser") == 200
    (tg_req,) = env.ups["telegram"].calls
    (gh_req,) = env.ups["github"].calls
    assert tg_req.path == f"/bot{TG_TOKEN}/getMe"
    assert gh_req.path == "/user"
    assert dict(gh_req.headers)["Authorization"] == f"Bearer {GH_TOKEN}"
    log = env.audit_path.read_text()
    assert TG_TOKEN not in log and GH_TOKEN not in log
    assert '"provider":"github"' in log.replace(" ", "")


def test_foreign_provider_secret_never_reaches_other_upstream(tmp_path):
    env = _env(tmp_path)
    _call(env, "ghbot", "/getUser")
    assert not env.ups["telegram"].calls
    assert TG_TOKEN not in str(env.ups["github"].calls)


def test_response_of_one_provider_filtered_by_that_provider(tmp_path):
    env = _env(tmp_path)
    env.ups["github"].response = UpstreamResponse(200, "application/json",
                                                  ('{"x":"' + GH_TOKEN + '"}').encode())
    assert _call(env, "ghbot", "/getUser") == 502


def test_client_without_provider_uses_default(tmp_path):
    env = _env(tmp_path, github_client_provider=None)  # поле provider нет: первый = telegram
    # запрос уходит к первому провайдеру (telegram), github не вызывается
    assert _call(env, "ghbot", "/getUser") == 200
    assert not env.ups["github"].calls
    assert env.ups["telegram"].calls[0].path == f"/bot{TG_TOKEN}/getUser"


def test_unconfigured_provider_denied(tmp_path):
    env = _env(tmp_path)
    del env.p.providers["github"], env.p.upstreams["github"]
    assert _call(env, "ghbot", "/getUser") == 403
    assert "provider_unavailable" in env.audit_path.read_text()


def test_pipeline_requires_provider():
    with pytest.raises(ValueError):
        Pipeline(identity=None, audit=None, nonces=None, client_limiter=None,  # type: ignore[arg-type]
                 budget=None, bans=None)  # type: ignore[arg-type]


# ---- конфиг ----
def _cfg(tmp_path, text):
    f = tmp_path / "config.toml"
    f.write_text(text, "utf-8")
    return load_config(f)


def test_config_multi_providers(tmp_path):
    cfg = _cfg(tmp_path, '[providers.telegram]\nsecret_env = "TG"\n'
                         '[providers.github]\nsecret_file = "/run/gh"\n')
    tg, gh = cfg.effective_providers()
    assert (tg.name, tg.secret_env) == ("telegram", "TG")
    assert (gh.name, gh.secret_file) == ("github", "/run/gh")


def test_config_default_secret_env_name(tmp_path):
    cfg = _cfg(tmp_path, "[providers.github]\n")
    assert cfg.effective_providers()[0].secret_env == "GATEKEEPER_GITHUB_TOKEN"


def test_config_legacy_single_provider_still_works(tmp_path):
    cfg = _cfg(tmp_path, '[provider]\nname = "github"\n')
    (only,) = cfg.effective_providers()
    assert only.name == "github"
    assert only.secret_env == "GATEKEEPER_UPSTREAM_TOKEN"


@pytest.mark.parametrize("text", [
    '[provider]\nname = "telegram"\n[providers.github]\n',        # оба формата сразу
    "[providers.slack]\n",                                        # неизвестный провайдер
    "[providers.telegram]\nbogus = 1\n",                          # неизвестный ключ
    "[providers.telegram]\nupstream_tls = false\nupstream_host = \"evil.example\"\n",
])
def test_config_rejects_bad_providers(tmp_path, text):
    with pytest.raises(ConfigError):
        _cfg(tmp_path, text)


# ---- гибрид, этап A: явный default, проверка при старте, изоляция провайдеров ----
def test_busy_provider_does_not_block_other(tmp_path):
    env = _env(tmp_path)
    env.p._inflight["github"] = asyncio.Semaphore(0)  # слоты github исчерпаны
    assert _call(env, "ghbot", "/getUser") == 503
    assert not env.ups["github"].calls
    assert _call(env, "tgbot", "/getMe") == 200


def test_unknown_provider_denied_before_budget_is_spent(tmp_path):
    env = _env(tmp_path)
    del env.p.providers["github"], env.p.upstreams["github"]
    assert _call(env, "ghbot", "/getUser") == 403
    assert env.p.budget.try_spend("ghbot")  # бюджет не тронут отказом


def test_confirm_apis_are_per_provider(tmp_path):
    env = _env(tmp_path)
    env.p._provider_confirm = {"telegram": frozenset({"deleteMessage"}), "github": frozenset()}
    assert env.p._needs_confirm("deletemessage", "telegram")
    assert not env.p._needs_confirm("deleteMessage", "github")


def test_provider_metrics_and_log_field(tmp_path):
    from gatekeeper.server.observe import Metrics

    env = _env(tmp_path)
    env.p.metrics = Metrics()
    _call(env, "ghbot", "/getUser")
    text = env.p.metrics.render()
    assert 'gk_upstream_requests_total{provider="github",status="200"} 1' in text


def _registry(tmp_path, entries):
    reg = Registry(tmp_path / "clients.json")
    reg.init_empty()
    for cid, prov in entries:
        e = {"fingerprint": cid.encode().hex().ljust(64, "0")[:64], "master_secret": MASTER.hex(),
             "status": "active", "created": 0, "expires": 2**40, "allow": ["GET:getMe"]}
        if prov:
            e["provider"] = prov
        reg.add(cid, e)
    return reg.path


def test_startup_rejects_client_with_unknown_provider(tmp_path):
    from gatekeeper.server.app import _validate_client_providers

    path = _registry(tmp_path, [("a", "gitlab")])
    with pytest.raises(ConfigError, match="missing from config"):
        _validate_client_providers(registry_path=path, names=("telegram", "github"), default=None)


def test_startup_rejects_implicit_provider_with_several(tmp_path):
    from gatekeeper.server.app import _validate_client_providers

    path = _registry(tmp_path, [("old", None)])
    with pytest.raises(ConfigError, match="default_provider"):
        _validate_client_providers(registry_path=path, names=("telegram", "github"), default=None)
    # явный default или единственный провайдер: можно
    _validate_client_providers(registry_path=path, names=("telegram", "github"), default="telegram")
    _validate_client_providers(registry_path=path, names=("telegram",), default=None)


def test_config_default_and_limits(tmp_path):
    cfg = _cfg(tmp_path, '[server]\ndefault_provider = "github"\n'
                         '[providers.telegram]\n[providers.github]\nmax_inflight = 4\n'
                         'confirm_apis = ["createIssue"]\nmax_response_bytes = 1048576\n')
    assert cfg.default_provider == "github"
    gh = cfg.effective_providers()[1]
    assert (gh.max_inflight, gh.confirm_apis, gh.max_response_bytes) == (4, ("createIssue",), 1048576)


@pytest.mark.parametrize("text", [
    '[server]\ndefault_provider = "slack"\n[providers.telegram]\n',
    "[providers.telegram]\nmax_inflight = 0\n",
    "[providers.telegram]\nmax_inflight = 100000\n",
    "[providers.telegram]\nmax_response_bytes = 10\n",
    "[providers.telegram]\nmax_response_bytes = 9999999999\n",
    '[providers.telegram]\nconfirm_apis = ["bad name!"]\n',
])
def test_config_rejects_bad_hybrid_values(tmp_path, text):
    with pytest.raises(ConfigError):
        _cfg(tmp_path, text)
