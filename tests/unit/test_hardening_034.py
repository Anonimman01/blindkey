"""Регрессионные тесты 0.3.4: N-01…N-06, GK-01…GK-06, SIGTERM (аудиты 0.3.3)."""
import gzip
import json
import os
import stat

import pytest
from test_telegram_provider import TOKEN as TG_TOKEN

from gatekeeper.server.config import ConfigError, load_config
from gatekeeper.server.limits import RateLimiter
from gatekeeper.server.providers.base import ProviderError, UpstreamResponse
from gatekeeper.server.providers.github import GitHubProvider
from gatekeeper.server.providers.telegram import TelegramProvider
from gatekeeper.store.approvals import ApprovalError, Approvals, request_key
from gatekeeper.store.fsperm import FilePermissionError, harden_private_file

GH_TOKEN = "ghp_" + "A1b2C3d4E5" * 4
PROVIDERS = [TelegramProvider(TG_TOKEN), GitHubProvider(GH_TOKEN)]
TOKENS = [TG_TOKEN, GH_TOKEN]
posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")


def _esc(text: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in text)


def _obj(inner: str) -> str:
    """'{' + inner + '}' без форматирования с процентами/фигурными скобками."""
    return "{" + inner + "}"


def _resp(body: str, ct: str = "application/json") -> UpstreamResponse:
    return UpstreamResponse(200, ct, body.encode())


# ---- N-01: короткая secret part отвергается форматом ----
def test_short_secret_part_rejected():
    with pytest.raises(ProviderError):
        TelegramProvider("12345678:12345678")


# ---- GK-02: дубли ключей JSON ----
@pytest.mark.parametrize("idx", [0, 1])
def test_duplicate_keys_block(idx):
    esc = _esc(TOKENS[idx])
    assert PROVIDERS[idx].filter_response(_resp(_obj('"a":"' + esc + '","a":"x"'))) is None
    nested = _obj('"r":[' + _obj('"a":"' + esc + '","a":"x"') + "]")
    assert PROVIDERS[idx].filter_response(_resp(nested)) is None
    assert PROVIDERS[idx].filter_response(_resp('{"a":1,"a":2}')) is None  # fail closed


@pytest.mark.parametrize("idx", [0, 1])
def test_escaped_secret_in_key_blocked(idx):
    assert PROVIDERS[idx].filter_response(_resp(_obj('"' + _esc(TOKENS[idx]) + '":1'))) is None


# ---- N-07: JSON по содержимому, а не по заголовку ----
@pytest.mark.parametrize("idx", [0, 1])
@pytest.mark.parametrize("ct", ["text/json", "application/x-ndjson", "text/plain", None])
def test_escaped_secret_with_odd_content_type(idx, ct):
    body = _obj('"a":"' + _esc(TOKENS[idx]) + '"')
    assert PROVIDERS[idx].filter_response(_resp(body, ct)) is None  # type: ignore[arg-type]


@pytest.mark.parametrize("idx", [0, 1])
def test_ndjson_lines_checked(idx):
    body = '{"x":1}\n' + _obj('"a":"' + _esc(TOKENS[idx]) + '"') + "\n"
    assert PROVIDERS[idx].filter_response(_resp(body, "application/x-ndjson")) is None


@pytest.mark.parametrize("idx", [0, 1])
def test_clean_json_passes(idx):
    ok = _resp('{"ok":true,"result":[{"a":"b"}]}')
    assert PROVIDERS[idx].filter_response(ok) is ok


# ---- GK-01: Content-Encoding ----
def test_gzip_body_not_a_filter_bypass():
    # Сжатое тело не должно доходить до фильтра как «обычное»: апстрим-клиент отказывает
    # (см. test_upstream_rejects_content_encoding), а побайтовая проверка по-прежнему есть.
    raw = gzip.compress(json.dumps({"t": TG_TOKEN}).encode())
    assert TG_TOKEN.encode() not in raw  # именно поэтому нужен отказ на уровне upstream


def test_upstream_rejects_content_encoding():
    import asyncio

    from gatekeeper.server.providers.base import UpstreamRequest
    from gatekeeper.server.upstream import Upstream, UpstreamError

    body = gzip.compress(b'{"ok":true}')

    async def handler(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                     b"Content-Encoding: gzip\r\nContent-Length: %d\r\n"
                     b"Connection: close\r\n\r\n" % len(body) + body)
        await writer.drain()
        writer.close()

    async def scenario():
        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        async with server:
            up = Upstream("127.0.0.1", port, use_tls=False)
            with pytest.raises(UpstreamError, match="unsupported_content_encoding"):
                await up.fetch(UpstreamRequest("GET", "/x", (("Host", "127.0.0.1"),)))

    asyncio.run(scenario())


# ---- N-02 / GK-06: nan/inf и верхние границы ----
def _cfg(tmp_path, body: str):
    p = tmp_path / "config.toml"
    p.write_text(body, "utf-8")
    return load_config(p)


@pytest.mark.parametrize("line", [
    "rate_per_sec = nan", "rate_per_sec = inf", "header_timeout = nan",
    "body_timeout = inf", "max_body_bytes = 100000000000", "burst = 1000000000",
    "max_connections = 1000000000", "daily_budget = 1000000000000",
    "header_timeout = 100000.0", "rate_per_sec = 1e9",
])
def test_config_rejects_nonfinite_and_huge(tmp_path, line):
    with pytest.raises(ConfigError):
        _cfg(tmp_path, f"[limits]\n{line}\n")


def test_config_defaults_still_valid(tmp_path):
    assert _cfg(tmp_path, "").rate_per_sec == 5.0


@pytest.mark.parametrize("rate", [float("nan"), float("inf")])
def test_rate_limiter_rejects_nonfinite(rate):
    with pytest.raises(ValueError):
        RateLimiter(rate, 3)


# ---- N-03 / GK-04: права существующих файлов ----
@posix_only
def test_harden_fixes_mode(tmp_path):
    f = tmp_path / "audit.log"
    f.write_bytes(b"x")
    f.chmod(0o644)
    harden_private_file(f)
    assert stat.S_IMODE(f.stat().st_mode) == 0o600


@posix_only
def test_harden_rejects_symlink_and_dir(tmp_path):
    target = tmp_path / "t"
    target.write_bytes(b"x")
    link = tmp_path / "l"
    link.symlink_to(target)
    with pytest.raises(FilePermissionError):
        harden_private_file(link)
    d = tmp_path / "d"
    d.mkdir()
    with pytest.raises(FilePermissionError):
        harden_private_file(d)


@posix_only
def test_state_db_mode_fixed(tmp_path):
    from gatekeeper.server.state import StateStore

    db = tmp_path / "state.db"
    db.write_bytes(b"")
    db.chmod(0o666)
    st = StateStore(db)
    st.close()
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    for suffix in ("-wal", "-shm"):
        side = tmp_path / ("state.db" + suffix)
        if side.exists():
            assert stat.S_IMODE(side.stat().st_mode) == 0o600


@posix_only
def test_audit_log_mode_fixed(tmp_path):
    from gatekeeper.server.audit.sink import FileSink

    log = tmp_path / "audit.log"
    log.write_bytes(b"")
    log.chmod(0o644)
    FileSink(log).append_line(b"{}")
    assert stat.S_IMODE(log.stat().st_mode) == 0o600


# ---- N-06 / GK-05: валидация approvals.json ----
def _write_items(path, items):
    path.write_text(json.dumps({"version": 1, "items": items}), "utf-8")


@pytest.mark.parametrize("bad", ["str", None, 5, {}, {"status": "approved"}])
def test_malformed_entry_is_approval_error(tmp_path, bad):
    path = tmp_path / "approvals.json"
    _write_items(path, {"a" * 64: bad})
    with pytest.raises(ApprovalError):
        Approvals(path).list_items()


def test_forged_entry_with_mismatched_key_rejected(tmp_path):
    path = tmp_path / "approvals.json"
    key = request_key("c1", "POST", "sendMessage", b"{}")
    entry = {"client": "c2", "method": "POST", "api": "sendMessage", "body_sha256": "0" * 64,
             "body_len": 2, "preview": "", "ip": "1.2.3.4", "status": "approved",
             "created": 1, "expires": 2**40}
    _write_items(path, {key: entry})
    with pytest.raises(ApprovalError):
        Approvals(path).request("c1", "POST", "sendMessage", b"{}", "", "1.2.3.4")


def test_valid_roundtrip_still_works(tmp_path):
    a = Approvals(tmp_path / "approvals.json")
    assert a.request("c1", "POST", "sendMessage", b"{}", "p", "1.2.3.4").state == "new"
    (item,) = a.list_items()
    a.approve(item[0])
    assert a.request("c1", "POST", "sendMessage", b"{}", "p", "1.2.3.4").state == "approved"
