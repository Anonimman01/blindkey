"""JSON-потолок тела: старый конфиг с малым max_body_bytes не ломается, действует min."""
import asyncio

from gatekeeper.server.config import load_config
from gatekeeper.server.http_io import HttpError, HttpLimits, read_request


def _cfg(tmp_path, text):
    f = tmp_path / "config.toml"
    f.write_text(text, encoding="utf-8")
    return load_config(f)


def test_old_config_with_small_max_body_bytes_loads(tmp_path):
    cfg = _cfg(tmp_path, "[limits]\nmax_body_bytes = 1024\n")
    assert cfg.max_body_bytes == 1024
    # max_json_body_bytes по умолчанию больше общего потолка — это не ошибка конфига.
    assert cfg.max_json_body_bytes > cfg.max_body_bytes


def test_effective_json_limit_is_the_minimum(tmp_path):
    cfg = _cfg(tmp_path, "[limits]\nmax_body_bytes = 1024\n")
    limits = HttpLimits(max_body=cfg.max_body_bytes, max_json_body=cfg.max_json_body_bytes)
    raw = (b"POST /x HTTP/1.1\r\nHost: gw\r\nContent-Type: application/json\r\n"
           b"Content-Length: 2048\r\n\r\n" + b"a" * 2048)

    async def go():
        reader = asyncio.StreamReader()
        reader.feed_data(raw)
        return await read_request(reader, limits)

    try:
        asyncio.run(go())
    except HttpError as exc:
        assert exc.status == 413  # сработал меньший (общий) потолок 1024
    else:
        raise AssertionError("expected 413")
