from gatekeeper.core.redact import MASK, redact_obj, redact_text

TOKEN = "123456789:AAH_abcdefghijklmnopqrstuvwxyz012345"


def test_telegram_token_pattern():
    assert TOKEN not in redact_text(f"error for {TOKEN} here")


def test_token_in_url():
    out = redact_text("https://api.telegram.org/bot123:abc/getMe")
    assert "123:abc" not in out and "/getMe" in out


def test_known_secret_str_and_bytes():
    s = b"\x01" * 32
    assert s.hex() not in redact_text(f"k={s.hex()}", [s])
    assert "hunter2hunter2" not in redact_text("pw hunter2hunter2", ["hunter2hunter2"])


def test_short_known_secret_ignored():
    assert redact_text("abc abc", ["ab"]) == "abc abc"


def test_pem_private_key():
    pem = "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"
    assert "MIIB" not in redact_text("x " + pem)


def test_bearer():
    assert "abcdefgh12345" not in redact_text("Authorization: Bearer abcdefgh12345")


def test_sensitive_keys_nested():
    out = redact_obj({"a": {"api_key": "x", "token": "y", "ok": "fine"}, "l": [{"password": "p"}]})
    assert out["a"]["api_key"] == MASK and out["a"]["token"] == MASK
    assert out["a"]["ok"] == "fine" and out["l"][0]["password"] == MASK


def test_does_not_mutate_input():
    src = {"token": "t", "n": [TOKEN]}
    redact_obj(src)
    assert src["token"] == "t" and src["n"] == [TOKEN]


def test_non_str_values_kept():
    assert redact_obj({"n": 5, "b": True, "x": None}) == {"n": 5, "b": True, "x": None}
