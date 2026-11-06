"""Тесты политики: белый список и защита от SSRF."""
import pytest

from gatekeeper.core.errors import PolicyError
from gatekeeper.server.policy import Policy, parse_rule


def make():
    return Policy.from_strings(["POST:sendMessage", "GET:getMe"])


def test_allowed_request():
    d = make().check("POST", "/sendMessage")
    assert d is not None and d.api_name == "sendMessage"


def test_method_not_in_whitelist():
    assert make().check("GET", "/sendMessage") is None
    assert make().check("POST", "/getMe") is None
    assert make().check("DELETE", "/sendMessage") is None


def test_unknown_path():
    assert make().check("POST", "/deleteWebhook") is None


def test_case_sensitive():
    assert make().check("POST", "/sendmessage") is None
    assert make().check("post", "/sendMessage") is None


@pytest.mark.parametrize(
    "target",
    [
        "sendMessage",                      # без слэша
        "//sendMessage",
        "/sendMessage/",
        "/sendMessage?chat_id=1",           # query
        "/sendMessage#x",
        "/sendMessage%00",
        "/%73endMessage",                   # процент-кодирование
        "/../sendMessage",
        "/./sendMessage",
        "/x/../sendMessage",
        "/bot123:TOKEN/sendMessage",        # SSRF: чужой токен/префикс
        "http://evil.example/sendMessage",  # абсолютный URL
        "https://api.telegram.org/sendMessage",
        "/sendMessage\r\nHost: evil",
        "/sendMessage ",
        "/sendMessage\n",                   # завершающий \n (раньше $ его пропускал)
        "/sendMessage\r",                   # завершающий \r
        "/sendMessage\x00",
        "/sendMessageé",
        "/" + "a" * 500,
        "",
        "*",
    ],
)
def test_ssrf_and_malformed_targets_denied(target):
    assert make().check("POST", target) is None


def test_non_string_inputs_denied():
    assert make().check(None, "/sendMessage") is None
    assert make().check("POST", None) is None
    assert make().check(b"POST", "/sendMessage") is None


def test_upstream_name_comes_from_rule_not_request():
    d = make().check("POST", "/sendMessage")
    assert d.api_name is d.rule.api_name or d.api_name == d.rule.api_name


def test_empty_policy_denies_everything():
    assert Policy.from_strings([]).check("POST", "/sendMessage") is None


@pytest.mark.parametrize(
    "bad",
    ["", "POST", "POST:", ":sendMessage", "post:sendMessage", "PUT:sendMessage",
     "POST:send Message", "POST:../x", "POST:a/b", "POST:1abc", "POST:a:b", "POST:sendMessage\n", "POST:sendMessage\r", None, 5],
)
def test_parse_rule_rejects_bad(bad):
    with pytest.raises(PolicyError):
        parse_rule(bad)


def test_from_strings_rejects_non_list_and_bad_rule():
    with pytest.raises(PolicyError):
        Policy.from_strings("POST:sendMessage")
    with pytest.raises(PolicyError):
        Policy.from_strings(["POST:sendMessage", "oops"])
