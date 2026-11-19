import pytest

from gatekeeper.server.providers import create_provider
from gatekeeper.server.providers.base import ProviderError, UpstreamResponse
from gatekeeper.server.providers.github import GitHubProvider

TOKEN = "ghp_" + "A1b2C3d4E5" * 4
JSON = "application/json"


def _p() -> GitHubProvider:
    return GitHubProvider(TOKEN)


def test_registry_creates_github():
    p = create_provider("github", TOKEN)
    assert isinstance(p, GitHubProvider)
    assert p.host == "api.github.com" and p.port == 443


@pytest.mark.parametrize("bad", ["", "abc", "123:ABC", "ghp_short", None, 5])
def test_invalid_token_rejected(bad):
    with pytest.raises(ProviderError):
        GitHubProvider(bad)


def test_fine_grained_token_accepted():
    GitHubProvider("github_pat_" + "a" * 30)


def test_build_request_puts_token_in_header_only():
    req = _p().build_request("getUser", "GET", b"", None)
    assert req.method == "GET" and req.path == "/user"
    assert ("Authorization", f"Bearer {TOKEN}") in req.headers
    assert TOKEN not in req.path


def test_unknown_api_rejected():
    with pytest.raises(ProviderError):
        _p().build_request("deleteRepo", "GET", b"", None)


def test_wrong_method_rejected():
    with pytest.raises(ProviderError):
        _p().build_request("getUser", "POST", b"", None)


def test_body_rejected():
    with pytest.raises(ProviderError):
        _p().build_request("getUser", "GET", b"{}", JSON)


def test_known_secrets():
    assert _p().known_secrets() == (TOKEN,)


def test_filter_passes_normal_response():
    resp = UpstreamResponse(200, JSON, b'{"login": "octocat"}')
    assert _p().filter_response(resp) is resp


def test_filter_blocks_exact_token():
    resp = UpstreamResponse(200, JSON, f'{{"x": "{TOKEN}"}}'.encode())
    assert _p().filter_response(resp) is None


def test_filter_blocks_foreign_token_shape():
    other = "ghp_" + "Z9y8X7w6V5" * 4
    resp = UpstreamResponse(200, "text/plain", other.encode())
    assert _p().filter_response(resp) is None


def test_filter_blocks_json_escaped_token():
    body = ('{"x": "\\u0067' + TOKEN[1:] + '"}').encode()
    assert _p().filter_response(UpstreamResponse(200, JSON, body)) is None


def test_filter_blocks_too_deep_json():
    body = (b"[" * 100) + (b"]" * 100)
    assert _p().filter_response(UpstreamResponse(200, JSON, body)) is None
