# BlindKey / gatekeeper: mTLS API-key gateway for bots, scripts and AI agents

**Language:** English · [Русский](README.ru.md)

[![CI](https://github.com/Anonimman01/blindkey/actions/workflows/ci.yml/badge.svg)](https://github.com/Anonimman01/blindkey/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Anonimman01/blindkey/actions/workflows/codeql.yml/badge.svg)](https://github.com/Anonimman01/blindkey/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)

**BlindKey** (PyPI: `blindkey`, command: `gatekeeper` or `blindkey`) is a small self-hosted Python gateway that sits in
front of third-party APIs and keeps your **real API token off the machines that use it**. Your bot,
script or AI agent never sees the Telegram, GitHub, OpenAI, Vercel or Cloudflare token. It gets a
revocable client certificate and an allowlist of API methods instead. If the client is compromised,
you revoke one certificate. The token is not leaked, and does not need to be rotated.

Typical uses: a **Telegram bot token proxy**, an **OpenAI API key proxy for AI agents**, a
**secretless credential gateway** for CI jobs and scripts, per-client allowlists for the GitHub API.

## How it works

```
 bot / script / AI agent                 gatekeeper (your server)                 upstream API
 -----------------------                 ------------------------                 ------------
 client certificate (mTLS)  ──TLS 1.3──▶ verify cert + HMAC signature
 signed request, no token                check allowlist, rate limit, budget
                                         [dangerous method? wait for operator]
                                         add the real token  ───────────────────▶ api.telegram.org
                                         filter response for token leaks  ◀─────── api.github.com ...
 response                      ◀──────── write hash-chained audit log
```

## Features

- **mTLS (TLS 1.3 only)** with your own CA: each client gets a revocable certificate.
- **HMAC-SHA256 request signing** bound to the certificate fingerprint, with replay protection
  (nonce cache and a ±30 s time window).
- **Per-client allowlist** of `METHOD:api` rules. The upstream path comes from the rule, never from
  the client request, so there is no SSRF through the gateway.
- **Response filter**: a response that contains the gateway's token is blocked (502) and logged.
  Compressed responses and duplicate-key JSON tricks are rejected rather than inspected.
- **Hash-chained audit log** with size-based rotation, truncated-tail recovery and external
  anchors (`audit-anchor`, `audit-verify`).
- **Decoys (honeytokens)**: a client that uses a decoy credential is caught and its IP banned.
- **Operator confirmation** for dangerous methods (`[confirm]`): the request waits until an
  operator runs `gatekeeper approve`.
- **Rate limits, daily request budget, anomaly counters and auto-freeze** of misbehaving clients.
- **Several providers on one gateway**: Telegram Bot API, GitHub, OpenAI, Vercel, Cloudflare.
  Each client is bound to one provider.
- Small footprint: Python 3.11+, two runtime dependencies (`cryptography`, `h11`),
  hash-pinned lock files, Apache-2.0.

## Supported providers

| Provider | Typical use |
|---|---|
| Telegram Bot API | keep the bot token off the bot host and off the app that talks to Telegram |
| GitHub | give scripts and agents a narrow slice of the GitHub API |
| OpenAI | keep the OpenAI API key away from agents and per-project runtimes |
| Vercel | limited access to selected Vercel API calls |
| Cloudflare | limited access to selected Cloudflare API calls |

## Quick start (Linux)

    pip install blindkey

The PyPI distribution is called `blindkey`. The command is `gatekeeper` (alias: `blindkey`) and the
Python package is `gatekeeper`. Do **not** run `pip install gatekeeper`: that name on PyPI belongs
to a different project. To work from a checkout with hash-pinned dependencies:

    git clone https://github.com/Anonimman01/blindkey
    cd blindkey
    python -m venv .venv && source .venv/bin/activate
    pip install --require-hashes -r requirements.lock
    pip install --no-deps -e .

Create the CA and the gateway certificate, add a client, start the gateway:

    useradd --system --create-home gatekeeper && su - gatekeeper
    export GATEKEEPER_CONFIG_DIR=$HOME/etc GATEKEEPER_DATA_DIR=$HOME/data

    gatekeeper init --host 203.0.113.10 --host gw.example.com --ca-key-out /safe/ca.key
    gatekeeper add-client --id mybot --ca-key /safe/ca.key --out ./mybot-bundle \
        --allow GET:getMe --allow POST:sendMessage
    export GATEKEEPER_UPSTREAM_TOKEN='123456:ABC...'
    gatekeeper run

Copy `mybot-bundle` to the bot's machine over a secure channel. `client.key` and `master.secret`
are secrets. A client example is in [examples/client_send_message.py](examples/client_send_message.py),
and all settings are in [examples/config.example.toml](examples/config.example.toml).

Production use is Linux only (file permissions 0600/0700 are enforced there). Windows works for
development. The full operator guide is currently in Russian: [README.ru.md](README.ru.md).

## Status and security

- Beta (0.3.x). The test suite has 700+ tests and CI runs lint, type checks, `pip-audit`,
  CodeQL and a lock-file drift check.
- The project has been through several internal and external audit passes. There is **no formal
  third-party certification or penetration test**. Findings and fixes are tracked in
  [docs/SECURITY-HISTORY.md](docs/SECURITY-HISTORY.md); the threat model is in
  [docs/threat-model.md](docs/threat-model.md).
- All provider secrets live in the memory of one gateway process. Compromising the gateway host
  compromises every configured provider token.
- Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Documentation

- [README.ru.md](README.ru.md): full guide in Russian (install, config, providers, audit log, decoys, limits)
- [SECURITY.md](SECURITY.md), [docs/threat-model.md](docs/threat-model.md)
- [CHANGELOG.md](CHANGELOG.md)

## License

Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
