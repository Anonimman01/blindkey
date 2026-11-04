"""mTLS-соединение со шлюзом: одно соединение на запрос, TLS 1.3, pin на наш CA."""
from __future__ import annotations

import socket

from gatekeeper.client.http_io import Response, exchange
from gatekeeper.client.session import Session
from gatekeeper.server.tls import build_client_context


class Transport:
    def __init__(self, session: Session, host: str, port: int, *,
                 server_name: str | None = None, timeout: float = 30.0) -> None:
        self.session, self.host, self.port, self.timeout = session, host, port, timeout
        self.server_name = server_name or host  # должно быть в SAN серверного сертификата
        self._ctx = build_client_context(session.ca_pem, session.cert_pem, session.key_pem)

    def request(self, method: str, target: str, body: bytes = b"",
                content_type: str | None = None, timeout: float | None = None) -> Response:
        headers = [("Host", self.server_name), ("Connection", "close")]
        if body:
            headers += [("Content-Type", content_type or "application/json"),
                        ("Content-Length", str(len(body)))]
        headers += list(self.session.sign_headers(method, target, body).items())
        with socket.create_connection((self.host, self.port), timeout=self.timeout if timeout is None else timeout) as raw:
            with self._ctx.wrap_socket(raw, server_hostname=self.server_name) as tls:
                return exchange(tls, method, target, headers, body)
