"""Пакет клиента (ca.pem, client.pem, client.key, master.secret) и подпись запросов."""
from __future__ import annotations

import os
import stat
import warnings
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.kdf import derive_signing_key
from gatekeeper.core.signing import build_headers, new_nonce
from gatekeeper.core.timeutil import unix_now
from gatekeeper.pki.fingerprint import cert_fingerprint


def _warn_loose_permissions(path: Path) -> None:
    """Пакет могли скопировать с другими правами: предупреждаем, но не отказываем."""
    if os.name == "nt":
        return
    try:
        mode = os.stat(path).st_mode
    except OSError:
        return
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        warnings.warn(f"{path.name} is accessible to group/others (chmod 600 recommended)",
                      RuntimeWarning, stacklevel=3)


class Session:
    def __init__(self, bundle_dir: str | Path) -> None:
        d = Path(bundle_dir)
        self.ca_pem, self.cert_pem, self.key_pem = d / "ca.pem", d / "client.pem", d / "client.key"
        self.master_path = d / "master.secret"
        try:
            cert = x509.load_pem_x509_certificate(self.cert_pem.read_bytes())
            master = bytes.fromhex(self.master_path.read_text("ascii").strip())
        except (OSError, ValueError) as exc:
            raise GatekeeperError("cannot read client bundle") from exc
        if not master:
            raise GatekeeperError("master.secret is empty")
        for private in (self.key_pem, self.master_path):
            _warn_loose_permissions(private)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(cn) != 1:
            raise GatekeeperError("client certificate must have exactly one CN")
        cn_value = cn[0].value
        if not isinstance(cn_value, str):
            raise GatekeeperError("client certificate CN must be text")
        self.client_id: str = cn_value
        self.fingerprint = cert_fingerprint(cert)
        self._key = derive_signing_key(master, 0)

    def sign_headers(self, method: str, target: str, body: bytes) -> dict[str, str]:
        """Подписывается метод и request-target как есть (например "/sendMessage")."""
        return build_headers(
            key=self._key, client_id=self.client_id, cert_fingerprint=self.fingerprint,
            epoch=0, timestamp=unix_now(), nonce=new_nonce(), method=method, path=target, body=body)
