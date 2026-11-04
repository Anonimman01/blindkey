"""Определение клиента по отпечатку SHA-256 сертификата из TLS-соединения.

TLS уже проверил цепочку, но шлюз перепроверяет сам (подпись CA, срок, EKU, CN):
идентификацию нельзя строить на User-Agent и подобных заголовках. clients.json
перечитывается при изменении файла, поэтому freeze/revoke действуют без перезапуска.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Callable

from cryptography import x509
from cryptography.x509.oid import NameOID

from gatekeeper.core import constants
from gatekeeper.core.errors import GatekeeperError, PolicyError
from gatekeeper.core.signing import is_valid_client_id
from gatekeeper.core.timeutil import unix_now
from gatekeeper.pki import ca as pki_ca
from gatekeeper.pki.fingerprint import fingerprint_from_der
from gatekeeper.server.policy import Policy
from gatekeeper.store.registry import STATUSES, Registry

_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ClientRecord:
    client_id: str
    fingerprint: str
    master_secret: bytes
    status: str
    expires: int
    policy: Policy


@dataclass(frozen=True)
class Identity:
    """record задан только при reason == "ok"."""
    fingerprint: str | None
    record: ClientRecord | None
    reason: str
    client_id: str | None = None


def _parse_entry(client_id: str, e: object) -> ClientRecord | None:
    try:
        fp, status, exp = e["fingerprint"], e["status"], e["expires"]
        master = bytes.fromhex(e["master_secret"])
        policy = Policy.from_strings(e["allow"])
        if (not is_valid_client_id(client_id) or not _HEX64.match(fp)
                or len(master) != constants.MASTER_SECRET_LEN or status not in STATUSES
                or isinstance(exp, bool) or not isinstance(exp, int)):
            return None
        return ClientRecord(client_id, fp, master, status, exp, policy)
    except (KeyError, TypeError, ValueError, PolicyError):
        return None  # битая запись = клиент недоступен (fail closed)


class IdentityStore:
    def __init__(self, registry: Registry, ca_cert: x509.Certificate,
                 clock: Callable[[], int] = unix_now) -> None:
        self._registry = registry
        self._ca = ca_cert
        self._clock = clock
        self._sig: object = "unset"
        self._by_fp: dict[str, ClientRecord] = {}
        self.invalid_entries = 0

    def _reload_if_changed(self) -> None:
        try:
            st = os.stat(self._registry.path)
            sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        except FileNotFoundError:
            sig = None
        if sig == self._sig:
            return
        self._sig = sig
        self._by_fp, self.invalid_entries = {}, 0
        try:
            clients = self._registry.load()
        except GatekeeperError:
            return  # повреждённый реестр: никого не пускаем
        for cid, entry in clients.items():
            rec = _parse_entry(cid, entry)
            if rec is None:
                self.invalid_entries += 1
            else:
                self._by_fp[rec.fingerprint] = rec

    def identify(self, peer_der: bytes | None) -> Identity:
        if not peer_der:
            return Identity(None, None, "no_cert")
        fp = fingerprint_from_der(peer_der)
        try:
            cert = x509.load_der_x509_certificate(peer_der)
        except ValueError:
            return Identity(fp, None, "bad_cert")
        if not pki_ca.validate_client_cert(cert, self._ca):
            return Identity(fp, None, "bad_cert")
        self._reload_if_changed()
        rec = self._by_fp.get(fp)
        if rec is None:
            return Identity(fp, None, "unknown")
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(cn) != 1 or cn[0].value != rec.client_id:
            return Identity(fp, None, "cn_mismatch", rec.client_id)
        if rec.status != "active":
            return Identity(fp, None, "inactive", rec.client_id)
        if self._clock() > rec.expires:
            return Identity(fp, None, "expired", rec.client_id)
        return Identity(fp, rec, "ok", rec.client_id)
