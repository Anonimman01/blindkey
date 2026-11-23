"""Определение клиента по отпечатку SHA-256 сертификата из TLS-соединения.

TLS уже проверил цепочку, но шлюз перепроверяет сам (подпись CA, срок, EKU, CN):
идентификацию нельзя строить на User-Agent и подобных заголовках. clients.json
перечитывается при изменении файла, поэтому freeze/revoke действуют без перезапуска.
"""
from __future__ import annotations

import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass

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
_PROVIDER_NAME = re.compile(r"[a-z][a-z0-9_]{0,31}")


@dataclass(frozen=True)
class ClientRecord:
    client_id: str
    fingerprint: str
    master_secret: bytes
    status: str
    expires: int
    policy: Policy
    provider: str | None = None  # имя провайдера клиента; None = первый в конфиге


@dataclass(frozen=True)
class Identity:
    """record задан только при reason == "ok"."""
    fingerprint: str | None
    record: ClientRecord | None
    reason: str
    client_id: str | None = None


def _parse_entry(client_id: str, e: object) -> ClientRecord | None:
    if not isinstance(e, dict):
        return None
    try:
        fp, status, exp = e["fingerprint"], e["status"], e["expires"]
        master = bytes.fromhex(e["master_secret"])
        policy = Policy.from_strings(e["allow"])
        if (not is_valid_client_id(client_id) or not _HEX64.fullmatch(fp)
                or len(master) != constants.MASTER_SECRET_LEN or status not in STATUSES
                or isinstance(exp, bool) or not isinstance(exp, int)):
            return None
        provider = e.get("provider")
        if provider is not None and (not isinstance(provider, str)
                                     or not _PROVIDER_NAME.fullmatch(provider)):
            return None
        return ClientRecord(client_id, fp, master, status, exp, policy, provider)
    except (KeyError, TypeError, ValueError, PolicyError):
        return None  # битая запись = клиент недоступен (fail closed)


class IdentityStore:
    def __init__(self, registry: Registry, ca_cert: x509.Certificate,
                 clock: Callable[[], int] = unix_now,
                 state_frozen: Callable[[str], bool] | None = None) -> None:
        self._registry = registry
        self._state_frozen = state_frozen  # слой автозаморозки в state.db
        self._ca = ca_cert
        self._clock = clock
        # identify вызывается из разных потоков (asyncio.to_thread): снимок реестра и _sig
        # меняются только под замком, иначе два потока могут разойтись в состоянии.
        self._lock = threading.Lock()
        self._sig: object = "unset"
        self._by_fp: dict[str, ClientRecord] = {}
        self.invalid_entries = 0

    def _reload_if_changed(self) -> None:
        try:
            st = os.stat(self._registry.path)
            sig = (st.st_mtime_ns, st.st_size, st.st_ino)
        except FileNotFoundError:
            sig = None
        with self._lock:
            if sig == self._sig:
                return
            self._sig = sig
            by_fp: dict[str, ClientRecord] = {}
            invalid = 0
            try:
                clients = self._registry.load()
            except GatekeeperError:
                clients = {}  # повреждённый реестр: никого не пускаем
            for cid, entry in clients.items():
                rec = _parse_entry(cid, entry)
                if rec is None:
                    invalid += 1
                else:
                    by_fp[rec.fingerprint] = rec
            self._by_fp, self.invalid_entries = by_fp, invalid

    def _lookup(self, fp: str) -> ClientRecord | None:
        self._reload_if_changed()
        with self._lock:
            return self._by_fp.get(fp)

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
        rec = self._lookup(fp)
        if rec is None:
            return Identity(fp, None, "unknown")
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(cn) != 1 or cn[0].value != rec.client_id:
            return Identity(fp, None, "cn_mismatch", rec.client_id)
        if rec.status != "active":  # ручной freeze/revoke из реестра важнее всего
            return Identity(fp, None, "inactive", rec.client_id)
        if self._state_frozen is not None and self._state_frozen(rec.client_id):
            return Identity(fp, None, "inactive", rec.client_id)  # автозаморозка из state.db
        if self._clock() > rec.expires:
            return Identity(fp, None, "expired", rec.client_id)
        return Identity(fp, rec, "ok", rec.client_id)
