"""Подтверждения опасных действий (v2).

Метод из `[confirm] apis` шлюз не выполняет сразу: первый запрос создаёт заявку (pending),
оператор на машине шлюза подтверждает её (`gatekeeper approve`), и повтор того же запроса
проходит один раз. Подтверждение привязано к (клиент, метод HTTP, имя API, SHA-256 тела):
изменённое тело или другой клиент подтверждения не получают. Подтверждение одноразовое и живёт
`ttl` секунд. Заявки лежат в approvals.json (0600) под межпроцессным замком; шлюз читает файл на
каждый запрос, поэтому перезапуск не нужен. Клиент подтвердить себя не может: файл доступен
только оператору.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from gatekeeper.core import constants
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.timeutil import unix_now
from gatekeeper.server.audit.sink import _try_lock, _unlock
from gatekeeper.store.atomic import atomic_write_private
from gatekeeper.store.fsperm import FilePermissionError, harden_private_file

_BINARY = getattr(os, "O_BINARY", 0)
PENDING, APPROVED = "pending", "approved"
ID_LEN = 12             # длина показываемого идентификатора заявки (hex)
MIN_ID_PREFIX = 6       # короче префикс в CLI не принимается
MAX_PENDING = 100       # всего заявок и подтверждений в файле
MAX_PER_CLIENT = 20     # на одного клиента
PREVIEW_LEN = 200
# Для параметров подтверждаемого JSON-запроса места больше: оператор должен видеть все
# ключи запроса, а не начало тела (C-04).
PARAM_PREVIEW_LEN = 400
# Подписанное одобрение (B1): Ed25519, отдельный ключ на машине оператора. Шлюз держит
# только публичную часть и принимает одобрение, только если подпись сходится.
SIGN_ALG = "ed25519"
SIGNATURE_FIELDS = frozenset({"alg", "signature", "key_fingerprint", "issued_at"})
_APPROVAL_DOC_VERSION = 1


class ApprovalError(GatekeeperError):
    """Ошибка хранилища подтверждений."""


def request_key(client_id: str, http_method: str, api: str, body: bytes,
                content_type: str = "") -> str:
    """Ключ заявки: хеш от клиента, метода, имени API, хеша тела и Content-Type.

    Content-Type входит в ключ: одно и то же тело как JSON и как form — разные запросы (X-03).
    """
    return request_key_from_hash(client_id, http_method, api,
                                 hashlib.sha256(body).hexdigest(), content_type)


def request_key_from_hash(client_id: str, http_method: str, api: str, body_sha256: str,
                          content_type: str = "") -> str:
    """То же без тела: нужно подписанному документу, где тела нет, а есть только хеш."""
    raw = "\n".join((client_id, http_method, api, body_sha256, content_type)).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def approval_payload(entry: dict, issued_at: int) -> bytes:
    """Канонические байты, которые подписывает оператор и проверяет шлюз.

    Подписывается вся запись, кроме самой подписи, вместе с `issued_at`: подмена любого
    поля, включая `expires`, ломает подпись. Раньше `expires` в подпись не входил, поэтому
    правка срока действия в approvals.json продлевала уже выданное одобрение навсегда.
    """
    body = {k: v for k, v in entry.items() if k != "signature"}
    body["issued_at"] = issued_at
    try:
        return json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, allow_nan=False).encode("ascii")
    except (TypeError, ValueError) as exc:
        raise ApprovalError("approval record cannot be canonicalized") from exc


def operator_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def load_operator_key(pem: bytes) -> Ed25519PublicKey:
    """Публичный ключ оператора (PEM). Ничего, кроме Ed25519, не принимается."""
    try:
        key = serialization.load_pem_public_key(pem)
    except (ValueError, TypeError) as exc:
        raise ApprovalError("operator public key is not a valid PEM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ApprovalError("operator public key must be Ed25519")
    return key


def load_signing_key(pem: bytes) -> Ed25519PrivateKey:
    """Закрытый ключ оператора для подписи одобрения (только на машине оператора)."""
    try:
        key = serialization.load_pem_private_key(pem, password=None)
    except (ValueError, TypeError) as exc:
        raise ApprovalError("signing key is not an unencrypted PEM private key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ApprovalError("signing key must be Ed25519")
    return key


def make_signature(private_key: Ed25519PrivateKey, entry: dict, issued_at: int) -> dict:
    payload = approval_payload(entry, issued_at)
    raw = private_key.sign(payload)
    return {"alg": SIGN_ALG, "signature": base64.b64encode(raw).decode("ascii"),
            "key_fingerprint": operator_key_fingerprint(private_key.public_key()),
            "issued_at": issued_at}


_HEX64 = frozenset("0123456789abcdef")


def _is_hex64(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX64


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hex16(value: object) -> bool:
    return isinstance(value, str) and len(value) == 16 and set(value) <= _HEX64


def _validate_signature(sig: object) -> None:
    if not isinstance(sig, dict) or set(sig) != SIGNATURE_FIELDS:
        raise ValueError("bad signature")
    if sig.get("alg") != SIGN_ALG:
        raise ValueError("bad signature algorithm")
    raw = sig.get("signature")
    if not isinstance(raw, str) or not raw:
        raise ValueError("bad signature value")
    try:
        base64.b64decode(raw, validate=True)
    except (ValueError, TypeError) as exc:
        raise ValueError("bad signature encoding") from exc
    if not _is_hex16(sig.get("key_fingerprint")) or not _is_int(sig.get("issued_at")):
        raise ValueError("bad signature metadata")


# Набор полей записи закрыт: лишний ключ — повреждённая запись, а не запас на будущее.
# Иначе в подписанную запись можно было бы добавить поле, которого нет в подписи.
_ENTRY_FIELDS = frozenset({
    "status", "client", "method", "api", "body_sha256", "body_len", "preview", "ip",
    "content_type", "created", "expires", "signature",
})
_REQUIRED_ENTRY_FIELDS = _ENTRY_FIELDS - {"signature"}


def _validate_entry(key: object, v: object) -> None:
    """Запись должна быть целой и согласованной с ключом (клиент/метод/API/хеш тела)."""
    if not _is_hex64(key) or not isinstance(v, dict):
        raise ValueError("bad entry")
    if set(v) - _ENTRY_FIELDS or _REQUIRED_ENTRY_FIELDS - set(v):
        raise ValueError("bad fields")
    if v.get("status") not in (PENDING, APPROVED):
        raise ValueError("bad status")
    # Записи старого формата (без content_type) считаются повреждёнными и отбрасываются:
    # заявки живут ttl секунд, терять их при обновлении не жалко (миграция не нужна).
    for f in ("client", "method", "api", "preview", "ip", "content_type"):
        if not isinstance(v.get(f), str):
            raise ValueError(f"bad {f}")
    if not _is_hex64(v.get("body_sha256")):
        raise ValueError("bad body_sha256")
    for f in ("body_len", "created", "expires"):
        if not _is_int(v.get(f)):
            raise ValueError(f"bad {f}")
    if v.get("signature") is not None:
        _validate_signature(v["signature"])
    raw = "\n".join((v["client"], v["method"], v["api"], v["body_sha256"],
                     v["content_type"])).encode("utf-8")
    if hashlib.sha256(raw).hexdigest() != key:
        raise ValueError("key does not match entry")


def make_preview(text: str, limit: int = PREVIEW_LEN) -> str:
    """Безопасная для терминала одна строка: непечатаемые символы (в том числе ESC) = '?'."""
    out = "".join(ch if ch.isprintable() else "?" for ch in text[:limit])
    return out + ("…" if len(text) > limit else "")


@dataclass(frozen=True)
class RequestResult:
    state: str   # "approved" (подтверждение израсходовано) | "pending" | "new" | "full"
    id: str


class Approvals:
    def __init__(self, path: str | os.PathLike, ttl: int = 300,
                 clock: Callable[[], int] = unix_now, *,
                 require_signed: bool = False,
                 operator_key: Ed25519PublicKey | None = None) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        if require_signed and operator_key is None:
            raise ValueError("require_signed needs the operator public key")
        self.path, self.ttl, self._clock = Path(path), ttl, clock
        self.require_signed = require_signed
        self._operator_key = operator_key
        self.last_dropped = 0  # сколько повреждённых записей проигнорировано последним чтением

    # ---- подпись оператора (B1) ----
    def signature_ok(self, entry: dict) -> bool:
        """Сходится ли подпись записи с публичным ключом оператора."""
        if self._operator_key is None:
            return False
        sig = entry.get("signature")
        try:
            _validate_signature(sig)
        except ValueError:
            return False
        assert isinstance(sig, dict)
        raw = base64.b64decode(sig["signature"], validate=True)
        try:
            payload = approval_payload(entry, sig["issued_at"])
        except ApprovalError:
            return False
        try:
            self._operator_key.verify(raw, payload)
        except InvalidSignature:
            return False
        return True

    def _authorized(self, entry: dict) -> bool:
        """Подтверждение действует: статус approved и, если требуется, валидная подпись."""
        if entry.get("status") != APPROVED:
            return False
        return self.signature_ok(entry) if self.require_signed else True

    def _check_signature_issued(self, signature: dict) -> None:
        """Подпись должна быть свежей: из неё считается срок действия одобрения."""
        now = self._clock()
        issued = signature["issued_at"]
        if issued > now + constants.MAX_CLOCK_SKEW_SECONDS:
            raise ApprovalError("signed approval is dated in the future")
        if now - issued > self.ttl:
            raise ApprovalError("signed approval is stale")

    # ---- файл ----
    def _read(self) -> tuple[dict[str, dict], int]:
        """Вернуть (годные записи, число выброшенных повреждённых).

        Повреждённая запись больше не ломает весь файл (B-10): она пропускается, а
        `list_items`/`request` перезаписывают файл без неё. Некорректная структура
        самого файла по-прежнему ошибка: иначе его легко принять за пустой.
        """
        try:
            harden_private_file(self.path)  # владелец, не симлинк, режим 0600
        except FilePermissionError as exc:
            raise ApprovalError(f"approvals.json: {exc}") from exc
        try:
            raw = self.path.read_text("utf-8")
        except FileNotFoundError:
            return {}, 0
        try:
            doc = json.loads(raw)
            items = doc["items"]
            if doc.get("version") != 1 or not isinstance(items, dict):
                raise ValueError("bad structure")
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            raise ApprovalError("approvals.json is malformed (fix or delete the file)") from exc
        valid: dict[str, dict] = {}
        dropped = 0
        for key, v in items.items():
            try:
                _validate_entry(key, v)
            except ValueError:
                dropped += 1  # повреждённая/подделанная запись: не даём ей сломать остальные
                continue
            valid[key] = v
        return valid, dropped

    def _save(self, items: dict[str, dict]) -> None:
        data = json.dumps({"version": 1, "items": items}, indent=2, sort_keys=True)
        atomic_write_private(self.path, data.encode("utf-8"))

    @contextmanager
    def _locked(self, timeout: float = 10.0) -> Iterator[None]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock = self.path.with_name(self.path.name + ".lock")
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | _BINARY, 0o600)
        try:
            deadline = time.monotonic() + timeout
            while True:
                try:
                    _try_lock(fd)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise ApprovalError("approvals lock timeout") from None
                    time.sleep(0.005)
            try:
                yield
            finally:
                with suppress(OSError):
                    _unlock(fd)
        finally:
            os.close(fd)

    def _purge(self, items: dict[str, dict]) -> bool:
        now = self._clock()
        dead = [k for k, v in items.items() if v["expires"] <= now]
        for k in dead:
            del items[k]
        return bool(dead)

    # ---- шлюз ----
    def request(self, client_id: str, http_method: str, api: str, body: bytes,
                preview: str, ip: str, content_type: str = "", *,
                consume: bool = True) -> RequestResult:
        """Подтверждение есть: approved. Иначе завести или найти заявку.

        `consume=True` (по умолчанию): подтверждение при этом расходуется. Шлюз вызывает с
        `consume=False`, прогоняет остальные проверки и расходует подтверждение методом
        `consume()` непосредственно перед обращением к upstream (issue #11).
        """
        key = request_key(client_id, http_method, api, body, content_type)
        rid = key[:ID_LEN]
        with self._locked():
            items, dropped = self._read()
            changed = self._purge(items) or dropped > 0
            entry = items.get(key)
            if entry is not None and self._authorized(entry):
                if consume:
                    del items[key]
                    self._save(items)
                elif changed:
                    self._save(items)
                return RequestResult("approved", rid)
            if entry is not None:
                if changed:
                    self._save(items)
                return RequestResult("pending", rid)
            mine = sum(1 for v in items.values() if v.get("client") == client_id)
            if len(items) >= MAX_PENDING or mine >= MAX_PER_CLIENT:
                if changed:
                    self._save(items)
                return RequestResult("full", rid)
            now = self._clock()
            items[key] = {
                "client": client_id, "method": http_method, "api": api,
                "body_sha256": hashlib.sha256(body).hexdigest(), "body_len": len(body),
                "preview": preview, "ip": ip, "status": PENDING,
                "content_type": content_type,
                "created": now, "expires": now + self.ttl,
            }
            self._save(items)
            return RequestResult("new", rid)

    def consume(self, client_id: str, http_method: str, api: str, body: bytes,
                content_type: str = "") -> bool:
        """Израсходовать подтверждение. False, если его уже нет (истекло или взято параллельным
        запросом): одно подтверждение разрешает ровно одно выполнение."""
        key = request_key(client_id, http_method, api, body, content_type)
        with self._locked():
            items, dropped = self._read()
            changed = self._purge(items) or dropped > 0
            entry = items.get(key)
            if entry is None or not self._authorized(entry):
                if changed:
                    self._save(items)
                return False
            del items[key]
            self._save(items)
            return True

    # ---- оператор ----
    def list_items(self) -> list[tuple[str, dict]]:
        """Действующие заявки и подтверждения (id, запись), старые первыми.

        Повреждённые записи пропускаются и удаляются из файла; их число — в `last_dropped`.
        """
        with self._locked():
            items, dropped = self._read()
            if self._purge(items) or dropped:
                self._save(items)
        self.last_dropped = dropped
        return sorted(((k[:ID_LEN], v) for k, v in items.items()), key=lambda t: t[1]["created"])

    def peek(self, prefix: str) -> dict:
        """Показать заявку, ничего не меняя (нужно, чтобы записать журнал до действия)."""
        with self._locked():
            items, _dropped = self._read()
            self._purge(items)
            key = self._resolve(items, prefix)
            return dict(items[key], id=key[:ID_LEN])

    @staticmethod
    def _resolve(items: dict[str, dict], prefix: str) -> str:
        prefix = (prefix or "").lower()
        if len(prefix) < MIN_ID_PREFIX:
            raise ApprovalError(f"id too short (need at least {MIN_ID_PREFIX} characters)")
        found = [k for k in items if k.startswith(prefix)]
        if not found:
            raise ApprovalError("no such request (expired or already handled)")
        if len(found) > 1:
            raise ApprovalError("id is ambiguous")
        return found[0]

    def approve(self, prefix: str, signature: dict | None = None) -> dict:
        """Подтвердить заявку: срок подтверждения отсчитывается от этого момента.

        При `require_signed` одобрение без валидной подписи оператора не выдаётся: шлюз
        и оператор под одним пользователем больше не могут обойти проверку (B1).
        """
        with self._locked():
            items, _dropped = self._read()
            self._purge(items)
            key = self._resolve(items, prefix)
            entry = items[key]
            if entry.get("status") != PENDING:
                raise ApprovalError("already approved")
            if signature is not None:
                _validate_signature(signature)
                # Подпись покрывает всю запись, поэтому expires выводится из подписи до
                # проверки: иначе проверять было бы нечего.
                entry = {**entry, "status": APPROVED,
                         "expires": signature["issued_at"] + self.ttl,
                         "signature": signature}
                if not self.signature_ok(entry):
                    raise ApprovalError("approval signature does not match the operator key")
                self._check_signature_issued(signature)
                items[key] = entry
            elif self.require_signed:
                raise ApprovalError("a signed approval is required: --sign-key or --approval-file")
            else:
                entry["expires"] = self._clock() + self.ttl
                entry["status"] = APPROVED
            self._save(items)
            return dict(entry, id=key[:ID_LEN])

    def sign(self, prefix: str, private_key: Ed25519PrivateKey) -> dict:
        """Подписать заявку, не меняя файл: документ для переноса на машину шлюза.

        Так закрытый ключ остаётся на машине оператора: шлюз получает только файл
        с записью и подписью.
        """
        with self._locked():
            items, _dropped = self._read()
            self._purge(items)
            key = self._resolve(items, prefix)
            entry = dict(items[key])
        if entry.get("status") != PENDING:
            raise ApprovalError("already approved")
        issued_at = self._clock()
        # Срок действия входит в подписываемую запись: подпись фиксирует и его.
        signed = {**entry, "status": APPROVED, "expires": issued_at + self.ttl}
        signature = make_signature(private_key, signed, issued_at)
        return {"version": _APPROVAL_DOC_VERSION, "key": key,
                "entry": {**signed, "signature": signature}}

    def import_signed(self, doc: object) -> dict:
        """Принять подписанный документ: подпись, ключ заявки и поля должны сходиться."""
        if not isinstance(doc, dict) or doc.get("version") != _APPROVAL_DOC_VERSION:
            raise ApprovalError("unknown signed approval format")
        key, entry = doc.get("key"), doc.get("entry")
        if not _is_hex64(key) or not isinstance(entry, dict):
            raise ApprovalError("malformed signed approval")
        try:
            _validate_entry(key, entry)
        except ValueError as exc:
            raise ApprovalError("signed approval record is invalid") from exc
        if entry.get("status") != APPROVED:
            raise ApprovalError("signed approval is not an approval")
        expect = request_key_from_hash(entry["client"], entry["method"], entry["api"],
                                       entry["body_sha256"], entry["content_type"])
        if expect != key:
            raise ApprovalError("signed approval does not match its request")
        if self._operator_key is None or not self.signature_ok(entry):
            raise ApprovalError("signed approval does not match the operator key")
        self._check_signature_issued(entry["signature"])
        issued = entry["signature"]["issued_at"]
        if entry["expires"] > issued + self.ttl:
            # Оператор подписал с большим ttl, чем у этого шлюза: одобрение жило бы дольше.
            raise ApprovalError("signed approval lives longer than the gateway ttl")
        with self._locked():
            items, _dropped = self._read()
            self._purge(items)
            current = items.get(key)
            if current is not None and self._authorized(current):
                raise ApprovalError("already approved")
            if len(items) >= MAX_PENDING and current is None:
                raise ApprovalError("approvals queue is full")
            items[key] = entry
            self._save(items)
        return dict(entry, id=key[:ID_LEN])

    def approve_with_key(self, prefix: str, private_key: Ed25519PrivateKey) -> dict:
        """Подписать и сразу применить одобрение (ключ и шлюз на одной машине)."""
        return self.import_signed(self.sign(prefix, private_key))

    def reject(self, prefix: str) -> dict:
        """Отклонить заявку или отозвать неиспользованное подтверждение."""
        with self._locked():
            items, _dropped = self._read()
            self._purge(items)
            key = self._resolve(items, prefix)
            entry = items.pop(key)
            self._save(items)
            return dict(entry, id=key[:ID_LEN])
