"""B1: подписанные одобрения — шлюз принимает только подпись ключом оператора.

Модель угроз: шлюз и оператор под одним пользователем (или взломанный процесс шлюза) не должен
уметь сам одобрить заявку. Закрытый ключ Ed25519 живёт на машине оператора, шлюз хранит
публичную часть; `require_signed_approvals` по умолчанию выключен, поэтому старое поведение
не меняется.
"""
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from gatekeeper.server.config import ConfigError, load_config
from gatekeeper.store.approvals import (
    APPROVED,
    ApprovalError,
    Approvals,
    load_operator_key,
    load_signing_key,
)

BODY = b'{"chat_id":1,"text":"hi"}'
TTL = 300


class Clock:
    def __init__(self) -> None:
        self.t = 1_000_000

    def __call__(self) -> int:
        return self.t


def make_keys():
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, private_pem, public_pem


def make_store(tmp_path, *, require=True, public_pem=None, clock=None):
    key = load_operator_key(public_pem) if public_pem is not None else None
    return Approvals(tmp_path / "approvals.json", TTL, clock or Clock(),
                     require_signed=require, operator_key=key)


def request(st, body=BODY, client="alice", method="POST", api="sendMessage"):
    return st.request(client, method, api, body, "params", "203.0.113.7")


def test_unsigned_approval_is_refused_when_signatures_are_required(tmp_path):
    _key, _priv, pub = make_keys()
    st = make_store(tmp_path, public_pem=pub)
    rid = request(st).id
    with pytest.raises(ApprovalError):
        st.approve(rid)
    (_rid, entry), = st.list_items()
    assert entry["status"] != APPROVED


def test_operator_signature_authorizes_exactly_one_request(tmp_path):
    key, _priv, pub = make_keys()
    st = make_store(tmp_path, public_pem=pub)
    rid = request(st).id
    st.approve_with_key(rid, key)
    assert request(st).state == "approved"
    assert request(st).state == "new"            # одноразово, как и раньше


def test_signature_is_bound_to_the_body_and_client(tmp_path):
    key, _priv, pub = make_keys()
    st = make_store(tmp_path, public_pem=pub)
    rid = request(st).id
    st.approve_with_key(rid, key)
    assert request(st, body=b'{"chat_id":2,"text":"evil"}').state == "new"
    assert request(st, client="bob").state == "new"
    assert request(st).state == "approved"       # исходное подтверждение цело


def test_signed_by_another_key_is_not_accepted(tmp_path):
    _key, _priv, pub = make_keys()
    other, _other_priv, _other_pub = make_keys()
    st = make_store(tmp_path, public_pem=pub)
    rid = request(st).id
    with pytest.raises(ApprovalError):
        st.approve_with_key(rid, other)
    assert request(st).state == "pending"


def test_unsigned_approved_record_cannot_bypass_the_requirement(tmp_path):
    """Запись, подсунутая в approvals.json вручную, без подписи не действует."""
    _key, _priv, pub = make_keys()
    weak = make_store(tmp_path, require=False)          # старое поведение: без подписи
    rid = request(weak).id
    weak.approve(rid)
    strict = make_store(tmp_path, public_pem=pub)       # шлюз с требованием подписи
    assert request(strict).state == "pending"


def test_offline_signed_document_moves_between_machines(tmp_path):
    """Ключ на машине оператора: подписанный файл применяется на шлюзе без ключа."""
    key, _priv, pub = make_keys()
    operator = make_store(tmp_path, public_pem=pub)
    rid = request(operator).id
    doc = operator.sign(rid, key)
    assert request(operator).state == "pending"          # sign ничего не одобрил
    gateway = make_store(tmp_path, public_pem=pub)
    gateway.import_signed(json.loads(json.dumps(doc)))
    assert request(gateway).state == "approved"


def test_tampered_signed_document_is_rejected(tmp_path):
    key, _priv, pub = make_keys()
    st = make_store(tmp_path, public_pem=pub)
    rid = request(st).id
    doc = st.sign(rid, key)
    doc["entry"]["body_sha256"] = "0" * 64
    with pytest.raises(ApprovalError):
        st.import_signed(doc)


def _tamper(tmp_path, field, value):
    path = tmp_path / "approvals.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    (entry,) = doc["items"].values()
    entry[field] = value
    path.write_text(json.dumps(doc), encoding="utf-8")


def test_tampered_expiry_does_not_extend_the_approval(tmp_path):
    """Правка expires в approvals.json ломает подпись: одобрение не продлевается."""
    key, _priv, pub = make_keys()
    clock = Clock()
    st = make_store(tmp_path, public_pem=pub, clock=clock)
    rid = request(st).id
    st.approve_with_key(rid, key)
    _tamper(tmp_path, "expires", clock() + 10 * 365 * 86400)
    assert request(st).state == "pending"
    assert st.consume("alice", "POST", "sendMessage", BODY) is False


def test_tampered_preview_breaks_the_signature(tmp_path):
    """Подписана вся запись, а не только клиент/метод/API/хеш тела."""
    key, _priv, pub = make_keys()
    st = make_store(tmp_path, public_pem=pub)
    rid = request(st).id
    st.approve_with_key(rid, key)
    _tamper(tmp_path, "preview", '{"chat_id":666}')
    assert request(st).state == "pending"


def test_unknown_field_makes_the_record_invalid(tmp_path):
    key, _priv, pub = make_keys()
    st = make_store(tmp_path, public_pem=pub)
    rid = request(st).id
    st.approve_with_key(rid, key)
    _tamper(tmp_path, "extra", "x")
    assert request(st).state == "new"          # запись отброшена как повреждённая


def test_signed_document_with_a_longer_ttl_is_refused(tmp_path):
    """Одобрение не должно жить дольше ttl шлюза, даже если подписано с большим ttl."""
    key, _priv, pub = make_keys()
    operator = Approvals(tmp_path / "approvals.json", TTL * 2, Clock(), require_signed=True,
                         operator_key=load_operator_key(pub))
    rid = request(operator).id
    doc = operator.sign(rid, key)
    gateway = Approvals(tmp_path / "approvals.json", TTL, Clock(), require_signed=True,
                        operator_key=load_operator_key(pub))
    with pytest.raises(ApprovalError):
        gateway.import_signed(doc)


def test_public_and_private_key_loaders_are_strict(tmp_path):
    key, private_pem, public_pem = make_keys()
    assert load_operator_key(public_pem).public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw) == key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert load_signing_key(private_pem) is not None
    with pytest.raises(ApprovalError):
        load_operator_key(b"not a key")
    with pytest.raises(ApprovalError):
        load_signing_key(public_pem)


def test_require_signed_needs_a_public_key(tmp_path):
    with pytest.raises(ValueError):
        Approvals(tmp_path / "approvals.json", TTL, require_signed=True)


def test_config_requires_a_key_for_signed_approvals(tmp_path):
    p = tmp_path / "c.toml"
    p.write_text("[confirm]\napis = [\"sendMessage\"]\nrequire_signed_approvals = true\n",
                 encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(p)
    p.write_text("[confirm]\napis = [\"sendMessage\"]\nrequire_signed_approvals = true\n"
                 "operator_public_key = \"/etc/gatekeeper/operator.pub\"\n", encoding="utf-8")
    cfg = load_config(p)
    assert cfg.confirm_require_signed and cfg.confirm_operator_key.endswith("operator.pub")
    p.write_text("", encoding="utf-8")
    assert load_config(p).confirm_require_signed is False      # по умолчанию выключено


# ---- CLI: подпись, офлайн-файл, отказ без подписи ----

from gatekeeper.cli.main import main  # noqa: E402


def _cli_env(tmp_path):
    cfg, data, cakey = tmp_path / "cfg", tmp_path / "data", tmp_path / "off" / "ca.key"
    cakey.parent.mkdir()
    base = ["--config-dir", str(cfg), "--data-dir", str(data)]
    assert main([*base, "init", "--host", "127.0.0.1", "--ca-key-out", str(cakey)]) == 0
    return base, cfg, data


def _enable_signed(cfg, public_key_path):
    with (cfg / "config.toml").open("a", encoding="utf-8") as fh:
        fh.write("\n[confirm]\nrequire_signed_approvals = true\n"
                 f"operator_public_key = {str(public_key_path)!r}\n")


def _pending(data, body=BODY):
    return Approvals(data / "approvals.json", TTL).request(
        "alice", "POST", "sendMessage", body, "params", "203.0.113.7").id


def test_cli_refuses_unsigned_approval_and_accepts_the_signature(tmp_path, capsys):
    base, cfg, data = _cli_env(tmp_path)
    _key, private_pem, public_pem = make_keys()
    pub_path, priv_path = tmp_path / "operator.pub", tmp_path / "operator.key"
    pub_path.write_bytes(public_pem)
    priv_path.write_bytes(private_pem)
    _enable_signed(cfg, pub_path)
    rid = _pending(data)
    capsys.readouterr()
    assert main([*base, "approve", "--id", rid]) == 1
    assert "--sign-key" in capsys.readouterr().err
    assert main([*base, "approve", "--id", rid, "--sign-key", str(priv_path)]) == 0
    (_rid, entry), = Approvals(data / "approvals.json", TTL).list_items()
    assert entry["status"] == APPROVED and entry["signature"]["alg"] == "ed25519"


def test_cli_offline_file_carries_the_approval_to_the_gateway(tmp_path, capsys):
    base, cfg, data = _cli_env(tmp_path)
    _key, private_pem, public_pem = make_keys()
    pub_path, priv_path = tmp_path / "operator.pub", tmp_path / "operator.key"
    pub_path.write_bytes(public_pem)
    priv_path.write_bytes(private_pem)
    _enable_signed(cfg, pub_path)
    rid = _pending(data)
    out_file = tmp_path / "approval.json"
    capsys.readouterr()
    assert main([*base, "approve", "--id", rid, "--sign-key", str(priv_path),
                 "--approval-out", str(out_file)]) == 0
    assert out_file.exists()
    (_rid, entry), = Approvals(data / "approvals.json", TTL).list_items()
    assert entry["status"] != APPROVED          # офлайн-подпись ничего не одобрила
    assert main([*base, "approve", "--id", rid, "--approval-file", str(out_file)]) == 0
    store = Approvals(data / "approvals.json", TTL, require_signed=True,
                      operator_key=load_operator_key(public_pem))
    (_r, entry), = store.list_items()
    assert entry["status"] == APPROVED and store.signature_ok(entry)


def test_offline_file_for_another_request_is_refused(tmp_path, capsys):
    """Файл, подписанный для одной заявки, нельзя применить к другой (журнал не врёт)."""
    base, cfg, data = _cli_env(tmp_path)
    _key, private_pem, public_pem = make_keys()
    pub_path, priv_path = tmp_path / "operator.pub", tmp_path / "operator.key"
    pub_path.write_bytes(public_pem)
    priv_path.write_bytes(private_pem)
    _enable_signed(cfg, pub_path)
    first = _pending(data)
    second = _pending(data, b'{"chat_id":2,"text":"hi"}')
    out_file = tmp_path / "approval.json"
    capsys.readouterr()
    assert main([*base, "approve", "--id", first, "--sign-key", str(priv_path),
                 "--approval-out", str(out_file)]) == 0
    capsys.readouterr()
    assert main([*base, "approve", "--id", second, "--approval-file", str(out_file)]) == 1
    assert "another request" in capsys.readouterr().err
    statuses = {rid: e["status"] for rid, e in Approvals(data / "approvals.json", TTL).list_items()}
    assert statuses[first] != APPROVED and statuses[second] != APPROVED
