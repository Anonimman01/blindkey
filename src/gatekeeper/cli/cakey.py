"""Парольная фраза для `ca.key` (C-09).

Корневой ключ CA нужен только в операциях выпуска (`init`, `add-client`, `renew`,
`decoy-create`, `renew-server`). Хранить его незашифрованным не обязательно: `ca.key`
шифруется PKCS8, а фраза передаётся файлом (`--ca-key-pass-file`, права не шире 0600)
или переменной окружения `GATEKEEPER_CA_KEY_PASSPHRASE`. Фраза не пишется ни в журнал,
ни в вывод CLI.
"""
from __future__ import annotations

import os
import stat
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from gatekeeper.core.errors import GatekeeperError
from gatekeeper.pki import ca

ENV_PASSPHRASE = "GATEKEEPER_CA_KEY_PASSPHRASE"


class CaKeyError(GatekeeperError):
    """Ошибка чтения фразы или ключа CA."""


def read_passphrase(args) -> bytes | None:
    """Прочитать фразу: файл важнее переменной окружения. None = ключ без пароля."""
    path = getattr(args, "ca_key_pass_file", None)
    if path:
        try:
            st = os.stat(path)
            if os.name != "nt" and st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise CaKeyError(
                    "CA key passphrase file must not be accessible to group/others (chmod 0400)")
            value = Path(path).read_text("utf-8").rstrip("\r\n")
        except OSError as exc:
            raise CaKeyError("cannot read CA key passphrase file") from exc
        if not value:
            raise CaKeyError("CA key passphrase file is empty")
        return value.encode("utf-8")
    value = os.environ.get(ENV_PASSPHRASE, "")
    return value.encode("utf-8") if value else None


def load_matching_ca_key(path: str | os.PathLike, passphrase: bytes | None,
                         ca_cert: x509.Certificate) -> ec.EllipticCurvePrivateKey:
    """Загрузить `ca.key` и убедиться, что он относится к `ca.pem` (issue #7).

    Ключ от другого CA выпускал бы сертификаты с именем издателя из `ca.pem`, но подписанные
    чужим ключом: клиент получил бы пакет, который шлюз никогда не примет.
    """
    key = load_ca_key(path, passphrase)
    if not ca.key_matches_cert(key, ca_cert):
        raise CaKeyError("this CA key does not match ca.pem")
    return key


def load_ca_key(path: str | os.PathLike, passphrase: bytes | None) -> ec.EllipticCurvePrivateKey:
    """Загрузить `ca.key` (зашифрованный или нет). Ошибка = понятный PkiError."""
    try:
        pem = Path(path).read_bytes()
    except OSError as exc:
        raise CaKeyError("cannot read CA key") from exc
    return ca.load_key_pem(pem, password=passphrase)
