"""gatekeeper renew-server: перевыпустить серверный сертификат шлюза (C-03).

Серверный сертификат живёт 365 дней; без продления клиенты перестанут подключаться.
SAN берутся из текущего сертификата, если не передан `--host`. Старые `server.pem` и
`server.key` заменяются атомарно (0600); после этого нужен перезапуск шлюза. CA-сертификат
не меняется, поэтому клиентские пакеты остаются действительными.
"""
from __future__ import annotations

from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path

from gatekeeper.cli import output
from gatekeeper.cli.cakey import load_matching_ca_key, read_passphrase
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.events import EventType
from gatekeeper.pki import ca
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.store.atomic import atomic_write_private
from gatekeeper.store.layout import Layout


def _existing_hosts(layout: Layout) -> list[str]:
    try:
        cert = ca.load_cert_pem(layout.server_cert.read_bytes())
    except (OSError, GatekeeperError):
        return []
    return ca.cert_hosts(cert)


def _read_or_none(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def _replace_pair(cert_path: Path, cert_pem: bytes, key_path: Path, key_pem: bytes) -> None:
    """Заменить сертификат и ключ как пару (issue #8).

    Две отдельные атомарные записи при сбое между ними оставляли новый сертификат со старым
    ключом (или наоборот), и шлюз не стартовал. Теперь при ошибке второй записи возвращается
    прежнее содержимое обоих файлов. Обрыв процесса ровно между записями так не закрыть, но
    старая пара остаётся в памяти этой функции, а шлюз при запуске отказывается стартовать на
    несовпадающей паре с понятной ошибкой.
    """
    old_cert, old_key = _read_or_none(cert_path), _read_or_none(key_path)
    try:
        atomic_write_private(cert_path, cert_pem)
        atomic_write_private(key_path, key_pem)
    except OSError:
        for path, old in ((cert_path, old_cert), (key_path, old_key)):
            if old is not None:
                with suppress(OSError):
                    atomic_write_private(path, old)
        raise


def run(args, layout: Layout) -> int:
    if not 1 <= args.days <= 3650:
        output.error("--days must be between 1 and 3650")
        return 1
    hosts = list(getattr(args, "host", None) or []) or _existing_hosts(layout)
    if not hosts:
        output.error("no --host given and the current server certificate has no SAN to reuse")
        return 1
    try:
        passphrase = read_passphrase(args)
        ca_cert = ca.load_cert_pem(layout.ca_cert.read_bytes())
        ca_key = load_matching_ca_key(Path(args.ca_key), passphrase, ca_cert)
        cert, key = ca.issue_server_cert(ca_cert, ca_key, hosts, days=args.days)
        if not ca.key_matches_cert(key, cert):  # страховка: пара обязана совпадать до записи
            raise GatekeeperError("internal error: new server certificate does not match its key")
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1

    try:
        _replace_pair(layout.server_cert, ca.cert_to_pem(cert), layout.server_key, ca.key_to_pem(key))
    except OSError as exc:
        output.error(f"cannot write the new server certificate: {exc}")
        return 1
    not_after = ca.cert_not_after(cert).strftime("%Y-%m-%d")
    try:
        AuditChain(FileSink(layout.audit_log), secrets=()).append(
            EventType.SERVER_CERT_RENEWED,
            {"hosts": hosts, "days": args.days, "not_after": not_after})
    except (GatekeeperError, OSError) as exc:
        output.info("server certificate replaced")
        output.error(f"WARNING: the new certificate is in place but not recorded in the journal: {exc}")
        return 0
    output.info(f"server certificate renewed for {', '.join(hosts)}: valid until {not_after} "
                f"({args.days} days)")
    output.info("restart the gateway (systemctl restart gatekeeper) to use the new certificate")
    output.info(f"renewed at {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC")
    return 0
