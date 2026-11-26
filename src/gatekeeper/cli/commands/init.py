"""gatekeeper init: создать каталоги, CA, серверный сертификат, пустой реестр, журнал.

Идемпотентен (B-12): недостающие части создаются, существующие не перезаписываются, повторный
запуск на целом каталоге ничего не меняет и возвращает 0. Если сбой случился посередине,
достаточно повторить init: не хватающий серверный сертификат выпускается тем же CA (для этого
нужен `--ca-key` или `--ca-key-out` с ключом CA).

Права существующих каталогов init не меняет — только у тех, которые создал сам (иначе
`--config-dir` с чужими правами молча менял бы их).
"""
from __future__ import annotations

import contextlib
import os
from pathlib import Path

from cryptography import x509

from gatekeeper.cli import output
from gatekeeper.cli.cakey import load_matching_ca_key, read_passphrase
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.core.events import EventType
from gatekeeper.pki import ca
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
from gatekeeper.store.atomic import atomic_write_private
from gatekeeper.store.layout import Layout
from gatekeeper.store.registry import Registry

_CONFIG_TEMPLATE = """\
# gatekeeper: минимальная конфигурация (MVP)
[server]
listen_host = "127.0.0.1"
listen_port = 8443

[provider]
name = "telegram"
# Токен бота: переменная окружения или файл с правами 0400, не в этом файле.
# secret_env = "GATEKEEPER_UPSTREAM_TOKEN"
"""


def _ensure_dir(path: Path, mode: int) -> bool:
    """Создать каталог, если его нет. Существующий не трогаем. True = создан нами."""
    if path.exists():
        if not path.is_dir():
            raise GatekeeperError(f"not a directory: {path}")
        return False
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    os.chmod(path, mode)
    return True


def _hosts_from_cert(path: Path) -> list[str]:
    """SAN существующего серверного сертификата: чтобы продление не теряло имена."""
    try:
        cert = ca.load_cert_pem(path.read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (OSError, GatekeeperError, x509.ExtensionNotFound):
        return []
    return [str(name.value) for name in san
            if isinstance(name, (x509.DNSName, x509.IPAddress))]


def run(args, layout: Layout) -> int:
    hosts = list(getattr(args, "host", None) or [])
    ca_key_out = Path(args.ca_key_out)
    try:
        passphrase = read_passphrase(args)
    except GatekeeperError as exc:
        output.error(str(exc))
        return 1

    try:
        for path, mode in ((layout.config_dir, 0o750), (layout.data_dir, 0o700),
                           (layout.pki_dir, 0o700), (layout.audit_dir, 0o700)):
            _ensure_dir(path, mode)
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1

    created: list[str] = []
    ca_key = None
    try:
        if layout.ca_cert.exists():
            ca_cert = ca.load_cert_pem(layout.ca_cert.read_bytes())
        else:
            if ca_key_out.exists():
                output.error(f"refusing to overwrite {ca_key_out}")
                return 1
            ca_cert, ca_key = ca.create_ca()
            # Ключ первым (issue #10): `ca.pem` без ключа это CA, которым уже нельзя выпускать
            # сертификаты и который нельзя восстановить. Если не удалось записать сам `ca.pem`,
            # только что созданный ключ убираем, и повторный `init` начинает с чистого места.
            ca.write_private_file(ca_key_out, ca.key_to_pem(ca_key, passphrase))
            try:
                ca.write_private_file(layout.ca_cert, ca.cert_to_pem(ca_cert))
            except (GatekeeperError, OSError):
                with contextlib.suppress(OSError):
                    ca_key_out.unlink()
                raise
            created.append("ca")

        if not (layout.server_cert.exists() and layout.server_key.exists()):
            if ca_key is None:
                key_path = Path(args.ca_key) if getattr(args, "ca_key", None) else ca_key_out
                if not key_path.exists():
                    output.error(
                        "server certificate is missing and the CA key is not available: "
                        f"pass it with --ca-key (or put it at {ca_key_out})")
                    return 1
                ca_key = load_matching_ca_key(key_path, passphrase, ca_cert)
            issue_hosts = hosts or _hosts_from_cert(layout.server_cert)
            if not issue_hosts:
                output.error("at least one --host is required to issue the server certificate")
                return 1
            cert, key = ca.issue_server_cert(ca_cert, ca_key, issue_hosts)
            atomic_write_private(layout.server_cert, ca.cert_to_pem(cert))
            atomic_write_private(layout.server_key, ca.key_to_pem(key))
            created.append("server")
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1

    cfg = layout.config_file
    if not cfg.exists():
        ca.write_private_file(cfg, _CONFIG_TEMPLATE.encode("utf-8"))
        os.chmod(cfg, 0o640)
        created.append("config")
    try:
        if not layout.clients_file.exists():
            Registry(layout.clients_file).init_empty()
            created.append("registry")
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1

    try:
        fresh_log = not layout.audit_log.exists() or layout.audit_log.stat().st_size == 0
    except OSError as exc:
        output.error(str(exc))
        return 1
    try:
        chain = AuditChain(FileSink(layout.audit_log))
        if fresh_log or created:
            chain.append(EventType.SERVER_STARTED,
                         {"action": "init", "hosts": hosts, "created": created})
    except (GatekeeperError, OSError) as exc:
        output.error(str(exc))
        return 1

    if not created and not fresh_log:
        output.info(f"already initialised: config={layout.config_dir} "
                    f"data={layout.data_dir} (nothing to change)")
        return 0
    output.info(f"initialised: config={layout.config_dir} data={layout.data_dir}"
                + (f" (created: {', '.join(created)})" if created else ""))
    if "ca" in created:
        output.info(f"CA key written to {ca_key_out}: move it OFFLINE, it is not needed on the server")
        if passphrase is None:
            output.info("warning: ca.key was written WITHOUT a passphrase; keep it offline, or "
                        "re-run init with --ca-key-pass-file (or GATEKEEPER_CA_KEY_PASSPHRASE) "
                        "to store it encrypted")
    return 0
