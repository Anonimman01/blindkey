"""gatekeeper init: создать каталоги, CA, серверный сертификат, пустой реестр, журнал."""
from __future__ import annotations

import os
from pathlib import Path

from gatekeeper.cli import output
from gatekeeper.core.events import EventType
from gatekeeper.pki import ca
from gatekeeper.server.audit.chain import AuditChain
from gatekeeper.server.audit.sink import FileSink
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


def _mkdir(path: Path, mode: int) -> None:
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    os.chmod(path, mode)


def run(args, layout: Layout) -> int:
    if layout.pki_dir.exists() and any(layout.pki_dir.iterdir()):
        output.error("already initialised (pki dir is not empty)")
        return 1
    ca_key_out = Path(args.ca_key_out)
    if ca_key_out.exists():
        output.error(f"refusing to overwrite {ca_key_out}")
        return 1

    _mkdir(layout.config_dir, 0o750)
    _mkdir(layout.data_dir, 0o700)
    _mkdir(layout.pki_dir, 0o700)
    _mkdir(layout.audit_dir, 0o700)

    ca_cert, ca_key = ca.create_ca()
    srv_cert, srv_key = ca.issue_server_cert(ca_cert, ca_key, args.host)

    # ca.key уходит ТОЛЬКО в указанное место (офлайн-хранилище), на шлюзе его нет.
    ca.write_private_file(ca_key_out, ca.key_to_pem(ca_key))
    ca.write_private_file(layout.ca_cert, ca.cert_to_pem(ca_cert))
    ca.write_private_file(layout.server_cert, ca.cert_to_pem(srv_cert))
    ca.write_private_file(layout.server_key, ca.key_to_pem(srv_key))

    cfg = layout.config_file
    if not cfg.exists():
        ca.write_private_file(cfg, _CONFIG_TEMPLATE.encode("utf-8"))
        os.chmod(cfg, 0o640)
    Registry(layout.clients_file).init_empty()

    AuditChain(FileSink(layout.audit_log)).append(
        EventType.SERVER_STARTED, {"action": "init", "hosts": list(args.host)}
    )
    output.info(f"initialised: config={layout.config_dir} data={layout.data_dir}")
    output.info(f"CA key written to {ca_key_out}: move it OFFLINE, it is not needed on the server")
    return 0
