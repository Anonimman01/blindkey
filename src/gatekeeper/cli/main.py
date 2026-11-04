"""Точка входа CLI: gatekeeper <команда>."""
from __future__ import annotations

import argparse
import sys

from gatekeeper.cli import output
from gatekeeper.cli.commands import (
    add_client, audit_verify, client_status, decoy_create, init, list_clients, renew, run,
)
from gatekeeper.store.layout import Layout


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gatekeeper")
    p.add_argument("--config-dir", help="по умолчанию /etc/gatekeeper")
    p.add_argument("--data-dir", help="по умолчанию /var/lib/gatekeeper")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="создать каталоги, CA и серверный сертификат")
    s.add_argument("--host", action="append", required=True, help="DNS-имя или IP шлюза (можно несколько)")
    s.add_argument("--ca-key-out", required=True, help="куда записать ca.key (храните офлайн)")
    s.set_defaults(func=init.run)

    s = sub.add_parser("add-client", help="выпустить пакет клиента")
    s.add_argument("--id", required=True)
    s.add_argument("--ca-key", required=True, help="путь к ca.key")
    s.add_argument("--out", required=True, help="каталог для пакета клиента")
    s.add_argument("--days", type=int, default=90)
    s.add_argument("--allow", action="append", default=[], help="METHOD:path, например POST:sendMessage")
    s.set_defaults(func=add_client.run)

    for name, fn, text in (("freeze", client_status.freeze, "временно заблокировать клиента"),
                           ("unfreeze", client_status.unfreeze, "снять блокировку"),
                           ("revoke", client_status.revoke, "отозвать клиента навсегда")):
        s = sub.add_parser(name, help=text)
        s.add_argument("--id", required=True)
        s.set_defaults(func=fn)

    s = sub.add_parser("renew", help="выпустить клиенту новый сертификат и ключ (права сохраняются)")
    s.add_argument("--id", required=True)
    s.add_argument("--ca-key", required=True, help="путь к ca.key")
    s.add_argument("--out", required=True, help="каталог для нового пакета")
    s.add_argument("--days", type=int, default=90)
    s.set_defaults(func=renew.run)

    s = sub.add_parser("list-clients")
    s.set_defaults(func=list_clients.run)

    s = sub.add_parser("audit-verify")
    s.set_defaults(func=audit_verify.run)

    s = sub.add_parser("decoy-create", help="создать приманку (фальшивый пакет клиента)")
    s.add_argument("--name", required=True)
    s.add_argument("--ca-key", required=True, help="путь к ca.key")
    s.add_argument("--out", required=True, help="каталог для пакета приманки")
    s.add_argument("--days", type=int, default=365)
    s.add_argument("--hint", default="", help="где вы её разместили (для журнала)")
    s.set_defaults(func=decoy_create.run)

    s = sub.add_parser("run", help="запустить шлюз")
    s.set_defaults(func=run.run)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    layout = Layout.from_args(args.config_dir, args.data_dir)
    try:
        return args.func(args, layout)
    except Exception as exc:  # последний рубеж: без трейсбека с возможными данными
        output.error(f"{type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
