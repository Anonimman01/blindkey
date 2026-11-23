"""Точка входа CLI: gatekeeper <команда>."""
from __future__ import annotations

import argparse
import sys

from gatekeeper.cli import output
from gatekeeper.cli.commands import (
    add_client,
    audit_anchor,
    audit_repair,
    audit_verify,
    client_status,
    confirm,
    decoy_create,
    init,
    list_clients,
    renew,
    renew_server,
    run,
    status,
)
from gatekeeper.server.providers import KNOWN_PROVIDERS
from gatekeeper.store.layout import Layout

_PASS_FILE_HELP = ("файл с паролем ca.key (права не шире 0400); по умолчанию "
                   "переменная окружения GATEKEEPER_CA_KEY_PASSPHRASE")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="gatekeeper")
    p.add_argument("--config-dir", help="по умолчанию /etc/gatekeeper")
    p.add_argument("--data-dir", help="по умолчанию /var/lib/gatekeeper")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="создать каталоги, CA и серверный сертификат (можно повторять)")
    s.add_argument("--host", action="append", help="DNS-имя или IP шлюза (можно несколько)")
    s.add_argument("--ca-key-out", required=True, help="куда записать ca.key (храните офлайн)")
    s.add_argument("--ca-key", help="ключ CA для завершения прерванного init (по умолчанию --ca-key-out)")
    s.add_argument("--ca-key-pass-file", help=_PASS_FILE_HELP)
    s.set_defaults(func=init.run)

    s = sub.add_parser("add-client", help="выпустить пакет клиента")
    s.add_argument("--id", required=True)
    s.add_argument("--ca-key", required=True, help="путь к ca.key")
    s.add_argument("--ca-key-pass-file", help=_PASS_FILE_HELP)
    s.add_argument("--out", required=True, help="каталог для пакета клиента")
    s.add_argument("--days", type=int, default=90)
    s.add_argument("--allow", action="append", default=[], help="METHOD:path, например POST:sendMessage")
    s.add_argument("--provider", choices=list(KNOWN_PROVIDERS), default=None,
                   help="провайдер клиента (если на шлюзе их несколько); по умолчанию первый в конфиге")
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
    s.add_argument("--ca-key-pass-file", help=_PASS_FILE_HELP)
    s.add_argument("--out", required=True, help="каталог для нового пакета")
    s.add_argument("--days", type=int, default=90)
    s.set_defaults(func=renew.run)

    s = sub.add_parser("renew-server", help="перевыпустить серверный сертификат шлюза")
    s.add_argument("--ca-key", required=True, help="путь к ca.key (офлайн)")
    s.add_argument("--ca-key-pass-file", help=_PASS_FILE_HELP)
    s.add_argument("--host", action="append",
                   help="DNS-имя или IP шлюза; по умолчанию SAN текущего сертификата")
    s.add_argument("--days", type=int, default=365)
    s.set_defaults(func=renew_server.run)

    s = sub.add_parser("pending", help="заявки на подтверждение опасных действий")
    s.set_defaults(func=confirm.pending)

    for name, fn, text in (("approve", confirm.approve, "подтвердить заявку (одноразово, на ограниченное время)"),
                           ("reject", confirm.reject, "отклонить заявку или отозвать подтверждение")):
        s = sub.add_parser(name, help=text)
        s.add_argument("--id", required=True, help="идентификатор из `gatekeeper pending` (хотя бы 6 символов)")
        s.set_defaults(func=fn)

    s = sub.add_parser("list-clients")
    s.set_defaults(func=list_clients.run)

    s = sub.add_parser("audit-verify")
    s.add_argument("--anchors", help="файл внешних якорей (см. audit-anchor): сверить журнал и с ними")
    s.add_argument("--all-segments", action="store_true",
                   help="проверить все ротированные сегменты по времени и текущий журнал")
    s.set_defaults(func=audit_verify.run)

    s = sub.add_parser("audit-repair", help="отрезать недописанную последнюю строку журнала")
    s.set_defaults(func=audit_repair.run)

    s = sub.add_parser("audit-anchor", help="проверить журнал и выдать якорь его головы")
    s.add_argument("--out", help="дописать якорь в этот файл (держите его вне каталога данных шлюза)")
    s.set_defaults(func=audit_anchor.run)

    s = sub.add_parser("decoy-create", help="создать приманку (фальшивый пакет клиента)")
    s.add_argument("--name", required=True)
    s.add_argument("--ca-key", required=True, help="путь к ca.key")
    s.add_argument("--ca-key-pass-file", help=_PASS_FILE_HELP)
    s.add_argument("--out", required=True, help="каталог для пакета приманки")
    s.add_argument("--days", type=int, default=365)
    s.add_argument("--hint", default="", help="где вы её разместили (для журнала)")
    s.set_defaults(func=decoy_create.run)

    s = sub.add_parser("status", help="сводка: клиенты, сертификат, журнал, состояние")
    s.set_defaults(func=status.run)

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
