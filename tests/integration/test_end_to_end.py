"""Сквозной тест: настоящий mTLS-шлюз на 127.0.0.1 + клиент + fake_telegram."""
import json
import asyncio
import socket
import ssl
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fake_telegram import FILE_BODY, FakeTelegram

from gatekeeper.cli.main import main
from gatekeeper.client.botapi import BotApi, GatewayError
from gatekeeper.core.errors import GatekeeperError
from gatekeeper.pki import ca
from gatekeeper.server.app import build_app
from gatekeeper.server.config import load_config
from gatekeeper.store.layout import Layout

TOKEN = "123456789:AAH-fakeFAKEfakeFAKEfakeFAKEfake12345"
ALLOW = ["GET:getMe", "POST:sendMessage", "POST:getFile", "POST:downloadFile", "POST:getUpdates"]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, app, port):
        self.app, self.port = app, port
        self.loop = asyncio.new_event_loop()
        self.task = None

    def start(self):
        started = threading.Event()

        def run():
            asyncio.set_event_loop(self.loop)

            async def main_():
                self.task = asyncio.current_task()
                started.set()
                await self.app.serve()

            try:
                self.loop.run_until_complete(main_())
            except asyncio.CancelledError:
                pass
            finally:
                self.loop.close()

        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()
        started.wait(5)
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise RuntimeError("gateway did not start")

    def stop(self):
        self.loop.call_soon_threadsafe(self.task.cancel)
        self.thread.join(5)


@pytest.fixture()
def gw(tmp_path, monkeypatch):
    monkeypatch.setenv("GATEKEEPER_UPSTREAM_TOKEN", TOKEN)
    fake = FakeTelegram(TOKEN)
    fake.start()
    cfgd, datad = tmp_path / "cfg", tmp_path / "data"
    cakey, bundle, decoy = tmp_path / "off" / "ca.key", tmp_path / "alice", tmp_path / "decoy"
    cakey.parent.mkdir()
    base = ["--config-dir", str(cfgd), "--data-dir", str(datad)]
    assert main(base + ["init", "--host", "127.0.0.1", "--ca-key-out", str(cakey)]) == 0
    allow = [x for a in ALLOW for x in ("--allow", a)]
    assert main(base + ["add-client", "--id", "alice", "--ca-key", str(cakey), "--out", str(bundle)] + allow) == 0
    port = free_port()
    (cfgd / "config.toml").write_text(
        f'[server]\nlisten_host="127.0.0.1"\nlisten_port={port}\n'
        f'[provider]\nname="telegram"\nupstream_host="127.0.0.1"\nupstream_port={fake.port}\n'
        f'upstream_tls=false\n[limits]\ndecoy_ban_seconds=2\nheader_timeout=1.0\nbody_timeout=1.0\n', encoding="utf-8")
    layout = Layout.from_args(str(cfgd), str(datad))
    server = Server(build_app(layout, load_config(layout.config_file)), port)
    server.start()
    yield SimpleNamespace(fake=fake, port=port, bundle=bundle, layout=layout, base=base,
                          cakey=cakey, decoy=decoy, tmp=tmp_path)
    server.stop()
    fake.stop()


def api(gw, bundle=None):
    return BotApi(str(bundle or gw.bundle), "127.0.0.1", gw.port)


def attempt(gw, ctx):
    """'refused', если шлюз оборвал соединение или TLS; иначе полученные байты."""
    try:
        with socket.create_connection(("127.0.0.1", gw.port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                tls.sendall(b"GET /getMe HTTP/1.1\r\nHost: x\r\n\r\n")
                data = tls.recv(200)
    except OSError:
        return "refused"
    return data or "refused"


def tls_ctx(gw, cert=None, key=None, maxv=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=str(gw.bundle / "ca.pem"))
    if cert:
        ctx.load_cert_chain(str(cert), str(key))
    if maxv:
        ctx.maximum_version = maxv
    return ctx


def test_get_me_send_message_and_files(gw):
    a = api(gw)
    assert a.get_me()["result"]["username"] == "fake_bot"
    assert a.send_message(5, "hi")["result"]["text"] == "hi"
    path = a.get_file("f1")["result"]["file_path"]
    assert a.download_file(path) == FILE_BODY
    paths = [p for _, p, _ in gw.fake.requests]
    assert f"/bot{TOKEN}/getMe" in paths and f"/file/bot{TOKEN}/docs/hello.txt" in paths


def test_get_updates_long_poll(gw):
    res = api(gw).get_updates(offset=5, timeout=1)["result"]
    assert res[0]["update_id"] == 10
    method, path, body = gw.fake.requests[-1]
    assert path == f"/bot{TOKEN}/getUpdates"
    assert json.loads(body) == {"timeout": 1, "offset": 5}


def test_method_outside_whitelist_denied(gw):
    with pytest.raises(GatewayError) as e:
        api(gw).call("deleteWebhook", {})
    assert e.value.status == 403
    assert not any("deleteWebhook" in p for _, p, _ in gw.fake.requests)


def test_ssrf_style_file_path_denied(gw):
    with pytest.raises(GatewayError):
        api(gw).download_file("../../getMe")
    assert not any(p.endswith("/getMe") for _, p, _ in gw.fake.requests)


def test_token_not_in_audit_log(gw):
    a = api(gw)
    a.get_me()
    a.send_message(1, "x")
    log = gw.layout.audit_log.read_text()
    assert "request_ok" in log and TOKEN not in log and TOKEN.split(":")[1] not in log


def test_tls12_refused(gw):
    ctx = tls_ctx(gw, gw.bundle / "client.pem", gw.bundle / "client.key", ssl.TLSVersion.TLSv1_2)
    assert attempt(gw, ctx) == "refused"


def test_no_client_certificate_refused(gw):
    assert attempt(gw, tls_ctx(gw)) == "refused"


def test_certificate_from_foreign_ca_refused(gw):
    other_ca, other_key = ca.create_ca()
    cert, key = ca.issue_client_cert(other_ca, other_key, "alice")
    (gw.tmp / "f.pem").write_bytes(ca.cert_to_pem(cert))
    (gw.tmp / "f.key").write_bytes(ca.key_to_pem(key))
    assert attempt(gw, tls_ctx(gw, gw.tmp / "f.pem", gw.tmp / "f.key")) == "refused"


def test_decoy_triggers_alarm_and_ban(gw):
    assert main(gw.base + ["decoy-create", "--name", "old-backup", "--ca-key", str(gw.cakey),
                           "--out", str(gw.decoy), "--hint", "test"]) == 0
    with pytest.raises(GatewayError) as e:
        api(gw, gw.decoy).get_me()
    assert e.value.status == 403
    assert "decoy_triggered" in gw.layout.audit_log.read_text()
    assert not gw.fake.requests
    with pytest.raises((GatekeeperError, OSError)):  # источник забанен
        api(gw, gw.decoy).get_me()


def test_started_callback_not_called_when_port_busy(gw):
    called = []
    app = build_app(gw.layout, load_config(gw.layout.config_file))
    with pytest.raises(OSError):
        asyncio.run(app.serve(on_started=lambda: called.append(1)))
    assert not called


def _status(gw):
    return json.loads(gw.layout.clients_file.read_text())["clients"]["alice"]["status"]


def test_freeze_unfreeze_without_restart(gw):
    a = api(gw)
    assert a.get_me()["ok"]
    assert main(gw.base + ["freeze", "--id", "alice"]) == 0
    with pytest.raises(GatewayError) as e:
        a.get_me()
    assert e.value.status == 403
    assert main(gw.base + ["unfreeze", "--id", "alice"]) == 0
    assert a.get_me()["ok"]
    log = gw.layout.audit_log.read_text()
    assert "client_frozen" in log and "client_unfrozen" in log


def test_revoke_denies_without_restart_and_is_final(gw):
    a = api(gw)
    assert a.get_me()["ok"]
    assert main(gw.base + ["revoke", "--id", "alice"]) == 0
    with pytest.raises(GatewayError) as e:
        a.get_me()
    assert e.value.status == 403
    assert _status(gw) == "revoked"
    assert main(gw.base + ["unfreeze", "--id", "alice"]) == 1  # revoked необратим
    assert _status(gw) == "revoked"
    assert "client_revoked" in gw.layout.audit_log.read_text()


def test_renew_replaces_certificate_and_keeps_rights(gw):
    new = gw.tmp / "alice2"
    assert main(gw.base + ["renew", "--id", "alice", "--ca-key", str(gw.cakey), "--out", str(new)]) == 0
    with pytest.raises(GatewayError) as e:  # старый пакет больше не работает
        api(gw).get_me()
    assert e.value.status == 403
    assert api(gw, new).send_message(5, "hi")["result"]["text"] == "hi"  # новый работает, права прежние
    assert "client_renewed" in gw.layout.audit_log.read_text()
    master = (new / "master.secret").read_text().strip()
    assert master not in gw.layout.audit_log.read_text()


def test_renew_refused_for_revoked_or_unknown(gw):
    assert main(gw.base + ["revoke", "--id", "alice"]) == 0
    for cid in ("alice", "nobody"):
        out = gw.tmp / f"out-{cid}"
        assert main(gw.base + ["renew", "--id", cid, "--ca-key", str(gw.cakey), "--out", str(out)]) == 1
        assert not out.exists()
    assert main(gw.base + ["freeze", "--id", "nobody"]) == 1


def test_autofreeze_over_real_mtls(gw):
    port = free_port()
    gw.layout.config_file.write_text(
        f'[server]\nlisten_host="127.0.0.1"\nlisten_port={port}\n'
        f'[provider]\nname="telegram"\nupstream_host="127.0.0.1"\nupstream_port={gw.fake.port}\n'
        f'upstream_tls=false\n[anomaly]\nautofreeze_threshold=3\nautofreeze_window=60\n', encoding="utf-8")
    server = Server(build_app(gw.layout, load_config(gw.layout.config_file)), port)
    server.start()
    try:
        a = BotApi(str(gw.bundle), "127.0.0.1", port)
        assert a.get_me()["ok"]
        for _ in range(3):  # подписанные запросы вне белого списка = deny_policy
            with pytest.raises(GatewayError) as e:
                a.call("deleteWebhook", {})
            assert e.value.status == 403
        assert _status(gw) == "frozen"
        with pytest.raises(GatewayError):
            a.get_me()  # заморожен, хотя запрос корректен
    finally:
        server.stop()
    log = gw.layout.audit_log.read_text()
    assert '"auto":true' in log.replace(" ", "") and "client_frozen" in log
    assert main(gw.base + ["unfreeze", "--id", "alice"]) == 0


def test_confirm_over_real_mtls(gw, capsys):
    port = free_port()
    gw.layout.config_file.write_text(
        f'[server]\nlisten_host="127.0.0.1"\nlisten_port={port}\n'
        f'[provider]\nname="telegram"\nupstream_host="127.0.0.1"\nupstream_port={gw.fake.port}\n'
        f'upstream_tls=false\n[confirm]\napis=["sendMessage"]\nttl=60\n', encoding="utf-8")
    server = Server(build_app(gw.layout, load_config(gw.layout.config_file)), port)
    server.start()
    try:
        a = BotApi(str(gw.bundle), "127.0.0.1", port)
        assert a.get_me()["ok"]                      # метод вне [confirm] работает как раньше
        payload = {"chat_id": 1, "text": "dangerous"}
        with pytest.raises(GatewayError) as e:
            a.call("sendMessage", payload)
        assert e.value.status == 403                 # заявка создана, ответ нейтральный
        capsys.readouterr()
        assert main(gw.base + ["pending"]) == 0
        out = capsys.readouterr().out
        rid = out.split()[0]
        assert "alice" in out and "sendMessage" in out and "dangerous" in out
        with pytest.raises(GatewayError):
            a.call("sendMessage", payload)           # без approve по-прежнему 403
        assert main(gw.base + ["approve", "--id", rid]) == 0
        with pytest.raises(GatewayError):
            a.call("sendMessage", {"chat_id": 1, "text": "changed"})   # другое тело не проходит
        assert a.call("sendMessage", payload)["ok"]  # без перезапуска шлюза
        with pytest.raises(GatewayError):
            a.call("sendMessage", payload)           # подтверждение одноразовое
    finally:
        server.stop()
    log = gw.layout.audit_log.read_text()
    assert "deny_confirm_required" in log and "confirm_approved" in log and '"confirmed"' in log
