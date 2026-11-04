"""Поддельный Telegram Bot API для интеграционных тестов (HTTP, без TLS, 127.0.0.1)."""
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FILE_BODY = b"hello file"


class FakeTelegram:
    def __init__(self, token: str) -> None:
        self.token = token
        self.requests: list[tuple[str, str, bytes]] = []
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, status, body, ctype="application/json"):
                self.send_response(status)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

            def _handle(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                fake.requests.append((self.command, self.path, body))
                tok = fake.token
                if self.path.startswith(f"/file/bot{tok}/"):
                    return self._send(200, FILE_BODY, "application/octet-stream")
                prefix = f"/bot{tok}/"
                if not self.path.startswith(prefix):
                    return self._send(401, b'{"ok":false,"error_code":401}')
                name = self.path[len(prefix):]
                if name == "getMe":
                    res = {"id": 1, "is_bot": True, "username": "fake_bot"}
                elif name == "sendMessage":
                    res = {"message_id": 7, "text": json.loads(body)["text"]}
                elif name == "getUpdates":
                    time.sleep(json.loads(body).get("timeout", 0))
                    res = [{"update_id": 10, "message": {"text": "hi"}}]
                elif name == "getFile":
                    res = {"file_id": "f1", "file_path": "docs/hello.txt"}
                else:
                    return self._send(404, b'{"ok":false,"error_code":404}')
                self._send(200, json.dumps({"ok": True, "result": res}).encode())

            do_GET = do_POST = _handle

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self._srv.server_address[1]

    def start(self) -> None:
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()

    def stop(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()
