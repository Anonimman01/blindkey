"""gatekeeper run: запустить шлюз."""
from __future__ import annotations

import asyncio

from gatekeeper.cli import output
from gatekeeper.server.app import build_app
from gatekeeper.server.config import load_config
from gatekeeper.store.layout import Layout


def run(args, layout: Layout) -> int:
    cfg = load_config(layout.config_file)
    app = build_app(layout, cfg)
    started = lambda: output.info(  # noqa: E731
        f"gatekeeper listening on {cfg.listen_host}:{cfg.listen_port} (mTLS, TLS 1.3)")
    try:
        asyncio.run(app.serve(on_started=started))
    except KeyboardInterrupt:
        output.info("stopped")
    return 0
