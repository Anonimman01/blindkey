"""Расположение файлов шлюза на диске (см. раздел 6 хендофа)."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

DEFAULT_CONFIG_DIR = "/etc/gatekeeper"
DEFAULT_DATA_DIR = "/var/lib/gatekeeper"


@dataclass(frozen=True)
class Layout:
    config_dir: Path
    data_dir: Path

    @classmethod
    def from_args(cls, config_dir: str | None, data_dir: str | None) -> "Layout":
        return cls(
            Path(config_dir or os.environ.get("GATEKEEPER_CONFIG_DIR", DEFAULT_CONFIG_DIR)),
            Path(data_dir or os.environ.get("GATEKEEPER_DATA_DIR", DEFAULT_DATA_DIR)),
        )

    @property
    def config_file(self) -> Path: return self.config_dir / "config.toml"
    @property
    def clients_file(self) -> Path: return self.config_dir / "clients.json"
    @property
    def pki_dir(self) -> Path: return self.data_dir / "pki"
    @property
    def ca_cert(self) -> Path: return self.pki_dir / "ca.pem"
    @property
    def server_cert(self) -> Path: return self.pki_dir / "server.pem"
    @property
    def server_key(self) -> Path: return self.pki_dir / "server.key"
    @property
    def audit_dir(self) -> Path: return self.data_dir / "audit"
    @property
    def audit_log(self) -> Path: return self.audit_dir / "audit.log"
    @property
    def decoys_file(self) -> Path: return self.data_dir / "decoys.json"
