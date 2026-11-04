"""TLS 1.3 с обязательным клиентским сертификатом (mTLS). Доверяем только нашему CA."""
from __future__ import annotations

import asyncio
import ssl
from pathlib import Path


def build_server_context(ca_pem: str | Path, cert_pem: str | Path, key_pem: str | Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(cafile=str(ca_pem))  # системные корни НЕ загружаем
    ctx.load_cert_chain(str(cert_pem), str(key_pem))
    return ctx


def build_client_context(ca_pem: str | Path, cert_pem: str | Path, key_pem: str | Path) -> ssl.SSLContext:
    """Контекст клиента: pin на наш CA, проверка имени шлюза по SAN, только TLS 1.3."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)  # check_hostname=True, CERT_REQUIRED
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(cafile=str(ca_pem))
    ctx.load_cert_chain(str(cert_pem), str(key_pem))
    return ctx


def peer_cert_der(writer: asyncio.StreamWriter) -> bytes | None:
    """DER клиентского сертификата из TLS-соединения (None, если не TLS или нет сертификата)."""
    ssl_obj = writer.get_extra_info("ssl_object")
    if ssl_obj is None:
        return None
    return ssl_obj.getpeercert(binary_form=True) or None
