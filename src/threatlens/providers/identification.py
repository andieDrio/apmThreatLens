"""Evidence-driven service identification and protocol metadata normalization."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class Protocol(StrEnum):
    TCP = "tcp"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    SMTP = "smtp"
    DNS = "dns"
    SMB = "smb"
    RDP = "rdp"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ServiceObservation:
    """Normalized observation; it is not a vulnerability claim."""

    protocol: Protocol
    port: int
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    confidence: float = 0.0
    banner: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError("service observation port must be within 1..65535")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("service observation confidence must be between 0 and 1")
        if self.banner is not None and len(self.banner) > 8192:
            raise ValueError("service observation banner exceeds 8192 bytes")


_PRODUCT_VERSION = re.compile(
    r"(?P<product>[A-Za-z][A-Za-z0-9_.-]{1,63})/(?P<version>[0-9][A-Za-z0-9._+-]{0,63})"
)
_SSH_BANNER = re.compile(
    r"SSH-[0-9.]+-(?P<product>[^\s/]+)(?:/(?P<version>[^\s]+))?(?:\s+(?P<comment>.+))?$",
    re.I,
)


def normalize_observation(
    *, port: int, banner: str | None = None, protocol: str | None = None
) -> ServiceObservation:
    """Normalize a bounded banner/protocol observation without declaring vulnerability."""
    if not 1 <= port <= 65535:
        raise ValueError("service observation port must be within 1..65535")
    text = (banner or "").replace("\x00", "").strip()
    proto = _normalize_protocol(port, protocol, text)

    product: str | None = None
    version: str | None = None
    service_name: str | None = proto.value if proto is not Protocol.UNKNOWN else None

    if proto in {Protocol.HTTP, Protocol.HTTPS}:
        server = _header_value(text, "server")
        if server:
            match = _PRODUCT_VERSION.search(server)
            if match:
                product, version = match.group("product"), match.group("version")
            else:
                product = server[:128]
    elif proto is Protocol.SSH:
        match = _SSH_BANNER.match(text)
        if match:
            product = match.group("product")
            version = match.group("version") or match.group("comment")
    else:
        match = _PRODUCT_VERSION.search(text)
        if match:
            product, version = match.group("product"), match.group("version")

    if protocol:
        confidence = 0.95 if proto is not Protocol.UNKNOWN else 0.2
    else:
        confidence = 0.9 if proto is not Protocol.UNKNOWN else 0.2
    if product:
        confidence = min(0.99, confidence + 0.04)

    return ServiceObservation(
        protocol=proto,
        port=port,
        service_name=service_name,
        product=product,
        version=version,
        confidence=confidence,
        banner=text or None,
    )


def _normalize_protocol(port: int, protocol: str | None, banner: str) -> Protocol:
    if protocol:
        value = protocol.strip().lower()
        try:
            return Protocol(value)
        except ValueError:
            return Protocol.UNKNOWN
    if banner.upper().startswith("SSH-"):
        return Protocol.SSH
    if banner.upper().startswith(("HTTP/1.", "HTTP/2", "HTTP/3")) or "\nserver:" in banner.lower():
        return Protocol.HTTP
    return {
        22: Protocol.SSH,
        25: Protocol.SMTP,
        53: Protocol.DNS,
        80: Protocol.HTTP,
        443: Protocol.HTTPS,
        445: Protocol.SMB,
        3389: Protocol.RDP,
    }.get(port, Protocol.TCP)


def _header_value(message: str, name: str) -> str | None:
    prefix = f"{name.lower()}:"
    for line in message.splitlines():
        if line.lower().startswith(prefix):
            value = line.split(":", 1)[1].strip()
            return value[:256] or None
    return None
