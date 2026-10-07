"""Controlled TCP network discovery adapter."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from ipaddress import ip_address
from threading import Event
from typing import Protocol
from uuid import UUID

from threatlens.domain.models import Asset, Campaign, Evidence, Service
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata


class NetworkDiscoveryRepository(Protocol):
    def save_asset(self, asset: Asset) -> None: ...

    def save_service(self, service: Service) -> None: ...


@dataclass(frozen=True, slots=True)
class NetworkDiscoveryPolicy:
    """Safe defaults for controlled TCP discovery."""

    ports: tuple[int, ...] = (80, 443)
    timeout_seconds: float = 1.0
    max_targets: int = 64

    def __post_init__(self) -> None:
        if not self.ports:
            raise ValueError("network discovery requires at least one port")
        if any(not 1 <= port <= 65535 for port in self.ports):
            raise ValueError("network discovery ports must be within 1..65535")
        if len(set(self.ports)) != len(self.ports):
            raise ValueError("network discovery ports must be unique")
        if not 0.05 <= self.timeout_seconds <= 30.0:
            raise ValueError("network discovery timeout must be within 0.05..30 seconds")
        if not 1 <= self.max_targets <= 64:
            raise ValueError("network discovery max_targets must be within 1..64")


class TcpProbe(Protocol):
    def connect(self, address: tuple[str, int], timeout: float) -> bool: ...


class SocketTcpProbe:
    """Minimal TCP connect probe; no application payload is sent."""

    def connect(self, address: tuple[str, int], timeout: float) -> bool:
        try:
            with socket.create_connection(address, timeout=timeout):
                return True
        except (OSError, TimeoutError):
            return False


class NetworkDiscoveryProvider:
    """Scope-locked TCP discovery for explicitly listed IP/FQDN targets."""

    name = "builtin-network-discovery"
    metadata = ProviderMetadata(
        name=name,
        version="1.0.0",
        capabilities=frozenset(
            {
                ProviderCapability.NETWORK,
                ProviderCapability.DISCOVERY,
                ProviderCapability.EVIDENCE,
            }
        ),
        safe_by_default=True,
    )

    def __init__(
        self,
        repository: NetworkDiscoveryRepository,
        handoff: ProviderHandoff,
        policy: NetworkDiscoveryPolicy | None = None,
        probe: TcpProbe | None = None,
    ) -> None:
        self.repository = repository
        self.handoff = handoff
        self.policy = policy or NetworkDiscoveryPolicy()
        self.probe = probe or SocketTcpProbe()

    def execute(self, campaign: Campaign, execution_id: UUID, cancel_event: Event) -> None:
        """Probe only explicitly scoped hosts and persist positive TCP observations."""
        if len(campaign.scope.include) > self.policy.max_targets:
            raise ValueError("network discovery target count exceeds execution policy")

        excluded = {self._normalize_host(value) for value in campaign.scope.exclude}
        processed = 0
        for target in campaign.scope.include:
            if cancel_event.is_set():
                return
            host = self._normalize_host(target)
            if host in excluded:
                continue
            processed += 1
            if processed > self.policy.max_targets:
                raise ValueError("network discovery target count exceeds execution policy")

            asset = Asset(
                canonical_id=f"host:{host}", asset_type=self._asset_type(host), value=host
            )
            self.repository.save_asset(asset)
            for port in self.policy.ports:
                if cancel_event.is_set():
                    return
                if not self.probe.connect((host, port), self.policy.timeout_seconds):
                    continue
                service = Service(
                    asset_id=asset.id,
                    protocol="tcp",
                    port=port,
                    service_name=self._well_known_service(port),
                )
                self.repository.save_service(service)
                evidence = Evidence(
                    kind="tcp-connect",
                    content=f"tcp://{host}:{port} accepted a TCP connection",
                    source=self.name,
                    metadata={
                        "asset_id": str(asset.id),
                        "host": host,
                        "port": str(port),
                        "protocol": "tcp",
                    },
                )
                self.handoff.persist_evidence(
                    execution_id=execution_id,
                    provider=self.metadata,
                    evidence=evidence,
                )

    @staticmethod
    def _normalize_host(target: str) -> str:
        value = target.strip()
        if not value:
            raise ValueError("network discovery target cannot be empty")
        if "://" in value or "/" in value:
            raise ValueError("network discovery accepts host/IP targets only")
        try:
            return str(ip_address(value))
        except ValueError:
            if any(char.isspace() for char in value) or len(value) > 253:
                raise ValueError(f"invalid network discovery host: {target!r}") from None
            normalized = value.lower().rstrip(".")
            labels = normalized.split(".")
            if not all(
                label and len(label) <= 63 and label[0] != "-" and label[-1] != "-"
                for label in labels
            ):
                raise ValueError(f"invalid network discovery host: {target!r}") from None
            return normalized

    @staticmethod
    def _asset_type(host: str) -> str:
        try:
            return "ipv4" if ip_address(host).version == 4 else "ipv6"
        except ValueError:
            return "fqdn"

    @staticmethod
    def _well_known_service(port: int) -> str | None:
        return {
            22: "ssh",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            3389: "rdp",
        }.get(port)
