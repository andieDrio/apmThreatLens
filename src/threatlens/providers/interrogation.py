"""Controlled, protocol-aware active service interrogation."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from threading import Event
from typing import Protocol
from uuid import UUID

from threatlens.domain.models import Campaign, Evidence
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.identification import normalize_observation
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata


class InterrogationProbe(Protocol):
    def probe(
        self,
        host: str,
        port: int,
        timeout: float,
        max_bytes: int,
        *,
        connect_address: str | None = None,
    ) -> str | None: ...


class SocketInterrogationProbe:
    """Bounded protocol probes; never sends arbitrary user-controlled payloads."""

    def probe(
        self,
        host: str,
        port: int,
        timeout: float,
        max_bytes: int,
        *,
        connect_address: str | None = None,
    ) -> str | None:
        try:
            with socket.create_connection((connect_address or host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                if port in {80}:
                    sock.sendall(
                        f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode(
                            "ascii", "strict"
                        )
                    )
                elif port in {22, 25}:
                    pass
                else:
                    return None
                return sock.recv(max_bytes).decode("utf-8", errors="replace") or None
        except (OSError, TimeoutError):
            return None


@dataclass(frozen=True, slots=True)
class InterrogationPolicy:
    ports: tuple[int, ...] = (22, 25, 80)
    timeout_seconds: float = 1.0
    max_targets: int = 32
    max_response_bytes: int = 8192
    allow_non_public_hostname_addresses: bool = False

    def __post_init__(self) -> None:
        if not self.ports:
            raise ValueError("interrogation requires at least one port")
        if any(not 1 <= port <= 65535 for port in self.ports):
            raise ValueError("interrogation ports must be within 1..65535")
        if len(set(self.ports)) != len(self.ports):
            raise ValueError("interrogation ports must be unique")
        if not 0.05 <= self.timeout_seconds <= 10.0:
            raise ValueError("interrogation timeout must be within 0.05..10 seconds")
        if not 1 <= self.max_targets <= 32:
            raise ValueError("interrogation max_targets must be within 1..32")
        if not 256 <= self.max_response_bytes <= 8192:
            raise ValueError("interrogation max_response_bytes must be within 256..8192")


class ActiveServiceInterrogationProvider:
    """Scope-locked interrogation for a small set of known-safe protocol probes."""

    name = "builtin-service-interrogation"
    metadata = ProviderMetadata(
        name=name,
        version="1.0.0",
        capabilities=frozenset({ProviderCapability.NETWORK, ProviderCapability.EVIDENCE}),
        safe_by_default=True,
    )

    def __init__(
        self,
        handoff: ProviderHandoff,
        policy: InterrogationPolicy | None = None,
        probe: InterrogationProbe | None = None,
        destination_resolver: Callable[[str], tuple[str, ...]] | None = None,
    ) -> None:
        self.handoff = handoff
        self.policy = policy or InterrogationPolicy()
        self.probe = probe or SocketInterrogationProbe()
        self.destination_resolver = destination_resolver or self._resolve_addresses

    def execute(self, campaign: Campaign, execution_id: UUID, cancel_event: Event) -> None:
        if len(campaign.scope.include) > self.policy.max_targets:
            raise ValueError("interrogation target count exceeds execution policy")
        excluded = {self._normalize_host(value) for value in campaign.scope.exclude}
        resolved_targets: dict[str, str] = {}
        processed = 0
        for target in campaign.scope.include:
            if cancel_event.is_set():
                return
            host = self._normalize_host(target)
            if host in excluded:
                continue
            if host not in resolved_targets:
                resolved_targets[host] = self._validate_destination(host)
            connect_address = resolved_targets[host]
            processed += 1
            if processed > self.policy.max_targets:
                raise ValueError("interrogation target count exceeds execution policy")
            for port in self.policy.ports:
                if cancel_event.is_set():
                    return
                response = self.probe.probe(
                    host,
                    port,
                    self.policy.timeout_seconds,
                    self.policy.max_response_bytes,
                    connect_address=connect_address,
                )
                if not response:
                    continue
                observation = normalize_observation(port=port, banner=response)
                evidence = Evidence(
                    kind="service-interrogation",
                    content=response[: self.policy.max_response_bytes],
                    source=self.name,
                    metadata={
                        "host": host,
                        "resolved_address": connect_address,
                        "port": str(port),
                        "protocol": observation.protocol.value,
                        "service_name": observation.service_name or "",
                        "product": observation.product or "",
                        "version": observation.version or "",
                        "confidence": str(observation.confidence),
                    },
                )
                self.handoff.persist_evidence(
                    execution_id=execution_id,
                    provider=self.metadata,
                    evidence=evidence,
                )

    def _validate_destination(self, host: str) -> str:
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is None:
            try:
                addresses = {
                    ipaddress.ip_address(value) for value in self.destination_resolver(host)
                }
            except OSError as exc:
                raise ConnectionError(
                    f"service interrogation DNS resolution failed: {host}"
                ) from exc
            if not addresses:
                raise ConnectionError(
                    f"service interrogation DNS resolution returned no addresses: {host}"
                ) from None
            if len(addresses) > 16:
                raise ValueError(
                    "service interrogation DNS answer count exceeds execution policy"
                ) from None
            if any(
                item.is_multicast
                or item.is_unspecified
                or (
                    not self.policy.allow_non_public_hostname_addresses
                    and not item.is_global
                )
                for item in addresses
            ):
                raise PermissionError(
                    "service interrogation destination resolves to a non-public address"
                ) from None
            address = sorted(addresses, key=lambda item: (item.version, int(item)))[0]
        if address.is_multicast or address.is_unspecified:
            raise PermissionError("service interrogation destination is not usable")
        return str(address)

    @staticmethod
    def _resolve_addresses(hostname: str) -> tuple[str, ...]:
        try:
            return tuple(
                result[4][0]
                for result in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            )
        except OSError as exc:
            raise ConnectionError(
                f"service interrogation DNS resolution failed: {hostname}"
            ) from exc

    @staticmethod
    def _normalize_host(target: str) -> str:
        value = target.strip()
        if not value or "://" in value or "/" in value:
            raise ValueError("service interrogation accepts host/IP targets only")
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            if any(char.isspace() for char in value) or len(value) > 253:
                raise ValueError(f"invalid service interrogation host: {target!r}") from None
            normalized = value.lower().rstrip(".")
            labels = normalized.split(".")
            if not all(
                label and len(label) <= 63 and label[0] != "-" and label[-1] != "-"
                for label in labels
            ):
                raise ValueError(f"invalid service interrogation host: {target!r}") from None
            return normalized
