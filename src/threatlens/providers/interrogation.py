"""Controlled, protocol-aware active service interrogation."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from threading import Event
from typing import Protocol
from uuid import UUID

from threatlens.domain.models import Campaign, Evidence
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.identification import normalize_observation
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata


class InterrogationProbe(Protocol):
    def probe(self, host: str, port: int, timeout: float, max_bytes: int) -> str | None: ...


class SocketInterrogationProbe:
    """Bounded protocol probes; never sends arbitrary user-controlled payloads."""

    def probe(self, host: str, port: int, timeout: float, max_bytes: int) -> str | None:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
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
    ) -> None:
        self.handoff = handoff
        self.policy = policy or InterrogationPolicy()
        self.probe = probe or SocketInterrogationProbe()

    def execute(self, campaign: Campaign, execution_id: UUID, cancel_event: Event) -> None:
        if len(campaign.scope.include) > self.policy.max_targets:
            raise ValueError("interrogation target count exceeds execution policy")
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
                raise ValueError("interrogation target count exceeds execution policy")
            for port in self.policy.ports:
                if cancel_event.is_set():
                    return
                response = self.probe.probe(
                    host,
                    port,
                    self.policy.timeout_seconds,
                    self.policy.max_response_bytes,
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

    @staticmethod
    def _normalize_host(target: str) -> str:
        value = target.strip()
        if not value or "://" in value or "/" in value:
            raise ValueError("service interrogation accepts host/IP targets only")
        import ipaddress

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
                raise ValueError(f"invalid service interrogation host: {target!r}")
            return normalized
