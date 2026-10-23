"""Controlled TCP network discovery adapter."""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass
from ipaddress import ip_address
from threading import Event
from typing import Protocol
from uuid import UUID

from threatlens.domain.models import (
    Asset,
    Campaign,
    Evidence,
    Finding,
    FindingState,
    Service,
    Severity,
)
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.identification import normalize_observation
from threatlens.providers.interrogation import (
    InterrogationPolicy,
    InterrogationProbe,
    SocketInterrogationProbe,
)
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata
from threatlens.providers.tls import (
    TLSAssessmentProvider,
    TLSProbe,
    serialize_tls_observation,
)
from threatlens.providers.tls_policy import evaluate_tls_observation
from threatlens.providers.vulnerability_intelligence import (
    VulnerabilityIntelligenceRecord,
    match_vulnerability,
)


class NetworkDiscoveryRepository(Protocol):
    def save_asset(self, asset: Asset) -> None: ...

    def save_asset_for_execution(self, execution_id: UUID, asset: Asset) -> Asset: ...

    def save_service(self, service: Service) -> Service: ...

    def save_service_for_execution(self, execution_id: UUID, service: Service) -> Service: ...

    def vulnerability_intelligence_for_service(
        self, product: str, version: str, limit: int = 50
    ) -> tuple[VulnerabilityIntelligenceRecord, ...]: ...


@dataclass(frozen=True, slots=True)
class NetworkDiscoveryPolicy:
    """Safe defaults for controlled TCP discovery."""

    ports: tuple[int, ...] = (22, 25, 80, 443)
    timeout_seconds: float = 1.0
    max_targets: int = 64
    allow_non_public_hostname_addresses: bool = False

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
        version="1.2.0",
        capabilities=frozenset(
            {
                ProviderCapability.NETWORK,
                ProviderCapability.DISCOVERY,
                ProviderCapability.TLS,
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
        interrogation_probe: InterrogationProbe | None = None,
        tls_probe: TLSProbe | None = None,
        destination_resolver: Callable[[str], tuple[str, ...]] | None = None,
    ) -> None:
        self.repository = repository
        self.handoff = handoff
        self.policy = policy or NetworkDiscoveryPolicy()
        self.probe = probe or SocketTcpProbe()
        self.interrogation_policy = InterrogationPolicy(
            max_targets=min(self.policy.max_targets, 32)
        )
        self.interrogation_probe = interrogation_probe or SocketInterrogationProbe()
        self.tls_probe = tls_probe
        self.destination_resolver = destination_resolver or self._resolve_addresses

    def execute(self, campaign: Campaign, execution_id: UUID, cancel_event: Event) -> None:
        """Probe only explicitly scoped hosts and persist positive TCP observations."""
        if len(campaign.scope.include) > self.policy.max_targets:
            raise ValueError("network discovery target count exceeds execution policy")

        excluded = {self._parse_target(value) for value in campaign.scope.exclude}
        resolved_targets: dict[str, str] = {}
        processed = 0
        for target in campaign.scope.include:
            if cancel_event.is_set():
                return
            host, explicit_port = self._parse_target(target)
            if (host, None) in excluded or (host, explicit_port) in excluded:
                continue
            if host not in resolved_targets:
                resolved_targets[host] = self._resolve_target(host)
            resolved_address = resolved_targets[host]
            processed += 1
            if processed > self.policy.max_targets:
                raise ValueError("network discovery target count exceeds execution policy")

            asset = Asset(
                canonical_id=f"host:{host}", asset_type=self._asset_type(host), value=host
            )
            save_asset_for_execution = getattr(
                self.repository, "save_asset_for_execution", None
            )
            if callable(save_asset_for_execution):
                asset = save_asset_for_execution(execution_id, asset)
            else:
                if getattr(self.repository, "requires_execution_fence", False):
                    raise RuntimeError("repository requires execution-fenced asset persistence")
                self.repository.save_asset(asset)
            ports = (explicit_port,) if explicit_port is not None else self.policy.ports
            for port in ports:
                if cancel_event.is_set():
                    return
                if (host, port) in excluded:
                    continue
                if not self.probe.connect((resolved_address, port), self.policy.timeout_seconds):
                    continue
                service = Service(
                    asset_id=asset.id,
                    protocol="tcp",
                    port=port,
                    service_name=self._well_known_service(port),
                )
                save_service_for_execution = getattr(
                    self.repository, "save_service_for_execution", None
                )
                if callable(save_service_for_execution):
                    save_service_for_execution(execution_id, service)
                else:
                    if getattr(self.repository, "requires_execution_fence", False):
                        raise RuntimeError(
                            "repository requires execution-fenced service persistence"
                        )
                    self.repository.save_service(service)
                evidence = Evidence(
                    kind="tcp-connect",
                    content=f"tcp://{host}:{port} accepted a TCP connection",
                    source=self.name,
                    metadata={
                        "asset_id": str(asset.id),
                        "host": host,
                        "resolved_address": resolved_address,
                        "port": str(port),
                        "protocol": "tcp",
                    },
                )
                self.handoff.persist_evidence(
                    execution_id=execution_id,
                    provider=self.metadata,
                    evidence=evidence,
                )
                if port in self.interrogation_policy.ports:
                    if cancel_event.is_set():
                        return
                    banner = self.interrogation_probe.probe(
                        host,
                        port,
                        min(self.policy.timeout_seconds, self.interrogation_policy.timeout_seconds),
                        self.interrogation_policy.max_response_bytes,
                        connect_address=resolved_address,
                    )
                    if banner and not cancel_event.is_set():
                        observation = normalize_observation(port=port, banner=banner)
                        identified_service = Service(
                            asset_id=asset.id,
                            protocol="tcp",
                            port=port,
                            service_name=observation.service_name
                            or self._well_known_service(port),
                            product=observation.product,
                            version=observation.version,
                        )
                        if callable(save_service_for_execution):
                            stored_service = save_service_for_execution(
                                execution_id, identified_service
                            )
                            if isinstance(stored_service, Service):
                                identified_service = stored_service
                        else:
                            stored_service = self.repository.save_service(identified_service)
                            if isinstance(stored_service, Service):
                                identified_service = stored_service
                        fingerprint_evidence = self.handoff.persist_evidence(
                            execution_id=execution_id,
                            provider=self.metadata,
                            evidence=Evidence(
                                kind="service-interrogation",
                                content=self._evidence_banner(
                                    port,
                                    banner,
                                    self.interrogation_policy.max_response_bytes,
                                ),
                                source=self.name,
                                metadata={
                                    "asset_id": str(asset.id),
                                    "host": host,
                                    "resolved_address": resolved_address,
                                    "port": str(port),
                                    "protocol": observation.protocol.value,
                                    "service_name": observation.service_name or "",
                                    "product": observation.product or "",
                                    "version": observation.version or "",
                                    "confidence": str(observation.confidence),
                                    "capture_policy": (
                                        "http-status-and-server-headers-only"
                                        if port == 80
                                        else "bounded-protocol-banner"
                                    ),
                                },
                            ),
                        )
                        self._persist_intelligence_matches(
                            execution_id=execution_id,
                            asset=asset,
                            service=identified_service,
                            evidence=fingerprint_evidence,
                            observed_confidence=observation.confidence,
                        )
                if (
                    self.tls_probe is not None
                    and port in {443, 8443}
                    and not cancel_event.is_set()
                ):
                    tls_observation = self.tls_probe.inspect(
                        host,
                        port,
                        min(self.policy.timeout_seconds, 2.0),
                        connect_address=resolved_address,
                    )
                    if tls_observation is not None and not cancel_event.is_set():
                        tls_evidence = self.handoff.persist_evidence(
                            execution_id=execution_id,
                            provider=TLSAssessmentProvider.metadata,
                            evidence=Evidence(
                                kind="tls-assessment",
                                content=serialize_tls_observation(tls_observation),
                                source=TLSAssessmentProvider.name,
                                metadata={
                                    "asset_id": str(asset.id),
                                    "host": host,
                                    "resolved_address": resolved_address,
                                    "port": str(port),
                                    "tls_version": tls_observation.tls_version or "",
                                    "cipher": tls_observation.cipher or "",
                                    "hostname_match": str(tls_observation.hostname_match),
                                    "certificate_error": tls_observation.certificate_error or "",
                                },
                            ),
                        )
                        for finding in evaluate_tls_observation(
                            tls_observation,
                            asset_id=asset.id,
                            evidence_id=tls_evidence.id,
                        ):
                            self.handoff.persist_finding(
                                execution_id=execution_id,
                                provider=TLSAssessmentProvider.metadata,
                                asset=asset,
                                finding=finding,
                                evidence=(tls_evidence,),
                            )

    def _persist_intelligence_matches(
        self,
        *,
        execution_id: UUID,
        asset: Asset,
        service: Service,
        evidence: Evidence,
        observed_confidence: float,
    ) -> None:
        lookup = getattr(self.repository, "vulnerability_intelligence_for_service", None)
        if not callable(lookup) or not service.product or not service.version:
            return
        records = lookup(service.product, service.version)
        for intelligence in records:
            match = match_vulnerability(service, asset.id, intelligence)
            if match is None:
                continue
            finding = Finding(
                title=(
                    "Potential CVE match (exact product/version): "
                    f"{intelligence.cve or intelligence.vulnerability_id} — {intelligence.title}"
                ),
                asset_id=asset.id,
                evidence_ids=(evidence.id,),
                state=FindingState.SUSPECTED,
                severity=Severity(intelligence.severity),
                vulnerability_id=intelligence.vulnerability_id,
                cwe=intelligence.cwe,
                cve=intelligence.cve,
                cvss=intelligence.cvss,
                confidence=min(observed_confidence, match.confidence),
                source=match.intelligence_source,
                service_id=service.id,
            )
            self.handoff.persist_finding(
                execution_id=execution_id,
                provider=self.metadata,
                asset=asset,
                finding=finding,
                evidence=(evidence,),
            )

    @staticmethod
    def _evidence_banner(port: int, banner: str, max_bytes: int) -> str:
        """Keep HTTP evidence to non-secret status/server headers, never cookies or bodies."""
        if port != 80:
            return banner[:max_bytes]
        safe_lines = []
        for index, line in enumerate(banner.splitlines()):
            if index == 0 and line.upper().startswith("HTTP/"):
                safe_lines.append(line)
            elif line.partition(":")[0].strip().lower() == "server":
                safe_lines.append(line)
        return "\r\n".join(safe_lines)[:max_bytes]

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
                label
                and len(label) <= 63
                and label[0] != "-"
                and label[-1] != "-"
                and all(char.isascii() and (char.isalnum() or char == "-") for char in label)
                for label in labels
            ):
                raise ValueError(f"invalid network discovery host: {target!r}") from None
            return normalized

    def _resolve_target(self, host: str) -> str:
        """Resolve a scoped hostname once and reject unsafe answers before connecting."""
        try:
            return str(ip_address(host))
        except ValueError:
            pass

        try:
            addresses = sorted(
                {str(ip_address(value)) for value in self.destination_resolver(host)}
            )
        except OSError as exc:
            raise ConnectionError(f"network discovery DNS resolution failed: {host}") from exc
        except ValueError as exc:
            raise ValueError("network discovery resolver returned an invalid IP address") from exc
        if not addresses:
            raise ConnectionError(f"network discovery DNS returned no addresses: {host}")
        if len(addresses) > 16:
            raise ValueError("network discovery DNS answer count exceeds execution policy")
        if not self.policy.allow_non_public_hostname_addresses and any(
            not ip_address(address).is_global for address in addresses
        ):
            raise PermissionError("network discovery hostname resolves to a non-public address")
        return addresses[0]

    @staticmethod
    def _resolve_addresses(hostname: str) -> tuple[str, ...]:
        try:
            return tuple(
                info[4][0] for info in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
            )
        except OSError as exc:
            raise OSError(f"DNS resolution failed for {hostname}") from exc

    @classmethod
    def _parse_target(cls, target: str) -> tuple[str, int | None]:
        """Accept a host/IP or an explicitly scoped host:port endpoint."""
        value = target.strip()
        host = value
        port = None
        if value.startswith("["):
            closing = value.find("]")
            if closing < 0:
                raise ValueError(f"invalid bracketed network target: {target!r}")
            host = value[1:closing]
            suffix = value[closing + 1 :]
            if suffix:
                if not suffix.startswith(":") or not suffix[1:].isdigit():
                    raise ValueError(f"invalid host/port target: {target!r}")
                port = int(suffix[1:])
        elif value.count(":") == 1:
            candidate_host, candidate_port = value.rsplit(":", 1)
            if candidate_port.isdigit():
                host, port = candidate_host, int(candidate_port)
        normalized = cls._normalize_host(host)
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("network target port must be within 1..65535")
        return normalized, port

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
