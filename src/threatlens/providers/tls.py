"""Controlled TLS assessment and transport-security normalization."""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Event
from typing import Callable, Protocol
from uuid import UUID

from threatlens.domain.models import Asset, Campaign, Evidence
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata


@dataclass(frozen=True, slots=True)
class TLSObservation:
    host: str
    port: int
    tls_version: str | None
    cipher: str | None
    subject: str | None
    issuer: str | None
    san: tuple[str, ...]
    not_before: str | None
    not_after: str | None
    hostname_match: bool | None
    certificate_error: str | None


class TLSProbe(Protocol):
    def inspect(self, host: str, port: int, timeout: float) -> TLSObservation | None: ...


class SocketTLSProbe:
    """Uses Python's TLS stack with certificate validation enabled."""

    def inspect(self, host: str, port: int, timeout: float) -> TLSObservation | None:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    subject = _name(cert.get("subject", ()))
                    issuer = _name(cert.get("issuer", ()))
                    san = tuple(value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS")
                    return TLSObservation(
                        host=host,
                        port=port,
                        tls_version=tls.version(),
                        cipher=tls.cipher()[0] if tls.cipher() else None,
                        subject=subject,
                        issuer=issuer,
                        san=san,
                        not_before=cert.get("notBefore"),
                        not_after=cert.get("notAfter"),
                        hostname_match=True,
                        certificate_error=None,
                    )
        except ssl.SSLCertVerificationError as exc:
            return TLSObservation(
                host=host,
                port=port,
                tls_version=None,
                cipher=None,
                subject=None,
                issuer=None,
                san=(),
                not_before=None,
                not_after=None,
                hostname_match=False,
                certificate_error=str(exc)[:512],
            )
        except (OSError, TimeoutError):
            return None


@dataclass(frozen=True, slots=True)
class TLSPolicy:
    ports: tuple[int, ...] = (443, 8443)
    timeout_seconds: float = 2.0
    max_targets: int = 16

    def __post_init__(self) -> None:
        if not self.ports or len(set(self.ports)) != len(self.ports):
            raise ValueError("TLS ports must be non-empty and unique")
        if any(not 1 <= port <= 65535 for port in self.ports):
            raise ValueError("TLS ports must be within 1..65535")
        if not 0.1 <= self.timeout_seconds <= 10.0:
            raise ValueError("TLS timeout must be within 0.1..10 seconds")
        if not 1 <= self.max_targets <= 16:
            raise ValueError("TLS max_targets must be within 1..16")


class TLSAssessmentProvider:
    name = "builtin-tls-assessment"
    metadata = ProviderMetadata(
        name=name,
        version="1.1.0",
        capabilities=frozenset({ProviderCapability.TLS, ProviderCapability.EVIDENCE}),
        safe_by_default=True,
    )

    def __init__(
        self,
        handoff: ProviderHandoff,
        policy: TLSPolicy | None = None,
        probe: TLSProbe | None = None,
        asset_resolver: Callable[[str], Asset | None] | None = None,
        finding_policy: object | None = None,
    ) -> None:
        self.handoff = handoff
        self.policy = policy or TLSPolicy()
        self.probe = probe or SocketTLSProbe()
        self.asset_resolver = asset_resolver
        self.finding_policy = finding_policy

    def execute(self, campaign: Campaign, execution_id: UUID, cancel_event: Event) -> None:
        if len(campaign.scope.include) > self.policy.max_targets:
            raise ValueError("TLS target count exceeds execution policy")
        excluded = {self._normalize_host(value) for value in campaign.scope.exclude}
        for target in campaign.scope.include:
            if cancel_event.is_set():
                return
            host = self._normalize_host(target)
            if host in excluded:
                continue
            for port in self.policy.ports:
                if cancel_event.is_set():
                    return
                observation = self.probe.inspect(host, port, self.policy.timeout_seconds)
                if observation is None:
                    continue
                content = _serialize(observation)
                evidence = Evidence(
                    kind="tls-assessment",
                    content=content,
                    source=self.name,
                    metadata={
                        "host": host,
                        "port": str(port),
                        "tls_version": observation.tls_version or "",
                        "cipher": observation.cipher or "",
                        "hostname_match": str(observation.hostname_match),
                        "certificate_error": observation.certificate_error or "",
                    },
                )
                persisted_evidence = self.handoff.persist_evidence(
                    execution_id=execution_id,
                    provider=self.metadata,
                    evidence=evidence,
                )
                self._persist_policy_findings(
                    host=host,
                    observation=observation,
                    evidence=persisted_evidence,
                    execution_id=execution_id,
                )

    def _persist_policy_findings(
        self,
        *,
        host: str,
        observation: TLSObservation,
        evidence: Evidence,
        execution_id: UUID,
    ) -> None:
        """Evaluate only persisted evidence and hand findings back through the domain boundary."""
        if self.asset_resolver is None:
            return
        asset = self.asset_resolver(host)
        if asset is None:
            raise ValueError(f"TLS finding integration could not resolve asset: {host}")

        from threatlens.providers.tls_policy import TLSPolicy as FindingPolicy
        from threatlens.providers.tls_policy import evaluate_tls_observation

        policy = self.finding_policy if isinstance(self.finding_policy, FindingPolicy) else None
        findings = evaluate_tls_observation(
            observation,
            asset_id=asset.id,
            evidence_id=evidence.id,
            policy=policy,
        )
        for finding in findings:
            self.handoff.persist_finding(
                execution_id=execution_id,
                provider=self.metadata,
                asset=asset,
                finding=finding,
                evidence=(evidence,),
            )

    @staticmethod
    def _normalize_host(target: str) -> str:
        value = target.strip()
        if not value or "://" in value or "/" in value:
            raise ValueError("TLS assessment accepts host/IP targets only")
        import ipaddress
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            if any(char.isspace() for char in value) or len(value) > 253:
                raise ValueError(f"invalid TLS host: {target!r}") from None
            normalized = value.lower().rstrip(".")
            labels = normalized.split(".")
            if not all(label and len(label) <= 63 and label[0] != "-" and label[-1] != "-" for label in labels):
                raise ValueError(f"invalid TLS host: {target!r}")
            return normalized


def _name(parts: tuple[tuple[tuple[str, str], ...], ...]) -> str | None:
    values = [value for group in parts for key, value in group if key in {"commonName", "organizationName"}]
    return values[0] if values else None


def _serialize(observation: TLSObservation) -> str:
    return (
        f"host={observation.host}\nport={observation.port}\n"
        f"tls_version={observation.tls_version or ''}\ncipher={observation.cipher or ''}\n"
        f"subject={observation.subject or ''}\nissuer={observation.issuer or ''}\n"
        f"san={','.join(observation.san)}\nnot_before={observation.not_before or ''}\n"
        f"not_after={observation.not_after or ''}\nhostname_match={observation.hostname_match}\n"
        f"certificate_error={observation.certificate_error or ''}\n"
        f"captured_at={datetime.now(timezone.utc).isoformat()}"
    )
