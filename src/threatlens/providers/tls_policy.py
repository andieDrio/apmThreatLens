"""Deterministic TLS security-policy evaluation over observed evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, UTC
from uuid import UUID

from threatlens.domain.models import Finding, FindingState, Severity
from threatlens.providers.tls import TLSObservation


@dataclass(frozen=True, slots=True)
class TLSPolicy:
    """Explicit security rules; evaluation never probes the network."""

    minimum_tls_version: tuple[int, int] = (1, 2)
    weak_cipher_markers: tuple[str, ...] = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")


def evaluate_tls_observation(
    observation: TLSObservation,
    *,
    asset_id: UUID,
    evidence_id: UUID,
    policy: TLSPolicy | None = None,
    now: datetime | None = None,
) -> tuple[Finding, ...]:
    """Turn explicit TLS observations into explainable findings.

    No network access occurs here. Every finding references the evidence that
    triggered the deterministic rule.
    """
    policy = policy or TLSPolicy()
    findings: list[Finding] = []
    current = now or datetime.now(UTC)

    if observation.certificate_error:
        findings.append(
            _finding(
                title="TLS certificate validation failed",
                asset_id=asset_id,
                evidence_id=evidence_id,
                severity=Severity.HIGH,
                confidence=0.98,
                vulnerability_id="TLS-CERT-VALIDATION",
                cwe="CWE-295",
            )
        )

    if observation.hostname_match is False:
        findings.append(
            _finding(
                title="TLS certificate hostname validation failed",
                asset_id=asset_id,
                evidence_id=evidence_id,
                severity=Severity.HIGH,
                confidence=0.99,
                vulnerability_id="TLS-HOSTNAME-MISMATCH",
                cwe="CWE-297",
            )
        )

    if _expired(observation.not_after, current):
        findings.append(
            _finding(
                title="TLS certificate is expired",
                asset_id=asset_id,
                evidence_id=evidence_id,
                severity=Severity.HIGH,
                confidence=0.99,
                vulnerability_id="TLS-CERT-EXPIRED",
                cwe="CWE-298",
            )
        )

    if observation.tls_version in {"TLSv1", "TLSv1.0", "TLSv1.1"}:
        findings.append(
            _finding(
                title=f"Deprecated TLS protocol: {observation.tls_version}",
                asset_id=asset_id,
                evidence_id=evidence_id,
                severity=Severity.HIGH,
                confidence=0.99,
                vulnerability_id="TLS-DEPRECATED-PROTOCOL",
                cwe="CWE-326",
            )
        )

    cipher = (observation.cipher or "").upper()
    if cipher and any(marker in cipher for marker in policy.weak_cipher_markers):
        findings.append(
            _finding(
                title=f"Weak TLS cipher suite observed: {observation.cipher}",
                asset_id=asset_id,
                evidence_id=evidence_id,
                severity=Severity.MEDIUM,
                confidence=0.95,
                vulnerability_id="TLS-WEAK-CIPHER",
                cwe="CWE-327",
            )
        )

    return tuple(findings)


def _expired(value: str | None, now: datetime) -> bool:
    if not value:
        return False
    try:
        expires = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=UTC)
    except ValueError:
        return False
    return expires < now


def _finding(
    *,
    title: str,
    asset_id: UUID,
    evidence_id: UUID,
    severity: Severity,
    confidence: float,
    vulnerability_id: str,
    cwe: str,
) -> Finding:
    return Finding(
        title=title,
        asset_id=asset_id,
        evidence_ids=(evidence_id,),
        state=FindingState.CONFIRMED,
        severity=severity,
        vulnerability_id=vulnerability_id,
        cwe=cwe,
        confidence=confidence,
        source="builtin-tls-policy",
    )
