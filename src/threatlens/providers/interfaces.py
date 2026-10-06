"""Provider boundaries for replaceable assessment capabilities."""

from __future__ import annotations

from typing import Protocol, Sequence

from threatlens.domain.models import Asset, Evidence, Finding, Service


class DiscoveryProvider(Protocol):
    name: str

    def discover(self, targets: Sequence[str]) -> Sequence[Asset]:
        """Discover and normalize assets within an already-authorized scope."""


class NetworkScannerProvider(Protocol):
    name: str

    def enumerate_services(self, asset: Asset) -> Sequence[Service]:
        """Enumerate services for an authorized asset."""


class AssessmentProvider(Protocol):
    name: str

    def assess(self, asset: Asset) -> Sequence[Finding]:
        """Assess an authorized asset and return evidence-backed findings."""


class EvidenceProvider(Protocol):
    name: str

    def store(self, evidence: Evidence) -> Evidence:
        """Persist raw evidence without changing provenance."""
