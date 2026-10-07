"""Provider boundaries for replaceable assessment capabilities."""

from __future__ import annotations

from typing import Protocol
from collections.abc import Sequence

from threatlens.domain.models import Asset, Evidence, Finding, Service


class DiscoveryProvider(Protocol):
    name: str

    def discover(self, targets: Sequence[str]) -> Sequence[Asset]: ...


class NetworkScannerProvider(Protocol):
    name: str

    def enumerate_services(self, asset: Asset) -> Sequence[Service]: ...


class AssessmentProvider(Protocol):
    name: str

    def assess(self, asset: Asset) -> Sequence[Finding]: ...


class WebScannerProvider(Protocol):
    name: str

    def execute(self, campaign, execution_id, cancel_event) -> None: ...


class APIScannerProvider(Protocol):
    name: str

    def execute(self, campaign, execution_id, cancel_event) -> None: ...


class EvidenceProvider(Protocol):
    name: str

    def store(self, evidence: Evidence) -> Evidence: ...
