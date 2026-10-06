"""Controlled asset discovery provider boundary.

Gate 06 deliberately starts with deterministic target normalization rather than
network probing. Real discovery backends will plug into the same provider runtime
once their execution semantics are implemented and reviewed.
"""

from __future__ import annotations

from ipaddress import ip_address
from threading import Event
from typing import Protocol
from urllib.parse import urlparse
from uuid import UUID

from threatlens.domain.models import Asset, Campaign, Evidence
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata


class AssetRepository(Protocol):
    def save_asset(self, asset: Asset) -> None: ...


class DiscoveryProvider:
    """Scope-controlled discovery of explicitly authorized campaign targets."""

    name = "builtin-discovery"

    def __init__(self, repository: AssetRepository, handoff: ProviderHandoff) -> None:
        self.repository = repository
        self.handoff = handoff

    def execute(self, campaign: Campaign, execution_id: UUID, cancel_event: Event) -> None:
        """Normalize and persist in-scope targets without probing the network."""
        excluded = {self._normalize_target(value) for value in campaign.scope.exclude}
        metadata = ProviderMetadata(
            name=self.name,
            version="1.0.0",
            capabilities=frozenset({ProviderCapability.DISCOVERY, ProviderCapability.EVIDENCE}),
            safe_by_default=True,
        )

        for target in campaign.scope.include:
            if cancel_event.is_set():
                return

            target_type, value = self._normalize_target(target)
            if (target_type, value) in excluded:
                continue

            asset = Asset(
                canonical_id=f"{target_type}:{value}",
                asset_type=target_type,
                value=value,
            )
            self.repository.save_asset(asset)
            evidence = Evidence(
                kind="discovery-target",
                content=value,
                source=self.name,
                metadata={"asset_id": str(asset.id), "asset_type": asset.asset_type},
            )
            self.handoff.persist_evidence(
                execution_id=execution_id,
                provider=metadata,
                evidence=evidence,
            )

    @staticmethod
    def _normalize_target(target: str) -> tuple[str, str]:
        value = target.strip()
        if not value:
            raise ValueError("discovery target cannot be empty")

        try:
            parsed_ip = ip_address(value)
            return ("ipv4" if parsed_ip.version == 4 else "ipv6", str(parsed_ip))
        except ValueError:
            pass

        parsed = urlparse(value if "://" in value else f"https://{value}")
        hostname = parsed.hostname
        if hostname:
            hostname = hostname.lower().rstrip(".")
            if parsed.scheme.lower() in {"http", "https"} and "://" in value:
                return ("url", value)
            return ("fqdn", hostname)

        raise ValueError(f"unsupported discovery target: {target!r}")
