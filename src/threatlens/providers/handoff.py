"""Evidence-first handoff contracts between provider runtime and domain persistence."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from typing import Protocol
from uuid import UUID

from threatlens.domain.models import Asset, Evidence, Finding
from threatlens.providers.runtime import ProviderMetadata
from threatlens.providers.vulnerability_enrichment import intelligence_evidence
from threatlens.providers.vulnerability_intelligence import VulnerabilityIntelligenceRecord


class EvidenceFindingRepository(Protocol):
    def save_evidence(self, evidence: Evidence) -> None: ...

    def save_finding(self, finding: Finding) -> None: ...


class ProviderHandoff:
    """Validates and persists provider output without conflating raw evidence and findings."""

    def __init__(self, repository: EvidenceFindingRepository, correlator=None) -> None:
        self.repository = repository
        self.correlator = correlator

    @staticmethod
    def seal_evidence(evidence: Evidence) -> Evidence:
        """Return immutable evidence with a deterministic SHA-256 content digest."""
        digest = sha256(evidence.content.encode("utf-8")).hexdigest()
        if evidence.sha256 is not None and evidence.sha256 != digest:
            raise ValueError("evidence.sha256 does not match evidence.content")
        return replace(evidence, sha256=digest)

    def persist_evidence(
        self,
        execution_id: UUID,
        provider: ProviderMetadata,
        evidence: Evidence,
    ) -> Evidence:
        """Persist raw evidence only after provenance is bound to the execution."""
        sealed = self.seal_evidence(evidence)
        metadata = dict(sealed.metadata)
        metadata.update(
            {
                "execution_id": str(execution_id),
                "provider": provider.name,
                "provider_version": provider.version,
            }
        )
        sealed = replace(sealed, metadata=metadata, source=provider.name)
        self.repository.save_evidence(sealed)
        return sealed

    def persist_intelligence_enriched_finding(
        self,
        execution_id: UUID,
        provider: ProviderMetadata,
        asset: Asset,
        finding: Finding,
        intelligence: VulnerabilityIntelligenceRecord,
        evidence: tuple[Evidence, ...],
    ) -> Finding:
        """Persist an intelligence-enriched finding through the normal handoff."""

        intelligence_evidence(intelligence, evidence)
        if not intelligence.evidence_ids:
            raise ValueError(
                "intelligence-backed finding enrichment requires evidence"
            )
        return self.persist_finding(
            execution_id,
            provider,
            asset,
            finding,
            tuple(dict.fromkeys((*evidence,))),
        )

    def persist_finding(
        self,
        execution_id: UUID,
        provider: ProviderMetadata,
        asset: Asset,
        finding: Finding,
        evidence: tuple[Evidence, ...],
    ) -> Finding:
        """Persist one normalized finding only when it references persisted evidence."""
        if finding.asset_id != asset.id:
            raise ValueError("finding.asset_id must match the supplied asset")
        if not finding.evidence_ids:
            raise ValueError("finding must reference evidence")
        evidence_by_id = {item.id: item for item in evidence}
        if any(item_id not in evidence_by_id for item_id in finding.evidence_ids):
            raise ValueError("finding references evidence not included in the handoff")

        normalized = replace(
            finding,
            source=provider.name,
        )
        if self.correlator is not None:
            return self.correlator.persist(normalized)
        self.repository.save_finding(normalized)
        return normalized
