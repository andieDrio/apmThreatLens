from hashlib import sha256

import pytest

from threatlens.domain.models import Asset, Evidence, Finding
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata


class MemoryRepository:
    def __init__(self) -> None:
        self.evidence = []
        self.findings = []

    def save_evidence(self, evidence):
        self.evidence.append(evidence)

    def save_finding(self, finding):
        self.findings.append(finding)


def metadata() -> ProviderMetadata:
    return ProviderMetadata("test-provider", "1.0.0", frozenset({ProviderCapability.WEB}))


def test_seal_evidence_hashes_raw_content() -> None:
    evidence = Evidence(kind="http-response", content="HTTP/1.1 200 OK", source="raw")
    sealed = ProviderHandoff.seal_evidence(evidence)
    assert sealed.sha256 == sha256(evidence.content.encode()).hexdigest()


def test_seal_evidence_rejects_tampered_digest() -> None:
    evidence = Evidence(kind="http-response", content="HTTP/1.1 200 OK", source="raw", sha256="bad")
    with pytest.raises(ValueError, match="does not match"):
        ProviderHandoff.seal_evidence(evidence)


def test_handoff_binds_evidence_provenance_and_finding_source() -> None:
    repository = MemoryRepository()
    handoff = ProviderHandoff(repository)
    provider = metadata()
    asset = Asset(canonical_id="fqdn:target.internal", asset_type="fqdn", value="target.internal")
    raw = Evidence(kind="http-response", content="HTTP/1.1 200 OK", source="raw")
    sealed = handoff.persist_evidence("8f9e1c5d-6cc8-4f70-91dd-cf3c0c0c7f10", provider, raw)
    finding = Finding(title="Example", asset_id=asset.id, evidence_ids=(sealed.id,), confidence=0.9)

    normalized = handoff.persist_finding(
        "8f9e1c5d-6cc8-4f70-91dd-cf3c0c0c7f10", provider, asset, finding, (sealed,)
    )

    assert repository.evidence[0].source == provider.name
    assert repository.evidence[0].metadata["provider_version"] == provider.version
    assert normalized.source == provider.name
    assert repository.findings[0].evidence_ids == (sealed.id,)


def test_handoff_rejects_finding_for_wrong_asset() -> None:
    repository = MemoryRepository()
    handoff = ProviderHandoff(repository)
    provider = metadata()
    asset = Asset(canonical_id="fqdn:a.internal", asset_type="fqdn", value="a.internal")
    other = Asset(canonical_id="fqdn:b.internal", asset_type="fqdn", value="b.internal")
    evidence = handoff.persist_evidence("8f9e1c5d-6cc8-4f70-91dd-cf3c0c0c7f10", provider, Evidence(kind="banner", content="x", source="raw"))
    finding = Finding(title="Example", asset_id=other.id, evidence_ids=(evidence.id,))

    with pytest.raises(ValueError, match="asset_id"):
        handoff.persist_finding("8f9e1c5d-6cc8-4f70-91dd-cf3c0c0c7f10", provider, asset, finding, (evidence,))
