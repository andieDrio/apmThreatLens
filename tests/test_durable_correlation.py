from uuid import uuid4

from threatlens.domain.models import Asset, Evidence, Finding, FindingState, Severity
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata
from threatlens.storage.sqlite import SQLiteRepository
from threatlens.storage.finding_correlation import DurableFindingCorrelator, SQLiteFindingCorrelationMixin


class CorrelatedSQLiteRepository(SQLiteFindingCorrelationMixin, SQLiteRepository):
    pass


def _setup():
    repository = SQLiteRepository(":memory:")
    repository.initialize()
    correlator = DurableFindingCorrelator(repository)
    asset = Asset(canonical_id="host:10.0.0.10", asset_type="ip", value="10.0.0.10")
    repository.save_asset(asset)
    provider = ProviderMetadata(
        name="test-provider", version="1.0.0",
        capabilities=frozenset({ProviderCapability.VULNERABILITY, ProviderCapability.EVIDENCE}),
    )
    handoff = ProviderHandoff(repository, correlator=correlator)
    return repository, asset, provider, handoff


def _finding(asset, evidence_id, source="test-provider", severity=Severity.MEDIUM):
    return Finding(
        title="Weak TLS", asset_id=asset.id, evidence_ids=(evidence_id,),
        state=FindingState.CONFIRMED, severity=severity,
        vulnerability_id="TLS-WEAK-CIPHER", cwe="CWE-326",
        confidence=0.8, source=source,
    )


def test_duplicate_provider_findings_persist_as_one_logical_finding():
    repository, asset, provider_a, provider_b, correlator = _setup()
    first_evidence = handoff.persist_evidence(
        uuid4(), provider, Evidence(kind="scan", content="a", source="scanner-a")
    )
    second_evidence = handoff.persist_evidence(
        uuid4(), provider, Evidence(kind="scan", content="b", source="scanner-b")
    )

    first = handoff.persist_finding(
        uuid4(), provider, asset, _finding(asset, first_evidence.id, "scanner-a", Severity.MEDIUM),
        (first_evidence,),
    )
    second = handoff.persist_finding(
        uuid4(), provider, asset, _finding(asset, second_evidence.id, "scanner-b", Severity.HIGH),
        (second_evidence,),
    )

    assert first.id == second.id
    assert repository.count("findings") == 1
    assert repository.count("finding_evidence") == 2

    row = repository.connection.execute(
        "SELECT severity,source FROM findings WHERE id=?", (str(first.id),)
    ).fetchone()
    assert row["severity"] == Severity.HIGH.value
    assert row["source"] == "scanner-a,scanner-b"


def test_durable_correlation_survives_new_correlator_instance():
    repository, asset, provider_a, provider_b, correlator = _setup()
    evidence = handoff.persist_evidence(
        uuid4(), provider, Evidence(kind="scan", content="same", source="scanner-a")
    )
    finding = handoff.persist_finding(
        uuid4(), provider, asset, _finding(asset, evidence.id), (evidence,)
    )

    restarted = DurableFindingCorrelator(repository)
    second_evidence = restarted.repository
    assert second_evidence.count("findings") == 1

    evidence2 = ProviderHandoff(repository, correlator=restarted).persist_evidence(
        uuid4(), provider, Evidence(kind="scan", content="new", source="scanner-b")
    )
    merged = ProviderHandoff(repository, correlator=restarted).persist_finding(
        uuid4(), provider_b, asset, _finding(asset, evidence2.id, "scanner-b"), (evidence2,)
    )

    assert merged.id == finding.id
    assert repository.count("findings") == 1
    assert repository.count("finding_evidence") == 2
