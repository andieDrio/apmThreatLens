import os
from threading import Barrier, Thread
from uuid import uuid4

from threatlens.domain.models import (
    Asset,
    AuditEvent,
    Campaign,
    Evidence,
    Finding,
    FindingState,
    LifecycleState,
    Scan,
    Scope,
    Severity,
)
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata
from threatlens.storage.finding_correlation import DurableFindingCorrelator


def setup_repo(repo):
    asset = Asset(canonical_id="host:10.0.0.10", asset_type="ip", value="10.0.0.10")
    repo.save_asset(asset)
    a = ProviderMetadata(
        "scanner-a",
        "1.0.0",
        frozenset({ProviderCapability.VULNERABILITY, ProviderCapability.EVIDENCE}),
    )
    b = ProviderMetadata(
        "scanner-b",
        "1.0.0",
        frozenset({ProviderCapability.VULNERABILITY, ProviderCapability.EVIDENCE}),
    )
    return asset, a, b, DurableFindingCorrelator(repo)




def running_execution(repo, provider_name):
    campaign = Campaign(
        name=f"correlation-{provider_name}",
        scope=Scope(include=("fqdn:correlation.internal",)),
        authorized=True,
    )
    repo.save_campaign(campaign)
    scan = Scan(campaign_id=campaign.id, provider_name=provider_name)
    repo.save_scan_with_audit(
        scan,
        AuditEvent(
            action="SCAN_QUEUED",
            resource_type="SCAN",
            resource_id=scan.execution_id,
            outcome="SUCCESS",
            detail=f"provider={provider_name}",
        ),
    )
    assert repo.update_scan_state_if_current(
        scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING
    )
    return scan.execution_id


def finding(asset, evidence_id, severity=Severity.MEDIUM):
    return Finding(
        title="Weak TLS",
        asset_id=asset.id,
        evidence_ids=(evidence_id,),
        state=FindingState.CONFIRMED,
        severity=severity,
        vulnerability_id="TLS-WEAK-CIPHER",
        cwe="CWE-326",
        confidence=0.8,
    )


def test_duplicate_provider_findings_persist_as_one_logical_finding(postgres_repository):
    repo = postgres_repository
    asset, a, b, c = setup_repo(repo)
    ha = ProviderHandoff(repo, correlator=c)
    hb = ProviderHandoff(repo, correlator=c)
    execution_a = running_execution(repo, a.name)
    execution_b = running_execution(repo, b.name)
    ea = ha.persist_evidence(execution_a, a, Evidence(kind="scan", content="a", source="scanner-a"))
    eb = hb.persist_evidence(execution_b, b, Evidence(kind="scan", content="b", source="scanner-b"))
    first = ha.persist_finding(execution_a, a, asset, finding(asset, ea.id), (ea,))
    second = hb.persist_finding(execution_b, b, asset, finding(asset, eb.id, Severity.HIGH), (eb,))
    assert first.id == second.id
    assert repo.count("findings") == 1
    assert repo.count("finding_evidence") == 2


def test_durable_correlation_survives_new_correlator_instance(postgres_repository):
    repo = postgres_repository
    asset, a, b, c = setup_repo(repo)
    h = ProviderHandoff(repo, correlator=c)
    execution_a = running_execution(repo, a.name)
    execution_b = running_execution(repo, b.name)
    e = h.persist_evidence(execution_a, a, Evidence(kind="scan", content="same", source="scanner-a"))
    original = h.persist_finding(execution_a, a, asset, finding(asset, e.id), (e,))
    restarted = DurableFindingCorrelator(repo)
    e2 = ProviderHandoff(repo, correlator=restarted).persist_evidence(
        execution_b, b, Evidence(kind="scan", content="new", source="scanner-b")
    )
    merged = ProviderHandoff(repo, correlator=restarted).persist_finding(
        execution_b, b, asset, finding(asset, e2.id), (e2,)
    )
    assert merged.id == original.id
    assert repo.count("findings") == 1
    assert repo.count("finding_evidence") == 2


def test_concurrent_instances_persist_one_logical_finding(postgres_repository):
    repo = postgres_repository
    asset, a, b, _ = setup_repo(repo)
    execution_a = running_execution(repo, a.name)
    execution_b = running_execution(repo, b.name)
    ea = ProviderHandoff(repo).persist_evidence(
        execution_a, a, Evidence(kind="scan", content="a", source="scanner-a")
    )
    eb = ProviderHandoff(repo).persist_evidence(
        execution_b, b, Evidence(kind="scan", content="b", source="scanner-b")
    )
    dsn = os.getenv("THREATLENS_TEST_DATABASE_URL") or os.getenv("THREATLENS_DATABASE_URL")
    assert dsn
    repo2 = type(repo)(dsn)
    repo2.initialize()
    barrier = Barrier(2)
    results = []
    errors = []

    def worker(worker_repo, metadata, evidence):
        try:
            correlator = DurableFindingCorrelator(worker_repo)
            handoff = ProviderHandoff(worker_repo, correlator=correlator)
            barrier.wait(timeout=5)
            results.append(
                handoff.persist_finding(
                    execution_a if metadata.name == a.name else execution_b,
                    metadata,
                    asset,
                    finding(asset, evidence.id),
                    (evidence,),
                )
            )
        except Exception as exc:
            errors.append(exc)

    # Evidence is already durable; each worker uses its own PostgreSQL connection.
    t1 = Thread(target=worker, args=(repo, a, ea))
    t2 = Thread(target=worker, args=(repo2, b, eb))
    t1.start()
    t2.start()
    t1.join(10)
    t2.join(10)
    try:
        assert not errors
        assert len(results) == 2
        assert results[0].id == results[1].id
        assert repo.count("findings") == 1
        assert repo.count("finding_evidence") == 2
        assert repo.count("finding_correlations") == 1
    finally:
        repo2.close()
