import os
from threading import Barrier, Thread
from uuid import uuid4

import pytest

from threatlens.domain.models import (
    Asset,
    Campaign,
    AuditEvent,
    Evidence,
    Finding,
    LifecycleState,
    Scan,
    Scope,
)
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata
from threatlens.storage.finding_correlation import DurableFindingCorrelator
from threatlens.storage.postgres import PostgresRepository


def provider_metadata() -> ProviderMetadata:
    return ProviderMetadata(
        "lease-fence-test",
        "1.0.0",
        frozenset({ProviderCapability.WEB}),
    )


def running_scan(repository) -> Scan:
    campaign = Campaign(
        name="lease-fence-campaign",
        scope=Scope(include=("fqdn:target.internal",)),
        authorized=True,
    )
    repository.save_campaign(campaign)
    scan = Scan(campaign_id=campaign.id, provider_name="lease-fence-test")
    repository.save_scan_with_audit(
        scan,
        AuditEvent(
            action="SCAN_QUEUED",
            resource_type="SCAN",
            resource_id=scan.execution_id,
            outcome="SUCCESS",
            detail="provider=lease-fence-test",
        ),
    )
    assert repository.update_scan_state_if_current(
        scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING
    )
    return scan


def count_rows(repository, table: str) -> int:
    with repository.connection.cursor() as cursor:
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        return int(cursor.fetchone()[0])


def test_postgres_handoff_rejects_evidence_after_execution_is_terminal(
    postgres_repository,
) -> None:
    repository = postgres_repository
    scan = running_scan(repository)
    handoff = ProviderHandoff(repository)
    before = count_rows(repository, "evidence")
    assert repository.update_scan_state_if_current(
        scan.execution_id, LifecycleState.RUNNING, LifecycleState.FAILED
    )

    with pytest.raises(RuntimeError, match="execution is not RUNNING"):
        handoff.persist_evidence(
            scan.execution_id,
            provider_metadata(),
            Evidence(kind="http-response", content="late response", source="raw"),
        )

    assert count_rows(repository, "evidence") == before


def test_postgres_handoff_rejects_finding_after_execution_is_terminal(
    postgres_repository,
) -> None:
    repository = postgres_repository
    scan = running_scan(repository)
    asset = Asset(
        canonical_id="fqdn:lease-fence.internal",
        asset_type="fqdn",
        value="lease-fence.internal",
    )
    repository.save_asset(asset)
    handoff = ProviderHandoff(repository)
    evidence = handoff.persist_evidence(
        scan.execution_id,
        provider_metadata(),
        Evidence(kind="http-response", content="valid response", source="raw"),
    )
    finding = Finding(
        title="Late finding",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
        source="untrusted-client-value",
    )
    before = count_rows(repository, "findings")
    assert repository.update_scan_state_if_current(
        scan.execution_id, LifecycleState.RUNNING, LifecycleState.COMPLETED
    )

    with pytest.raises(RuntimeError, match="execution is not RUNNING"):
        handoff.persist_finding(
            scan.execution_id, provider_metadata(), asset, finding, (evidence,)
        )

    assert count_rows(repository, "findings") == before


def test_postgres_correlator_rejects_finding_after_execution_is_terminal(
    postgres_repository,
) -> None:
    repository = postgres_repository
    scan = running_scan(repository)
    asset = Asset(
        canonical_id="fqdn:lease-correlation.internal",
        asset_type="fqdn",
        value="lease-correlation.internal",
    )
    repository.save_asset(asset)
    handoff = ProviderHandoff(repository, DurableFindingCorrelator(repository))
    evidence = handoff.persist_evidence(
        scan.execution_id,
        provider_metadata(),
        Evidence(kind="http-response", content="valid response", source="raw"),
    )
    finding = Finding(
        title="Late correlated finding",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
    )
    before = count_rows(repository, "findings")
    assert repository.update_scan_state_if_current(
        scan.execution_id, LifecycleState.RUNNING, LifecycleState.CANCELLED
    )

    with pytest.raises(RuntimeError, match="execution is not RUNNING"):
        handoff.persist_finding(
            scan.execution_id, provider_metadata(), asset, finding, (evidence,)
        )

    assert count_rows(repository, "findings") == before



def test_postgres_handoff_accepts_output_while_execution_is_running(
    postgres_repository,
) -> None:
    repository = postgres_repository
    scan = running_scan(repository)
    asset = Asset(
        canonical_id="fqdn:lease-active.internal",
        asset_type="fqdn",
        value="lease-active.internal",
    )
    repository.save_asset(asset)
    handoff = ProviderHandoff(repository)
    evidence = handoff.persist_evidence(
        scan.execution_id,
        provider_metadata(),
        Evidence(kind="http-response", content="active response", source="raw"),
    )
    finding = Finding(
        title="Active finding",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
    )

    persisted = handoff.persist_finding(
        scan.execution_id, provider_metadata(), asset, finding, (evidence,)
    )

    assert persisted.source == "lease-fence-test"
    assert count_rows(repository, "evidence") == 1
    assert count_rows(repository, "findings") == 1


def test_postgres_output_write_serializes_with_terminal_transition(
    postgres_repository,
) -> None:
    repository = postgres_repository
    scan = running_scan(repository)
    dsn = os.getenv("THREATLENS_TEST_DATABASE_URL") or os.getenv(
        "THREATLENS_DATABASE_URL"
    )
    assert dsn
    other_repository = PostgresRepository(dsn)
    other_repository.initialize()
    barrier = Barrier(2)
    outcomes: list[str] = []
    handoff = ProviderHandoff(repository)

    def write_output() -> None:
        barrier.wait(timeout=5)
        try:
            handoff.persist_evidence(
                scan.execution_id,
                provider_metadata(),
                Evidence(kind="http-response", content="racing response", source="raw"),
            )
        except RuntimeError as exc:
            assert "execution is not RUNNING" in str(exc)
            outcomes.append("rejected")
        else:
            outcomes.append("written")

    def cancel_execution() -> None:
        barrier.wait(timeout=5)
        changed = other_repository.update_scan_state_if_current(
            scan.execution_id, LifecycleState.RUNNING, LifecycleState.CANCELLED
        )
        assert changed
        outcomes.append("cancelled")

    writer = Thread(target=write_output)
    canceller = Thread(target=cancel_execution)
    try:
        writer.start()
        canceller.start()
        writer.join(10)
        canceller.join(10)
        assert not writer.is_alive()
        assert not canceller.is_alive()
        assert sorted(outcomes) in (
            ["cancelled", "rejected"],
            ["cancelled", "written"],
        )
        assert repository.scan_state(scan.execution_id) is LifecycleState.CANCELLED
        assert count_rows(repository, "evidence") == (1 if "written" in outcomes else 0)
    finally:
        other_repository.close()



class _FenceRequiredLegacyRepository:
    """Simulate a production repository missing the execution-fenced methods."""

    requires_execution_fence = True

    def __init__(self) -> None:
        self.unfenced_writes = 0

    def save_evidence(self, evidence) -> None:
        self.unfenced_writes += 1

    def save_finding(self, finding) -> None:
        self.unfenced_writes += 1


def test_handoff_fails_closed_when_production_repository_lacks_evidence_fence() -> None:
    repository = _FenceRequiredLegacyRepository()
    handoff = ProviderHandoff(repository)
    execution_id = uuid4()

    with pytest.raises(RuntimeError, match="requires execution-fenced evidence"):
        handoff.persist_evidence(
            execution_id,
            provider_metadata(),
            Evidence(kind="http-response", content="must not persist", source="raw"),
        )

    assert repository.unfenced_writes == 0


def test_handoff_fails_closed_when_production_repository_lacks_finding_fence() -> None:
    repository = _FenceRequiredLegacyRepository()
    handoff = ProviderHandoff(repository)
    asset = Asset(
        canonical_id="fqdn:unfenced.internal",
        asset_type="fqdn",
        value="unfenced.internal",
    )
    evidence = Evidence(
        kind="http-response",
        content="existing evidence",
        source="raw",
    )
    finding = Finding(
        title="Must not persist without fence",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
    )

    with pytest.raises(RuntimeError, match="requires execution-fenced finding"):
        handoff.persist_finding(
            uuid4(),
            provider_metadata(),
            asset,
            finding,
            (evidence,),
        )

    assert repository.unfenced_writes == 0


def test_postgres_rejects_execution_bound_evidence_on_unfenced_method(
    postgres_repository,
) -> None:
    repository = postgres_repository
    scan = running_scan(repository)
    evidence = Evidence(
        kind="http-response",
        content="execution-bound evidence",
        source="lease-fence-test",
        metadata={"execution_id": str(scan.execution_id)},
    )

    with pytest.raises(RuntimeError, match="must use save_evidence_for_execution"):
        repository.save_evidence(evidence)

    assert count_rows(repository, "evidence") == 0
