import pytest

from threatlens.domain.models import (
    Asset,
    Campaign,
    Evidence,
    Finding,
    LifecycleState,
    Scan,
    Scope,
)
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata
from threatlens.storage.finding_correlation import DurableFindingCorrelator


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
    repository.save_scan(scan)
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
