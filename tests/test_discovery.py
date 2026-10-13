from threading import Event

import pytest

from threatlens.domain.models import AuditEvent, Campaign, LifecycleState, Scan, Scope
from threatlens.providers.discovery import DiscoveryProvider
from threatlens.providers.handoff import ProviderHandoff


def running_execution(repository, campaign: Campaign) -> Scan:
    repository.save_campaign(campaign)
    scan = Scan(campaign_id=campaign.id, provider_name="controlled-discovery")
    repository.save_scan_with_audit(
        scan,
        AuditEvent(
            action="SCAN_QUEUED",
            resource_type="SCAN",
            resource_id=scan.execution_id,
            outcome="SUCCESS",
            detail="provider=controlled-discovery",
        ),
    )
    assert repository.update_scan_state_if_current(
        scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING
    )
    return scan


def test_discovery_normalizes_and_persists_only_in_scope_targets(postgres_repository) -> None:
    provider = DiscoveryProvider(postgres_repository, ProviderHandoff(postgres_repository))
    campaign = Campaign(
        name="controlled-discovery",
        scope=Scope(
            include=("198.51.100.10", "example.internal", "https://example.test/login"),
            exclude=("example.internal",),
        ),
        authorized=True,
    )

    scan = running_execution(postgres_repository, campaign)
    provider.execute(campaign, scan.execution_id, Event())

    assert postgres_repository.count("assets") == 2
    assert postgres_repository.count("evidence") == 2
    assert postgres_repository.asset_id("ipv4:198.51.100.10")
    assert postgres_repository.asset_id("url:https://example.test/login")


def test_discovery_cancellation_stops_before_processing(postgres_repository) -> None:
    provider = DiscoveryProvider(postgres_repository, ProviderHandoff(postgres_repository))
    campaign = Campaign(
        name="cancelled-discovery",
        scope=Scope(include=("198.51.100.10",)),
        authorized=True,
    )
    event = Event()
    event.set()

    scan = running_execution(postgres_repository, campaign)
    provider.execute(campaign, scan.execution_id, event)

    assert postgres_repository.count("assets") == 0
    assert postgres_repository.count("evidence") == 0


def test_discovery_rejects_blank_target() -> None:
    with pytest.raises(ValueError, match="scope.include cannot contain blank targets"):
        Scope(include=("   ",))
