from threading import Event

import pytest

from threatlens.domain.models import Campaign, Scope
from threatlens.providers.discovery import DiscoveryProvider
from threatlens.providers.handoff import ProviderHandoff


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

    provider.execute(campaign, campaign.id, Event())

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

    provider.execute(campaign, campaign.id, event)

    assert postgres_repository.count("assets") == 0
    assert postgres_repository.count("evidence") == 0


def test_discovery_rejects_blank_target() -> None:
    with pytest.raises(ValueError, match="scope.include cannot contain blank targets"):
        Scope(include=("   ",))
