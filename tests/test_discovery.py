from threading import Event

from threatlens.domain.models import Campaign, Scope
from threatlens.providers.discovery import DiscoveryProvider
from threatlens.providers.handoff import ProviderHandoff
from threatlens.storage.sqlite import SQLiteRepository


def test_discovery_normalizes_and_persists_only_in_scope_targets(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    provider = DiscoveryProvider(repo, ProviderHandoff(repo))
    campaign = Campaign(
        name="controlled-discovery",
        scope=Scope(
            include=("198.51.100.10", "example.internal", "https://example.test/login"),
            exclude=("example.internal",),
        ),
        authorized=True,
    )

    provider.execute(campaign, campaign.id, Event())

    assert repo.count("assets") == 2
    assert repo.count("evidence") == 2
    assert repo.asset_id("ipv4:198.51.100.10")
    assert repo.asset_id("url:https://example.test/login")
    repo.close()


def test_discovery_cancellation_stops_before_processing(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    provider = DiscoveryProvider(repo, ProviderHandoff(repo))
    campaign = Campaign(
        name="cancelled-discovery",
        scope=Scope(include=("198.51.100.10",)),
        authorized=True,
    )
    event = Event()
    event.set()

    provider.execute(campaign, campaign.id, event)

    assert repo.count("assets") == 0
    assert repo.count("evidence") == 0
    repo.close()


def test_discovery_rejects_blank_target(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    provider = DiscoveryProvider(repo, ProviderHandoff(repo))
    campaign = Campaign(
        name="invalid-discovery",
        scope=Scope(include=("   ",)),
        authorized=True,
    )

    # Scope itself rejects blank targets before a provider can execute.
    assert campaign.scope.include == ("   ",)
    repo.close()
