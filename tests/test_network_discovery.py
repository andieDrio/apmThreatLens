from threading import Event
from uuid import uuid4

import pytest

from threatlens.domain.models import Campaign, Scope
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.network_discovery import NetworkDiscoveryPolicy, NetworkDiscoveryProvider
from threatlens.storage.sqlite import SQLiteRepository


class FakeProbe:
    def __init__(self, open_ports: set[tuple[str, int]]) -> None:
        self.open_ports = open_ports
        self.calls: list[tuple[str, int]] = []

    def connect(self, address: tuple[str, int], timeout: float) -> bool:
        self.calls.append(address)
        return address in self.open_ports


def test_network_discovery_persists_only_open_tcp_services(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    campaign = Campaign(
        name="network-test",
        scope=Scope(include=("192.0.2.10",), exclude=()),
        authorized=True,
    )
    probe = FakeProbe({("192.0.2.10", 443)})
    provider = NetworkDiscoveryProvider(
        repo,
        ProviderHandoff(repo),
        policy=NetworkDiscoveryPolicy(ports=(80, 443), timeout_seconds=0.2, max_targets=2),
        probe=probe,
    )

    provider.execute(campaign, uuid4(), Event())

    assert probe.calls == [("192.0.2.10", 80), ("192.0.2.10", 443)]
    assert repo.count("assets") == 1
    assert repo.count("services") == 1
    assert repo.count("evidence") == 1
    repo.close()


def test_network_discovery_honors_exclusions(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    campaign = Campaign(
        name="excluded-network-test",
        scope=Scope(include=("192.0.2.10", "192.0.2.11"), exclude=("192.0.2.10",)),
        authorized=True,
    )
    probe = FakeProbe({("192.0.2.11", 443)})
    provider = NetworkDiscoveryProvider(repo, ProviderHandoff(repo), probe=probe)

    provider.execute(campaign, uuid4(), Event())

    assert all(host != "192.0.2.10" for host, _ in probe.calls)
    assert repo.count("assets") == 1
    repo.close()


def test_network_discovery_rejects_url_and_target_overflow(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    with pytest.raises(ValueError):
        NetworkDiscoveryProvider(repo, ProviderHandoff(repo))._normalize_host("https://example.test")
    campaign = Campaign(
        name="overflow-test",
        scope=Scope(include=("192.0.2.10", "192.0.2.11"), exclude=()),
        authorized=True,
    )
    provider = NetworkDiscoveryProvider(
        repo,
        ProviderHandoff(repo),
        policy=NetworkDiscoveryPolicy(max_targets=1),
        probe=FakeProbe(set()),
    )
    with pytest.raises(ValueError, match="target count"):
        provider.execute(campaign, uuid4(), Event())
    repo.close()


def test_network_discovery_honors_cancellation(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    campaign = Campaign(
        name="cancel-test",
        scope=Scope(include=("192.0.2.10",), exclude=()),
        authorized=True,
    )
    cancel = Event()
    cancel.set()
    probe = FakeProbe({("192.0.2.10", 443)})
    provider = NetworkDiscoveryProvider(repo, ProviderHandoff(repo), probe=probe)

    provider.execute(campaign, uuid4(), cancel)

    assert probe.calls == []
    assert repo.count("assets") == 0
    repo.close()
