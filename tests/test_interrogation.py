from __future__ import annotations

from threading import Event
from uuid import uuid4

import pytest

from threatlens.domain.models import Campaign, Scope
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.interrogation import ActiveServiceInterrogationProvider, InterrogationPolicy


class FakeRepository:
    def __init__(self) -> None:
        self.evidence = []

    def save_evidence(self, evidence) -> None:
        self.evidence.append(evidence)

    def save_finding(self, finding) -> None:
        raise AssertionError("interrogation must not create findings")


class FakeProbe:
    def __init__(self, responses: dict[tuple[str, int], str | None]) -> None:
        self.responses = responses
        self.calls = []

    def probe(self, host: str, port: int, timeout: float, max_bytes: int) -> str | None:
        self.calls.append((host, port, timeout, max_bytes))
        return self.responses.get((host, port))


def test_ssh_interrogation_preserves_bounded_banner_evidence() -> None:
    repository = FakeRepository()
    probe = FakeProbe({("192.0.2.10", 22): "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"})
    provider = ActiveServiceInterrogationProvider(
        handoff=ProviderHandoff(repository),
        policy=InterrogationPolicy(ports=(22,)),
        probe=probe,
    )
    campaign = Campaign("authorized", Scope(("192.0.2.10",)), authorized=True)

    provider.execute(campaign, uuid4(), Event())

    assert len(repository.evidence) == 1
    evidence = repository.evidence[0]
    assert evidence.kind == "service-interrogation"
    assert evidence.metadata["protocol"] == "ssh"
    assert evidence.metadata["product"] == "OpenSSH_9.6p1"
    assert evidence.metadata["version"] == "Ubuntu-3ubuntu13"


def test_http_probe_is_bounded_and_does_not_create_findings() -> None:
    repository = FakeRepository()
    probe = FakeProbe({("example.test", 80): "HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"})
    provider = ActiveServiceInterrogationProvider(
        handoff=ProviderHandoff(repository),
        policy=InterrogationPolicy(ports=(80,), max_response_bytes=1024),
        probe=probe,
    )
    campaign = Campaign("authorized", Scope(("example.test",)), authorized=True)

    provider.execute(campaign, uuid4(), Event())

    assert repository.evidence[0].metadata["product"] == "nginx"
    assert repository.evidence[0].metadata["version"] == "1.24.0"
    assert probe.calls == [("example.test", 80, 1.0, 1024)]


def test_excluded_target_is_not_interrogated() -> None:
    repository = FakeRepository()
    probe = FakeProbe({("192.0.2.10", 22): "SSH-2.0-OpenSSH_9.6p1"})
    provider = ActiveServiceInterrogationProvider(
        handoff=ProviderHandoff(repository),
        policy=InterrogationPolicy(ports=(22,)),
        probe=probe,
    )
    campaign = Campaign(
        "authorized",
        Scope(("192.0.2.10",), exclude=("192.0.2.10",)),
        authorized=True,
    )

    provider.execute(campaign, uuid4(), Event())

    assert probe.calls == []
    assert repository.evidence == []


def test_cancellation_stops_before_probe() -> None:
    repository = FakeRepository()
    probe = FakeProbe({("192.0.2.10", 22): "SSH-2.0-OpenSSH_9.6p1"})
    provider = ActiveServiceInterrogationProvider(
        handoff=ProviderHandoff(repository),
        policy=InterrogationPolicy(ports=(22,)),
        probe=probe,
    )
    campaign = Campaign("authorized", Scope(("192.0.2.10",)), authorized=True)
    cancelled = Event()
    cancelled.set()

    provider.execute(campaign, uuid4(), cancelled)

    assert probe.calls == []


def test_policy_rejects_unbounded_response_limit() -> None:
    with pytest.raises(ValueError):
        InterrogationPolicy(max_response_bytes=16384)
