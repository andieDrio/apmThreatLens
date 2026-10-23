from __future__ import annotations

import socket
from threading import Event
from uuid import uuid4

import pytest

from threatlens.domain.models import Campaign, Scope
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.interrogation import (
    ActiveServiceInterrogationProvider,
    InterrogationPolicy,
    SocketInterrogationProbe,
)


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

    def probe(
        self, host: str, port: int, timeout: float, max_bytes: int, *, connect_address=None
    ) -> str | None:
        self.calls.append((host, port, timeout, max_bytes, connect_address))
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
    assert evidence.metadata["product"] == "OpenSSH"
    assert evidence.metadata["version"] == "9.6p1"


def test_http_probe_is_bounded_and_does_not_create_findings() -> None:
    repository = FakeRepository()
    probe = FakeProbe({("example.test", 80): "HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\n\r\n"})
    provider = ActiveServiceInterrogationProvider(
        handoff=ProviderHandoff(repository),
        policy=InterrogationPolicy(ports=(80,), max_response_bytes=1024),
        probe=probe,
        destination_resolver=lambda hostname: ("93.184.216.34",),
    )
    campaign = Campaign("authorized", Scope(("example.test",)), authorized=True)

    provider.execute(campaign, uuid4(), Event())

    assert repository.evidence[0].metadata["product"] == "nginx"
    assert repository.evidence[0].metadata["version"] == "1.24.0"
    assert probe.calls == [("example.test", 80, 1.0, 1024, "93.184.216.34")]
    assert repository.evidence[0].metadata["resolved_address"] == "93.184.216.34"


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


def test_private_dns_answer_is_rejected_before_interrogation():
    repository = FakeRepository()
    probe = FakeProbe({("example.test", 80): "unexpected"})
    provider = ActiveServiceInterrogationProvider(
        handoff=ProviderHandoff(repository),
        policy=InterrogationPolicy(ports=(80,)),
        probe=probe,
        destination_resolver=lambda hostname: ("127.0.0.1",),
    )
    campaign = Campaign("authorized", Scope(("example.test",)), authorized=True)

    with pytest.raises(PermissionError, match="non-public"):
        provider.execute(campaign, uuid4(), Event())
    assert probe.calls == []


def test_empty_dns_answer_fails_closed_before_interrogation():
    probe = FakeProbe({("example.test", 80): "unexpected"})
    provider = ActiveServiceInterrogationProvider(
        handoff=ProviderHandoff(FakeRepository()),
        policy=InterrogationPolicy(ports=(80,)),
        probe=probe,
        destination_resolver=lambda hostname: (),
    )
    with pytest.raises(ConnectionError, match="no addresses"):
        provider.execute(
            Campaign("authorized", Scope(("example.test",)), authorized=True), uuid4(), Event()
        )
    assert probe.calls == []


def test_private_literal_ip_remains_interrogatable():
    probe = FakeProbe({("192.168.1.10", 22): "SSH-2.0-OpenSSH_9.6p1"})
    provider = ActiveServiceInterrogationProvider(
        handoff=ProviderHandoff(FakeRepository()),
        policy=InterrogationPolicy(ports=(22,)),
        probe=probe,
    )
    provider.execute(
        Campaign("authorized", Scope(("192.168.1.10",)), authorized=True), uuid4(), Event()
    )
    assert probe.calls[0][4] == "192.168.1.10"


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


def test_socket_interrogation_pins_address_but_keeps_authorized_host_header(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.request = b""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout):
            pass

        def sendall(self, request):
            self.request = request

        def recv(self, _max_bytes):
            return b"HTTP/1.1 200 OK\r\nServer: test\r\n"

    fake_socket = FakeSocket()
    connect_calls = []

    def fake_create_connection(address, timeout):
        connect_calls.append((address, timeout))
        return fake_socket

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    result = SocketInterrogationProbe().probe(
        "scanner.example.test", 80, 0.5, 1024, connect_address="93.184.216.34"
    )

    assert connect_calls == [(('93.184.216.34', 80), 0.5)]
    assert b"Host: scanner.example.test" in fake_socket.request
    assert result.startswith("HTTP/1.1 200 OK")
