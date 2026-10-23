from threading import Event
from uuid import uuid4

import pytest

from threatlens.domain.models import Campaign, FindingState, Scope
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.network_discovery import NetworkDiscoveryPolicy, NetworkDiscoveryProvider
from threatlens.providers.tls import TLSObservation
from threatlens.providers.vulnerability_intelligence import normalize_vulnerability_record
from threatlens.storage.sqlite import SQLiteRepository


class FakeProbe:
    def __init__(self, open_ports: set[tuple[str, int]]) -> None:
        self.open_ports = open_ports
        self.calls: list[tuple[str, int]] = []

    def connect(self, address: tuple[str, int], timeout: float) -> bool:
        self.calls.append(address)
        return address in self.open_ports


class FakeInterrogationProbe:
    def __init__(self, response: str | None) -> None:
        self.response = response
        self.calls: list[tuple[str, int, float, int]] = []
        self.connect_addresses: list[str | None] = []

    def probe(
        self,
        host: str,
        port: int,
        timeout: float,
        max_bytes: int,
        *,
        connect_address: str | None = None,
    ) -> str | None:
        self.calls.append((host, port, timeout, max_bytes))
        self.connect_addresses.append(connect_address)
        return self.response


class FakeTLSProbe:
    def __init__(self, observation: TLSObservation | None) -> None:
        self.observation = observation
        self.calls: list[tuple[str, int, float, str | None]] = []

    def inspect(self, host, port, timeout, *, connect_address=None):
        self.calls.append((host, port, timeout, connect_address))
        return self.observation


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


def test_network_scan_records_pinned_tls_observation_and_policy_finding(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "network-tls.db")
    repo.initialize()
    campaign = Campaign(
        name="network-tls-test",
        scope=Scope(include=("scanner.example.test",), exclude=()),
        authorized=True,
    )
    tls_probe = FakeTLSProbe(
        TLSObservation(
            host="scanner.example.test",
            port=443,
            tls_version="TLSv1.1",
            cipher="TLS_RSA_WITH_AES_128_CBC_SHA",
            subject="scanner.example.test",
            issuer="Example CA",
            san=("scanner.example.test",),
            not_before=None,
            not_after=None,
            hostname_match=True,
            certificate_error=None,
        )
    )
    provider = NetworkDiscoveryProvider(
        repo,
        ProviderHandoff(repo),
        policy=NetworkDiscoveryPolicy(ports=(443,), timeout_seconds=0.5),
        probe=FakeProbe({("93.184.216.34", 443)}),
        tls_probe=tls_probe,
        destination_resolver=lambda _hostname: ("93.184.216.34",),
    )

    provider.execute(campaign, uuid4(), Event())

    assert tls_probe.calls == [
        ("scanner.example.test", 443, 0.5, "93.184.216.34")
    ]
    evidence = repo.connection.execute(
        "SELECT content,metadata_json,sha256 FROM evidence WHERE kind='tls-assessment'"
    ).fetchone()
    assert "tls_version=TLSv1.1" in evidence[0]
    assert '"provider": "builtin-tls-assessment"' in evidence[1]
    assert '"resolved_address": "93.184.216.34"' in evidence[1]
    assert evidence[2]
    finding = repo.connection.execute(
        "SELECT vulnerability_id,source FROM findings"
    ).fetchone()
    assert tuple(finding) == ("TLS-DEPRECATED-PROTOCOL", "builtin-tls-assessment")
    repo.close()


def test_network_scan_skips_tls_probe_when_tcp_port_is_closed(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "closed-tls-port.db")
    repo.initialize()
    tls_probe = FakeTLSProbe(None)
    provider = NetworkDiscoveryProvider(
        repo,
        ProviderHandoff(repo),
        policy=NetworkDiscoveryPolicy(ports=(443,)),
        probe=FakeProbe(set()),
        tls_probe=tls_probe,
    )

    provider.execute(
        Campaign("closed-tls-test", Scope(("192.0.2.10",)), authorized=True),
        uuid4(),
        Event(),
    )

    assert tls_probe.calls == []
    assert repo.count("evidence") == 0
    repo.close()


def test_network_scan_fingerprints_open_ssh_service_and_seals_banner_evidence(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "fingerprint.db")
    repo.initialize()
    campaign = Campaign(
        name="ssh-fingerprint-test",
        scope=Scope(include=("192.0.2.10:22",)),
        authorized=True,
    )
    tcp_probe = FakeProbe({("192.0.2.10", 22)})
    banner_probe = FakeInterrogationProbe("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
    provider = NetworkDiscoveryProvider(
        repo,
        ProviderHandoff(repo),
        policy=NetworkDiscoveryPolicy(ports=(22,), timeout_seconds=0.4),
        probe=tcp_probe,
        interrogation_probe=banner_probe,
    )

    provider.execute(campaign, uuid4(), Event())

    assert tcp_probe.calls == [("192.0.2.10", 22)]
    assert banner_probe.calls == [("192.0.2.10", 22, 0.4, 8192)]
    assert banner_probe.connect_addresses == ["192.0.2.10"]
    service = tuple(
        repo.connection.execute(
            "SELECT service_name,version,product FROM services WHERE port=22"
        ).fetchone()
    )
    assert service == ("ssh", "9.6p1", "OpenSSH")
    evidence = repo.connection.execute(
        "SELECT kind,content,metadata_json,sha256 FROM evidence ORDER BY kind"
    ).fetchall()
    assert len(evidence) == 2
    fingerprint = next(row for row in evidence if row[0] == "service-interrogation")
    assert fingerprint[1] == "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13"
    assert '"product": "OpenSSH"' in fingerprint[2]
    assert '"version": "9.6p1"' in fingerprint[2]
    assert fingerprint[3]
    repo.close()


def test_network_scan_persists_suspected_exact_version_cve_match(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "cve-correlation.db")
    repo.initialize()
    record = normalize_vulnerability_record(
        vulnerability_id="CVE-2026-3456",
        title="Sample OpenSSH issue",
        severity="HIGH",
        cve="CVE-2026-3456",
        product="OpenSSH",
        affected_versions=("9.6p1",),
        cvss=8.1,
        confidence=0.95,
        source="NVD CVE API 2.0",
    )
    repo.vulnerability_intelligence_for_service = lambda product, version: (
        (record,) if (product, version) == ("OpenSSH", "9.6p1") else ()
    )
    campaign = Campaign(
        name="ssh-cve-correlation-test",
        scope=Scope(include=("192.0.2.10:22",)),
        authorized=True,
    )
    provider = NetworkDiscoveryProvider(
        repo,
        ProviderHandoff(repo),
        policy=NetworkDiscoveryPolicy(ports=(22,)),
        probe=FakeProbe({("192.0.2.10", 22)}),
        interrogation_probe=FakeInterrogationProbe("SSH-2.0-OpenSSH_9.6p1"),
    )

    provider.execute(campaign, uuid4(), Event())

    finding = repo.connection.execute(
        """SELECT f.state,f.cve,f.service_id,f.source,f.title,e.kind,e.content
           FROM findings f
           JOIN finding_evidence fe ON fe.finding_id=f.id
           JOIN evidence e ON e.id=fe.evidence_id"""
    ).fetchone()
    assert finding[0] == FindingState.SUSPECTED.value
    assert finding[1] == "CVE-2026-3456"
    assert finding[3] == "builtin-network-discovery; NVD CVE API 2.0"
    assert finding[4].startswith("Potential CVE match (exact product/version):")
    assert finding[5] == "service-interrogation"
    assert finding[6] == "SSH-2.0-OpenSSH_9.6p1"
    assert repo.count("findings") == 1
    repo.close()


def test_network_scan_redacts_unneeded_http_response_headers_from_evidence(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "http-fingerprint.db")
    repo.initialize()
    campaign = Campaign(
        name="http-fingerprint-test",
        scope=Scope(include=("192.0.2.10:80",)),
        authorized=True,
    )
    banner = (
        "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
        "Set-Cookie: session=secret-value\r\nContent-Length: 0\r\n\r\n"
    )
    provider = NetworkDiscoveryProvider(
        repo,
        ProviderHandoff(repo),
        policy=NetworkDiscoveryPolicy(ports=(80,)),
        probe=FakeProbe({("192.0.2.10", 80)}),
        interrogation_probe=FakeInterrogationProbe(banner),
    )

    provider.execute(campaign, uuid4(), Event())

    fingerprint = repo.connection.execute(
        "SELECT content,metadata_json FROM evidence WHERE kind='service-interrogation'"
    ).fetchone()
    assert "HTTP/1.1 200 OK" in fingerprint[0]
    assert "Server: nginx/1.24.0" in fingerprint[0]
    assert "Set-Cookie" not in fingerprint[0]
    assert "secret-value" not in fingerprint[0]
    assert "Content-Length" not in fingerprint[0]
    assert '"capture_policy": "http-status-and-server-headers-only"' in fingerprint[1]
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


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        ("192.0.2.20:8443", ("192.0.2.20", 8443)),
        ("[2001:db8::20]:9443", ("2001:db8::20", 9443)),
    ],
)
def test_network_discovery_probes_only_explicit_scoped_port(tmp_path, target, expected) -> None:
    repo = SQLiteRepository(tmp_path / "explicit-port.db")
    repo.initialize()
    campaign = Campaign(
        name="explicit-port-test",
        scope=Scope(include=(target,)),
        authorized=True,
    )
    probe = FakeProbe({expected})
    provider = NetworkDiscoveryProvider(
        repo,
        ProviderHandoff(repo),
        policy=NetworkDiscoveryPolicy(ports=(80, 443), max_targets=2),
        probe=probe,
    )

    provider.execute(campaign, uuid4(), Event())

    assert probe.calls == [expected]
    assert repo.count("services") == 1
    repo.close()


def test_network_discovery_can_exclude_one_explicit_port(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "excluded-port.db")
    repo.initialize()
    campaign = Campaign(
        name="excluded-port-test",
        scope=Scope(include=("192.0.2.21",), exclude=("192.0.2.21:80",)),
        authorized=True,
    )
    probe = FakeProbe(set())
    provider = NetworkDiscoveryProvider(
        repo,
        ProviderHandoff(repo),
        policy=NetworkDiscoveryPolicy(ports=(80, 443)),
        probe=probe,
    )

    provider.execute(campaign, uuid4(), Event())

    assert probe.calls == [("192.0.2.21", 443)]
    repo.close()


def test_network_discovery_rejects_url_and_target_overflow(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    with pytest.raises(ValueError):
        NetworkDiscoveryProvider(repo, ProviderHandoff(repo))._normalize_host(
            "https://example.test"
        )
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


def test_network_discovery_resolves_hostname_once_and_pins_both_probes(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "pinned-dns.db")
    repo.initialize()
    campaign = Campaign(
        name="hostname-pinning",
        scope=Scope(include=("scanner.example.test:22",)),
        authorized=True,
    )
    resolutions = []
    tcp_probe = FakeProbe({("93.184.216.34", 22)})
    banner_probe = FakeInterrogationProbe("SSH-2.0-OpenSSH_9.6p1")
    provider = NetworkDiscoveryProvider(
        repo,
        ProviderHandoff(repo),
        policy=NetworkDiscoveryPolicy(ports=(22,)),
        probe=tcp_probe,
        interrogation_probe=banner_probe,
        destination_resolver=lambda hostname: resolutions.append(hostname)
        or ("93.184.216.34",),
    )

    provider.execute(campaign, uuid4(), Event())

    assert resolutions == ["scanner.example.test"]
    assert tcp_probe.calls == [("93.184.216.34", 22)]
    assert banner_probe.calls == [("scanner.example.test", 22, 1.0, 8192)]
    assert banner_probe.connect_addresses == ["93.184.216.34"]
    metadata = repo.connection.execute(
        "SELECT metadata_json FROM evidence WHERE kind='tcp-connect'"
    ).fetchone()[0]
    assert '"host": "scanner.example.test"' in metadata
    assert '"resolved_address": "93.184.216.34"' in metadata
    repo.close()


@pytest.mark.parametrize(
    "answers",
    [("127.0.0.1",), ("93.184.216.34", "10.0.0.8")],
)
def test_network_discovery_rejects_non_public_hostname_dns_before_connect(
    tmp_path, answers
) -> None:
    repo = SQLiteRepository(tmp_path / "rejected-dns.db")
    repo.initialize()
    campaign = Campaign(
        name="unsafe-hostname-resolution",
        scope=Scope(include=("scanner.example.test:22",)),
        authorized=True,
    )
    probe = FakeProbe({("93.184.216.34", 22), ("127.0.0.1", 22)})
    provider = NetworkDiscoveryProvider(
        repo,
        ProviderHandoff(repo),
        policy=NetworkDiscoveryPolicy(ports=(22,)),
        probe=probe,
        destination_resolver=lambda hostname: answers,
    )

    with pytest.raises(PermissionError, match="non-public address"):
        provider.execute(campaign, uuid4(), Event())

    assert probe.calls == []
    assert repo.count("assets") == 0
    repo.close()


def test_network_discovery_keeps_explicit_private_ip_target_usable(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "private-ip-target.db")
    repo.initialize()
    campaign = Campaign(
        name="authorized-private-ip",
        scope=Scope(include=("10.0.0.8:22",)),
        authorized=True,
    )
    probe = FakeProbe({("10.0.0.8", 22)})
    provider = NetworkDiscoveryProvider(
        repo,
        ProviderHandoff(repo),
        policy=NetworkDiscoveryPolicy(ports=(22,)),
        probe=probe,
        destination_resolver=lambda _hostname: pytest.fail(
            "literal IP targets must not be resolved as hostnames"
        ),
    )

    provider.execute(campaign, uuid4(), Event())

    assert probe.calls == [("10.0.0.8", 22)]
    assert repo.count("services") == 1
    repo.close()
