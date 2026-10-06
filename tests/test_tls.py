from threading import Event
from uuid import uuid4

from threatlens.domain.models import Asset, Campaign, Scope
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.tls import TLSAssessmentProvider, TLSObservation, TLSPolicy
from threatlens.providers.tls_policy import TLSPolicy as FindingPolicy


class MemoryRepository:
    def __init__(self) -> None:
        self.evidence = []
        self.findings = []

    def save_evidence(self, evidence):
        self.evidence.append(evidence)

    def save_finding(self, finding):
        self.findings.append(finding)


class FakeProbe:
    def __init__(self, observation=None):
        self.observation = observation
        self.calls = []

    def inspect(self, host, port, timeout):
        self.calls.append((host, port, timeout))
        return self.observation


def _observation(**overrides):
    values = {
        "host": "example.test",
        "port": 443,
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "subject": "example.test",
        "issuer": "Example CA",
        "san": ("example.test",),
        "not_before": "Jan 01 00:00:00 2026 GMT",
        "not_after": "Jan 01 00:00:00 2027 GMT",
        "hostname_match": True,
        "certificate_error": None,
    }
    values.update(overrides)
    return TLSObservation(**values)


def test_tls_probe_observation_is_persisted_as_evidence() -> None:
    repo = MemoryRepository()
    provider = TLSAssessmentProvider(
        ProviderHandoff(repo),
        policy=TLSPolicy(ports=(443,), timeout_seconds=1.0, max_targets=1),
        probe=FakeProbe(_observation()),
    )
    campaign = Campaign("tls", Scope(("example.test",)), authorized=True)

    execution_id = uuid4()
    provider.execute(campaign, execution_id, Event())

    assert len(repo.evidence) == 1
    evidence = repo.evidence[0]
    assert evidence.kind == "tls-assessment"
    assert evidence.sha256
    assert evidence.metadata["execution_id"] == str(execution_id)
    assert evidence.metadata["tls_version"] == "TLSv1.3"
    assert evidence.metadata["hostname_match"] == "True"


def test_tls_policy_finding_is_persisted_only_after_evidence() -> None:
    repo = MemoryRepository()
    asset = Asset(canonical_id="fqdn:example.test", asset_type="fqdn", value="example.test")
    provider = TLSAssessmentProvider(
        ProviderHandoff(repo),
        policy=TLSPolicy(ports=(443,), max_targets=1),
        probe=FakeProbe(_observation(tls_version="TLSv1.1")),
        asset_resolver=lambda host: asset if host == asset.value else None,
        finding_policy=FindingPolicy(),
    )
    campaign = Campaign("tls", Scope(("example.test",)), authorized=True)

    provider.execute(campaign, uuid4(), Event())

    assert len(repo.evidence) == 1
    assert len(repo.findings) == 1
    finding = repo.findings[0]
    assert finding.vulnerability_id == "TLS-DEPRECATED-PROTOCOL"
    assert finding.evidence_ids == (repo.evidence[0].id,)
    assert finding.asset_id == asset.id
    assert finding.source == provider.name


def test_tls_policy_does_not_create_finding_without_asset_resolution() -> None:
    repo = MemoryRepository()
    provider = TLSAssessmentProvider(
        ProviderHandoff(repo),
        policy=TLSPolicy(ports=(443,), max_targets=1),
        probe=FakeProbe(_observation(tls_version="TLSv1.1")),
    )
    campaign = Campaign("tls", Scope(("example.test",)), authorized=True)

    provider.execute(campaign, uuid4(), Event())

    assert len(repo.evidence) == 1
    assert repo.findings == []


def test_tls_exclusion_is_enforced() -> None:
    repo = MemoryRepository()
    probe = FakeProbe(None)
    provider = TLSAssessmentProvider(
        ProviderHandoff(repo),
        policy=TLSPolicy(ports=(443,), max_targets=2),
        probe=probe,
    )
    campaign = Campaign("tls", Scope(("example.test",), ("example.test",)), authorized=True)

    provider.execute(campaign, uuid4(), Event())

    assert probe.calls == []
    assert repo.evidence == []


def test_tls_cancellation_stops_before_probe() -> None:
    repo = MemoryRepository()
    probe = FakeProbe(None)
    provider = TLSAssessmentProvider(ProviderHandoff(repo), probe=probe)
    campaign = Campaign("tls", Scope(("example.test",)), authorized=True)
    cancel = Event()
    cancel.set()

    provider.execute(campaign, uuid4(), cancel)

    assert probe.calls == []


def test_tls_policy_rejects_duplicate_ports() -> None:
    try:
        TLSPolicy(ports=(443, 443))
    except ValueError as exc:
        assert "unique" in str(exc)
    else:
        raise AssertionError("duplicate TLS ports must be rejected")
