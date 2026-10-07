from threading import Event
from uuid import uuid4

import pytest

from threatlens.domain.models import Campaign, Scope
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.web import (
    HTTPObservation,
    WebAssessmentPolicy,
    WebAssessmentProvider,
    evaluate_web_policy,
)


class MemoryRepository:
    def __init__(self) -> None:
        self.evidence = []
        self.findings = []

    def save_evidence(self, evidence):
        self.evidence.append(evidence)

    def save_finding(self, finding):
        self.findings.append(finding)


class FakeProbe:
    def __init__(self, observation: HTTPObservation) -> None:
        self.observation = observation
        self.calls = []

    def request(self, url, method, timeout, max_bytes):
        self.calls.append((url, method, timeout, max_bytes))
        return self.observation


def observation(headers=(), status=200):
    return HTTPObservation(
        url="https://example.test/",
        method="HEAD",
        status_code=status,
        reason="OK",
        headers=tuple(headers),
        body_excerpt="",
    )


def test_web_policy_is_deterministic_and_evidence_backed() -> None:
    asset_id = uuid4()
    evidence_id = uuid4()
    findings = evaluate_web_policy(observation(), asset_id, evidence_id)

    assert {finding.vulnerability_id for finding in findings} == {
        "THREATLENS-WEB-HSTS",
        "THREATLENS-WEB-XCTO",
    }
    assert all(finding.evidence_ids == (evidence_id,) for finding in findings)
    assert all(finding.asset_id == asset_id for finding in findings)


def test_web_policy_does_not_flag_hsts_when_present() -> None:
    findings = evaluate_web_policy(
        observation(
            headers=(
                ("strict-transport-security", "max-age=31536000"),
                ("x-content-type-options", "nosniff"),
            )
        ),
        uuid4(),
        uuid4(),
    )
    assert findings == ()


def test_web_provider_persists_evidence_and_policy_findings() -> None:
    repository = MemoryRepository()
    asset = None
    from threatlens.domain.models import Asset

    asset = Asset(
        canonical_id="url:https://example.test/", asset_type="url", value="https://example.test/"
    )
    probe = FakeProbe(observation())
    provider = WebAssessmentProvider(
        ProviderHandoff(repository),
        WebAssessmentPolicy(allow_private_addresses=True),
        probe=probe,
        asset_resolver=lambda canonical_id: asset if canonical_id == asset.canonical_id else None,
        destination_resolver=lambda hostname: ("93.184.216.34",),
    )
    campaign = Campaign(
        name="web-assessment",
        scope=Scope(include=("https://example.test/",)),
        authorized=True,
    )

    execution_id = uuid4()
    provider.execute(campaign, execution_id, Event())

    assert len(probe.calls) == 1
    assert probe.calls[0][1] == "HEAD"
    assert len(repository.evidence) == 1
    assert len(repository.findings) == 2
    assert all(
        str(execution_id) == finding_metadata["execution_id"]
        for finding_metadata in [repository.evidence[0].metadata]
    )


def test_web_provider_rejects_private_destination_by_default() -> None:
    provider = WebAssessmentProvider(
        ProviderHandoff(MemoryRepository()),
        probe=FakeProbe(observation()),
    )
    campaign = Campaign(
        name="web-ssrf-boundary",
        scope=Scope(include=("http://127.0.0.1/",)),
        authorized=True,
    )
    with pytest.raises(PermissionError, match="non-public"):
        provider.execute(campaign, uuid4(), Event())


def test_web_provider_rejects_url_userinfo() -> None:
    with pytest.raises(ValueError, match="userinfo"):
        WebAssessmentProvider._normalize_url("https://user:pass@example.test/")


def test_web_provider_supports_explicit_bounded_get() -> None:
    repository = MemoryRepository()
    probe = FakeProbe(observation())
    provider = WebAssessmentProvider(
        ProviderHandoff(repository),
        WebAssessmentPolicy(methods=("GET",), allow_private_addresses=True),
        probe=probe,
        destination_resolver=lambda hostname: ("93.184.216.34",),
    )
    campaign = Campaign(
        name="bounded-get",
        scope=Scope(include=("https://example.test/",)),
        authorized=True,
    )
    provider.execute(campaign, uuid4(), Event())
    assert probe.calls[0][1] == "GET"
