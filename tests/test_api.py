from threading import Event
from uuid import uuid4

import pytest

from threatlens.domain.models import Asset, Campaign, Scope
from threatlens.providers.api import (
    APIObservation,
    APIAssessmentPolicy,
    APIAssessmentProvider,
    evaluate_api_policy,
)
from threatlens.providers.handoff import ProviderHandoff


class MemoryRepository:
    def __init__(self) -> None:
        self.evidence = []
        self.findings = []

    def save_evidence(self, evidence):
        self.evidence.append(evidence)

    def save_finding(self, finding):
        self.findings.append(finding)


class FakeProbe:
    def __init__(self, observation: APIObservation) -> None:
        self.observation = observation
        self.calls = []

    def request(self, url, method, timeout, max_bytes):
        self.calls.append((url, method, timeout, max_bytes))
        return self.observation


def make_observation(body="{}", headers=(("content-type", "application/json"),)):
    return APIObservation(
        url="https://api.example.test/v1/items",
        method="GET",
        status_code=200,
        reason="OK",
        headers=headers,
        body_excerpt=body,
    )


def test_api_policy_flags_only_malformed_explicit_json() -> None:
    findings = evaluate_api_policy(make_observation(body='{"broken":'), uuid4(), uuid4())
    assert len(findings) == 1
    assert findings[0].vulnerability_id == "THREATLENS-API-JSON"


def test_api_policy_ignores_non_json_and_head() -> None:
    asset_id = uuid4()
    evidence_id = uuid4()
    assert (
        evaluate_api_policy(
            make_observation(body="<html>", headers=(("content-type", "text/html"),)),
            asset_id,
            evidence_id,
        )
        == ()
    )
    assert (
        evaluate_api_policy(
            APIObservation(
                url="https://api.example.test/v1/items",
                method="HEAD",
                status_code=200,
                reason="OK",
                headers=(("content-type", "application/json"),),
                body_excerpt="",
            ),
            asset_id,
            evidence_id,
        )
        == ()
    )


def test_api_provider_persists_evidence_and_finding() -> None:
    repository = MemoryRepository()
    asset = Asset(
        canonical_id="url:https://api.example.test/v1/items",
        asset_type="url",
        value="https://api.example.test/v1/items",
    )
    provider = APIAssessmentProvider(
        ProviderHandoff(repository),
        APIAssessmentPolicy(methods=("GET",)),
        probe=FakeProbe(make_observation(body='{"broken":')),
        asset_resolver=lambda canonical_id: asset,
        destination_resolver=lambda hostname: ("93.184.216.34",),
    )
    campaign = Campaign(
        name="api-assessment",
        scope=Scope(include=("https://api.example.test/v1/items",)),
        authorized=True,
    )
    provider.execute(campaign, uuid4(), Event())
    assert len(repository.evidence) == 1
    assert len(repository.findings) == 1
    assert repository.evidence[0].kind == "api-assessment"
    assert repository.findings[0].evidence_ids == (repository.evidence[0].id,)


def test_api_provider_rejects_private_destination() -> None:
    provider = APIAssessmentProvider(
        ProviderHandoff(MemoryRepository()),
        probe=FakeProbe(make_observation()),
        destination_resolver=lambda hostname: ("127.0.0.1",),
    )
    campaign = Campaign(
        name="api-ssrf-boundary",
        scope=Scope(include=("https://api.example.test/v1/items",)),
        authorized=True,
    )
    with pytest.raises(PermissionError, match="non-public"):
        provider.execute(campaign, uuid4(), Event())


def test_api_provider_rejects_userinfo_and_fragments() -> None:
    with pytest.raises(ValueError, match="userinfo"):
        APIAssessmentProvider._normalize_url("https://u:p@api.example.test/v1")
    with pytest.raises(ValueError, match="fragments"):
        APIAssessmentProvider._normalize_url("https://api.example.test/v1#fragment")


def test_api_provider_bounds_methods() -> None:
    with pytest.raises(ValueError):
        APIAssessmentPolicy(methods=("POST",))


def test_api_provider_does_not_expand_redirects() -> None:
    repository = MemoryRepository()
    asset = Asset(
        canonical_id="url:https://api.example.test/v1/items",
        asset_type="url",
        value="https://api.example.test/v1/items",
    )
    observation = APIObservation(
        url="https://api.example.test/v1/items",
        method="GET",
        status_code=302,
        reason="Found",
        headers=(("location", "https://other.example.test/v1"),),
        body_excerpt="",
        redirect_location="https://other.example.test/v1",
    )
    provider = APIAssessmentProvider(
        ProviderHandoff(repository),
        APIAssessmentPolicy(methods=("GET",), allow_private_addresses=True),
        probe=FakeProbe(observation),
        asset_resolver=lambda canonical_id: asset,
        destination_resolver=lambda hostname: ("93.184.216.34",),
    )
    provider.execute(
        Campaign(
            name="api-redirect",
            scope=Scope(include=("https://api.example.test/v1/items",)),
            authorized=True,
        ),
        uuid4(),
        Event(),
    )
    assert len(repository.evidence) == 1
    assert len(repository.findings) == 0
