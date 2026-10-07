from uuid import uuid4

import pytest

from threatlens.auth import AuthenticationService, Role
from threatlens.domain.models import (
    Asset,
    Campaign,
    Evidence,
    Finding,
    FindingState,
    LifecycleState,
    Scope,
    Service,
    Severity,
)
from threatlens.evidence.validation import EvidenceValidation, EvidenceValidationState
from threatlens.orchestration.engine import ScanOrchestrator
from threatlens.providers.handoff import ProviderHandoff
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata
from threatlens.safety.policy import ExecutionPolicy
from threatlens.storage.finding_correlation import DurableFindingCorrelator


def make_campaign():
    return Campaign(
        name="authorized-postgres-campaign",
        scope=Scope(include=("198.51.100.10",)),
        authorized=True,
    )


def test_postgres_persists_domain_relationships(postgres_repository):
    repo = postgres_repository
    c = make_campaign()
    asset = Asset(canonical_id="ip:198.51.100.10", asset_type="ipv4", value="198.51.100.10")
    service = Service(asset_id=asset.id, protocol="tcp", port=443, service_name="https")
    evidence = ProviderHandoff.seal_evidence(
        Evidence(kind="http-response", content="HTTP/1.1 200 OK", source="unit-test")
    )
    finding = Finding(
        title="Example finding",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
        confidence=0.9,
        source="unit-test",
    )
    repo.save_campaign(c)
    repo.save_asset(asset)
    repo.save_service(service)
    repo.save_evidence(evidence)
    repo.save_finding(finding)
    assert repo.count("campaigns") == 1
    assert repo.count("assets") == 1
    assert repo.count("services") == 1
    assert repo.count("evidence") == 1
    assert repo.count("findings") == 1
    assert repo.count("finding_evidence") == 1
    assert repo.asset_id(asset.canonical_id) == asset.id


def test_postgres_enforces_foreign_key_integrity(postgres_repository):
    with pytest.raises(Exception):
        postgres_repository.save_service(Service(asset_id=uuid4(), protocol="tcp", port=443))


def test_postgres_auth_persistence(postgres_repository):
    auth = AuthenticationService(postgres_repository)
    auth.create_user("postgres-analyst", "correct horse battery staple", Role.ANALYST)
    assert postgres_repository.count("users") == 1
    assert postgres_repository.count("audit_events") >= 1


def test_postgres_durable_correlation_merges_provider_findings(postgres_repository):
    repo = postgres_repository
    asset = Asset(canonical_id="host:10.0.0.10", asset_type="ip", value="10.0.0.10")
    repo.save_asset(asset)
    a = ProviderMetadata(
        "scanner-a",
        "1.0.0",
        frozenset({ProviderCapability.VULNERABILITY, ProviderCapability.EVIDENCE}),
    )
    b = ProviderMetadata(
        "scanner-b",
        "1.0.0",
        frozenset({ProviderCapability.VULNERABILITY, ProviderCapability.EVIDENCE}),
    )
    correlator = DurableFindingCorrelator(repo)
    ha = ProviderHandoff(repo, correlator=correlator)
    hb = ProviderHandoff(repo, correlator=correlator)
    ea = ha.persist_evidence(uuid4(), a, Evidence(kind="scan", content="a", source="a"))
    eb = hb.persist_evidence(uuid4(), b, Evidence(kind="scan", content="b", source="b"))

    def make_finding(evidence_id, severity):
        return Finding(
            title="Weak TLS",
            asset_id=asset.id,
            evidence_ids=(evidence_id,),
            state=FindingState.CONFIRMED,
            severity=severity,
            vulnerability_id="TLS-WEAK-CIPHER",
            cwe="CWE-326",
            confidence=0.8,
        )

    first = ha.persist_finding(uuid4(), a, asset, make_finding(ea.id, Severity.MEDIUM), (ea,))
    second = hb.persist_finding(uuid4(), b, asset, make_finding(eb.id, Severity.HIGH), (eb,))
    assert first.id == second.id
    assert repo.count("findings") == 1
    assert repo.count("finding_evidence") == 2


def test_postgres_evidence_validation_is_append_only(postgres_repository):
    repo = postgres_repository
    evidence = ProviderHandoff.seal_evidence(
        Evidence(kind="banner", content="SSH-2.0-test", source="test")
    )
    repo.save_evidence(evidence)
    pending = EvidenceValidation(
        evidence_id=evidence.id,
        state=EvidenceValidationState.PENDING,
        validator="analyst",
        rationale="Awaiting independent review.",
    )
    repo.save_evidence_validation(pending)
    validated = EvidenceValidation(
        evidence_id=evidence.id,
        state=EvidenceValidationState.VALIDATED,
        validator="reviewer",
        rationale="Independently confirmed.",
        supporting_evidence_ids=(evidence.id,),
    )
    repo.transition_evidence_validation(pending.id, validated)
    assert repo.count("evidence_validations") == 2


def test_postgres_scan_lifecycle_cas_is_authoritative(postgres_repository):
    repo = postgres_repository
    c = make_campaign()
    repo.save_campaign(c)
    auth = AuthenticationService(repo)
    auth.create_user("lifecycle-analyst", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("lifecycle-analyst", "correct horse battery staple")

    class Provider:
        name = "postgres-test-provider"

        def execute(self, campaign, execution_id, cancel_event):
            return None

    orchestrator = ScanOrchestrator(repo, ExecutionPolicy(), auth)
    scan = orchestrator.queue(c, Provider(), principal=principal)
    assert repo.update_scan_state_if_current(
        scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING
    )
    assert not repo.update_scan_state_if_current(
        scan.execution_id, LifecycleState.QUEUED, LifecycleState.COMPLETED
    )
    assert repo.scan_state(scan.execution_id) is LifecycleState.RUNNING
