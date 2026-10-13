from datetime import UTC, datetime
from threading import Barrier, Thread
from uuid import UUID, uuid4

import pytest
from psycopg.errors import ForeignKeyViolation

from threatlens.auth import AuthenticationService, Role
from threatlens.domain.models import (
    Asset,
    AuditEvent,
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
from threatlens.safety.policy import ExecutionPolicy
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
    with pytest.raises(ForeignKeyViolation):
        postgres_repository.save_service(Service(asset_id=uuid4(), protocol="tcp", port=443))


def test_postgres_auth_persistence(postgres_repository):
    auth = AuthenticationService(postgres_repository)
    auth.create_user("postgres-analyst", "correct horse battery staple", Role.ANALYST)
    assert postgres_repository.count("users") == 1
    assert postgres_repository.count("audit_events") >= 1


def test_postgres_audit_events_read_model_is_bounded_ordered_and_excludes_detail(
    postgres_repository,
):
    repo = postgres_repository
    created_at = datetime(2026, 10, 13, tzinfo=UTC)
    older = AuditEvent(
        action="OLDER_EVENT",
        resource_type="AUTH",
        outcome="SUCCESS",
        detail="password=must-not-be-exposed",
        id=UUID(int=1),
        created_at=created_at,
    )
    newer = AuditEvent(
        action="NEWER_EVENT",
        resource_type="AUTH",
        outcome="DENIED",
        detail="session_token=must-not-be-exposed",
        id=UUID(int=2),
        created_at=created_at,
    )
    repo.save_audit_event(older)
    repo.save_audit_event(newer)

    first_page = repo.audit_events_read_model(limit=1, offset=0)
    assert first_page["total"] == 2
    assert first_page["limit"] == 1
    assert first_page["offset"] == 0
    assert first_page["items"][0]["id"] == str(newer.id)
    assert first_page["items"][0]["action"] == "NEWER_EVENT"
    assert "detail" not in first_page["items"][0]
    assert "password" not in str(first_page["items"][0])
    assert "session_token" not in str(first_page["items"][0])

    second_page = repo.audit_events_read_model(limit=1, offset=1)
    assert second_page["items"][0]["id"] == str(older.id)


def test_postgres_audit_events_read_model_empty(postgres_repository):
    result = postgres_repository.audit_events_read_model()
    assert result == {"total": 0, "limit": 50, "offset": 0, "items": []}



def test_postgres_scan_queue_idempotency_rejects_changed_request(postgres_repository):
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    auth = AuthenticationService(repo)
    auth.create_user("idempotency-analyst", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("idempotency-analyst", "correct horse battery staple")
    orchestrator = ScanOrchestrator(repo, ExecutionPolicy(), auth)

    class Provider:
        name = "idempotency-provider"

        def execute(self, campaign, execution_id, cancel_event):
            raise AssertionError("queueing must not execute providers")

    class DifferentProvider:
        name = "different-provider"

        def execute(self, campaign, execution_id, cancel_event):
            raise AssertionError("queueing must not execute providers")

    first, created = orchestrator.queue_idempotent(
        campaign, Provider(), "same-idempotency-key-0001", principal=principal
    )
    replay, replay_created = orchestrator.queue_idempotent(
        campaign, Provider(), "same-idempotency-key-0001", principal=principal
    )
    assert created is True
    assert replay_created is False
    assert replay.execution_id == first.execution_id
    with pytest.raises(ValueError, match="different scan request"):
        orchestrator.queue_idempotent(
            campaign, DifferentProvider(), "same-idempotency-key-0001", principal=principal
        )
    assert repo.count("scans") == 1
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='SCAN_QUEUED'"
    ).fetchone()[0] == 1



def test_postgres_scan_idempotency_and_audit_are_atomic_on_audit_failure(
    postgres_repository,
):
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    auth = AuthenticationService(repo)
    auth.create_user("atomic-idempotency", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("atomic-idempotency", "correct horse battery staple")
    orchestrator = ScanOrchestrator(repo, ExecutionPolicy(), auth)

    class Provider:
        name = "atomic-idempotency-provider"

        def execute(self, campaign, execution_id, cancel_event):
            raise AssertionError("queueing must not execute providers")

    repo.connection.execute(
        """
        CREATE OR REPLACE FUNCTION fail_idempotent_queue_audit_fn()
        RETURNS trigger AS $
        BEGIN
            IF NEW.action = 'SCAN_QUEUED' THEN
                RAISE EXCEPTION 'injected idempotent queue audit failure';
            END IF;
            RETURN NEW;
        END;
        $ LANGUAGE plpgsql;
        CREATE TRIGGER fail_idempotent_queue_audit
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_idempotent_queue_audit_fn()
        """
    )
    repo.connection.commit()
    key = "atomic-idempotency-key-0001"
    with pytest.raises(Exception, match="injected idempotent queue audit failure"):
        orchestrator.queue_idempotent(campaign, Provider(), key, principal=principal)
    assert repo.count("scans") == 0
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM scan_command_idempotency"
    ).fetchone()[0] == 0

    repo.connection.execute(
        "DROP TRIGGER fail_idempotent_queue_audit ON audit_events; "
        "DROP FUNCTION fail_idempotent_queue_audit_fn()"
    )
    repo.connection.commit()
    scan, created = orchestrator.queue_idempotent(
        campaign, Provider(), key, principal=principal
    )
    assert created is True
    assert repo.scan_state(scan.execution_id) is LifecycleState.QUEUED
    assert repo.count("scans") == 1
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM scan_command_idempotency"
    ).fetchone()[0] == 1


def test_postgres_cross_instance_scan_queue_idempotency_has_single_winner(
    postgres_repository,
):
    import os

    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    auth = AuthenticationService(repo)
    auth.create_user("distributed-idempotency", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("distributed-idempotency", "correct horse battery staple")
    dsn = os.getenv("THREATLENS_TEST_DATABASE_URL") or os.getenv("THREATLENS_DATABASE_URL")
    assert dsn
    repo2 = PostgresRepository(dsn)
    repo2.initialize()
    try:
        auth2 = AuthenticationService(repo2)
        principal2, _ = auth2.authenticate("distributed-idempotency", "correct horse battery staple")
        orchestrator1 = ScanOrchestrator(repo, ExecutionPolicy(), auth)
        orchestrator2 = ScanOrchestrator(repo2, ExecutionPolicy(), auth2)
        barrier = Barrier(2)
        results = []
        errors = []

        class Provider:
            name = "distributed-idempotency-provider"

            def execute(self, campaign, execution_id, cancel_event):
                raise AssertionError("queueing must not execute providers")

        def queue(orchestrator, worker_principal):
            try:
                barrier.wait(timeout=5)
                results.append(
                    orchestrator.queue_idempotent(
                        campaign,
                        Provider(),
                        "distributed-idempotency-key-0001",
                        principal=worker_principal,
                    )
                )
            except Exception as exc:
                errors.append(exc)

        workers = [
            Thread(target=queue, args=(orchestrator1, principal)),
            Thread(target=queue, args=(orchestrator2, principal2)),
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)

        assert all(not worker.is_alive() for worker in workers)
        assert not errors
        assert len(results) == 2
        assert len({item[0].execution_id for item in results}) == 1
        assert sorted(item[1] for item in results) == [False, True]
        assert repo.count("scans") == 1
        assert repo.connection.execute(
            "SELECT COUNT(*) FROM audit_events WHERE action='SCAN_QUEUED'"
        ).fetchone()[0] == 1
    finally:
        repo2.close()


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
        scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING
    )
    assert repo.scan_state(scan.execution_id) is LifecycleState.RUNNING
