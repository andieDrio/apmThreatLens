from threading import Event, Thread
from time import sleep
from uuid import UUID

import pytest

from threatlens.auth import AuthenticationService, Role
from threatlens.domain.models import AuditEvent, Campaign, LifecycleState, Scope
from threatlens.orchestration.engine import ScanOrchestrator
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata, ProviderRegistry
from threatlens.safety.policy import ExecutionPolicy
from threatlens.storage.postgres import PostgresRepository


class SuccessfulProvider:
    name = "test-provider"

    def execute(self, campaign, execution_id, cancel_event) -> None:
        assert campaign.authorized
        assert not cancel_event.is_set()


class FailingProvider:
    name = "failing-provider"

    def execute(self, campaign, execution_id, cancel_event) -> None:
        raise RuntimeError("provider failure")


class CancelDuringExecutionProvider:
    name = "cancel-during-execution"

    def __init__(self, cancel) -> None:
        self.cancel = cancel

    def execute(self, campaign, execution_id, cancel_event) -> None:
        self.cancel(execution_id)


class CancelAwareProvider:
    name = "cancel-aware-provider"

    def execute(self, campaign, execution_id, cancel_event) -> None:
        assert cancel_event.is_set()


def make_campaign() -> Campaign:
    return Campaign(
        name="authorized-campaign",
        scope=Scope(include=("198.51.100.10",)),
        authorized=True,
    )


def make_orchestrator(postgres_repository) -> tuple[PostgresRepository, ScanOrchestrator, Campaign, object]:
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    auth = AuthenticationService(repo)
    auth.create_user("analyst", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("analyst", "correct horse battery staple")
    return repo, ScanOrchestrator(repo, ExecutionPolicy(), auth), campaign, principal


def test_successful_provider_reaches_completed(postgres_repository) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    result = orchestrator.run(campaign, SuccessfulProvider(), principal=principal)
    assert result.state is LifecycleState.COMPLETED
    assert repo.scan_state(result.execution_id) is LifecycleState.COMPLETED
    repo.close()


def test_registered_provider_path_uses_runtime_and_observer(postgres_repository) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    registry = ProviderRegistry()
    registry.register(
        ProviderMetadata(
            name="test-provider",
            version="1.0.0",
            capabilities=frozenset({ProviderCapability.NETWORK}),
        ),
        SuccessfulProvider(),
    )
    observed = []
    result = orchestrator.run_registered(campaign, "test-provider", registry, observer=observed.append, principal=principal)
    assert result.state is LifecycleState.COMPLETED
    assert [event.event_type.value for event in observed] == ["STARTED", "COMPLETED"]
    repo.close()


def test_provider_failure_is_persisted_and_does_not_escape_as_success(postgres_repository) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    result = orchestrator.run(campaign, FailingProvider(), principal=principal)
    assert result.state is LifecycleState.FAILED
    assert repo.scan_state(result.execution_id) is LifecycleState.FAILED
    repo.close()


def test_pre_cancelled_execution_never_enters_provider(postgres_repository) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    event = Event()
    event.set()
    result = orchestrator.run(campaign, CancelAwareProvider(), event, principal=principal)
    assert result.state is LifecycleState.CANCELLED
    assert repo.scan_state(result.execution_id) is LifecycleState.CANCELLED
    repo.close()


def test_terminal_scan_cannot_transition_again(postgres_repository) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    result = orchestrator.run(campaign, SuccessfulProvider(), principal=principal)
    with pytest.raises(ValueError, match="invalid lifecycle transition"):
        repo.update_scan_state(result.execution_id, LifecycleState.FAILED)
    repo.close()


def test_scan_requires_authenticated_principal(postgres_repository):
    repo, orchestrator, campaign, _ = make_orchestrator(postgres_repository)
    with pytest.raises(PermissionError, match="authentication required"):
        orchestrator.run(campaign, SuccessfulProvider())
    repo.close()


def test_scan_cancellation_requires_authenticated_principal(postgres_repository):
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    scan = orchestrator.queue(campaign, SuccessfulProvider(), principal=principal)
    with pytest.raises(PermissionError, match="authentication required"):
        orchestrator.cancel(scan.execution_id)
    orchestrator.cancel(scan.execution_id, principal=principal)
    assert repo.scan_state(scan.execution_id) is LifecycleState.CANCELLED
    repo.close()


def test_concurrent_cancellation_wins_over_provider_completion(postgres_repository) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    provider = CancelDuringExecutionProvider(lambda execution_id: orchestrator.cancel(execution_id, principal))
    result = orchestrator.run(campaign, provider, principal=principal)
    assert result.state is LifecycleState.CANCELLED
    assert repo.scan_state(result.execution_id) is LifecycleState.CANCELLED
    repo.close()


class ExternallyCancelledProvider:
    name = "externally-cancelled-provider"

    def __init__(self, started: Event) -> None:
        self.started = started
        self.execution_id = None

    def execute(self, campaign, execution_id, cancel_event) -> None:
        self.execution_id = execution_id
        self.started.set()
        while not cancel_event.is_set():
            sleep(0.005)


def test_external_cancellation_is_thread_safe_against_provider_finalization(postgres_repository) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    started = Event()
    cancel_event = Event()
    provider = ExternallyCancelledProvider(started)
    results = []

    worker = Thread(
        target=lambda: results.append(
            orchestrator.run(campaign, provider, cancel_event, principal=principal)
        )
    )
    worker.start()
    assert started.wait(1.0)
    assert provider.execution_id is not None
    orchestrator.cancel(provider.execution_id, principal=principal)
    cancel_event.set()
    worker.join(1.0)

    assert not worker.is_alive()
    assert len(results) == 1
    assert results[0].state is LifecycleState.CANCELLED
    assert repo.scan_state(results[0].execution_id) is LifecycleState.CANCELLED
    repo.close()


def test_queue_and_audit_are_atomic_on_audit_failure(postgres_repository) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    repo.connection.execute(
        """CREATE OR REPLACE FUNCTION fail_queue_audit_fn() RETURNS trigger AS $ BEGIN IF NEW.action = 'SCAN_QUEUED' THEN RAISE EXCEPTION 'injected queue audit failure'; END IF; RETURN NEW; END; $ LANGUAGE plpgsql; CREATE TRIGGER fail_queue_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_queue_audit_fn()"""
    )
    repo.connection.commit()
    with pytest.raises(Exception, match="injected queue audit failure"):
        orchestrator.queue(campaign, SuccessfulProvider(), principal=principal)
    assert repo.count("scans") == 0
    repo.connection.execute("DROP TRIGGER fail_queue_audit ON audit_events; DROP FUNCTION fail_queue_audit_fn()"); repo.connection.commit()
    repo.close()


def test_successful_provider_is_not_marked_failed_when_finalization_persistence_fails(postgres_repository) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    repo.connection.execute(
        """CREATE OR REPLACE FUNCTION fail_finalization_audit_fn() RETURNS trigger AS $ BEGIN IF NEW.action = 'SCAN_FINALIZED' THEN RAISE EXCEPTION 'injected finalization audit failure'; END IF; RETURN NEW; END; $ LANGUAGE plpgsql; CREATE TRIGGER fail_finalization_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_finalization_audit_fn()"""
    )
    with pytest.raises(Exception, match="injected finalization audit failure"):
        orchestrator.run(campaign, SuccessfulProvider(), principal=principal)
    scan_id = repo.connection.execute("SELECT execution_id FROM scans ORDER BY queued_at DESC LIMIT 1").fetchone()[0]
    assert repo.scan_state(UUID(scan_id)) is LifecycleState.RUNNING
    repo.connection.execute("DROP TRIGGER fail_finalization_audit ON audit_events; DROP FUNCTION fail_finalization_audit_fn()"); repo.connection.commit()
    repo.update_scan_state_if_current_with_audit(
        UUID(scan_id),
        LifecycleState.RUNNING,
        LifecycleState.COMPLETED,
        AuditEvent(actor_user_id=principal.user_id, action="SCAN_FINALIZED", resource_type="SCAN", resource_id=UUID(scan_id), outcome=LifecycleState.COMPLETED.value, detail="recovered after persistence failure"),
    )
    assert repo.scan_state(UUID(scan_id)) is LifecycleState.COMPLETED
    assert repo.count("audit_events") >= 3
    repo.close()


def test_cancellation_and_audit_are_atomic_on_audit_failure(postgres_repository) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    scan = orchestrator.queue(campaign, SuccessfulProvider(), principal=principal)
    repo.connection.execute(
        """CREATE OR REPLACE FUNCTION fail_cancel_audit_fn() RETURNS trigger AS $ BEGIN IF NEW.action = 'SCAN_CANCELLED' THEN RAISE EXCEPTION 'injected cancel audit failure'; END IF; RETURN NEW; END; $ LANGUAGE plpgsql; CREATE TRIGGER fail_cancel_audit BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fail_cancel_audit_fn()"""
    )
    with pytest.raises(Exception, match="injected cancel audit failure"):
        orchestrator.cancel(scan.execution_id, principal=principal)
    assert repo.scan_state(scan.execution_id) is LifecycleState.QUEUED
    repo.connection.execute("DROP TRIGGER fail_cancel_audit ON audit_events; DROP FUNCTION fail_cancel_audit_fn()"); repo.connection.commit()
    orchestrator.cancel(scan.execution_id, principal=principal)
    assert repo.scan_state(scan.execution_id) is LifecycleState.CANCELLED
    repo.close()


def test_stale_running_scan_can_be_recovered_from_expired_heartbeat(postgres_repository) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    scan = orchestrator.queue(campaign, SuccessfulProvider(), principal=principal)
    assert repo.update_scan_state_if_current(scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING)
    repo.connection.execute("UPDATE scans SET heartbeat_at=%s WHERE execution_id=%s", ("2000-01-01T00:00:00+00:00", scan.execution_id))
    repo.connection.commit()
    assert orchestrator.recover_stale(scan.execution_id, principal=principal)
    assert repo.scan_state(scan.execution_id) is LifecycleState.FAILED
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='SCAN_RECOVERED_STALE'"
    ).fetchone()[0] == 1
    repo.close()


def test_recent_heartbeat_is_not_recovered_as_stale(postgres_repository) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(postgres_repository)
    scan = orchestrator.queue(campaign, SuccessfulProvider(), principal=principal)
    assert repo.update_scan_state_if_current(scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING)
    repo.heartbeat_scan(scan.execution_id)
    assert not orchestrator.recover_stale(scan.execution_id, principal=principal)
    assert repo.scan_state(scan.execution_id) is LifecycleState.RUNNING
    repo.close()


def test_cross_instance_stale_recovery_has_single_winner(postgres_repository):
    import os
    from threading import Barrier
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    auth = AuthenticationService(repo)
    auth.create_user("distributed-analyst", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("distributed-analyst", "correct horse battery staple")
    orchestrator = ScanOrchestrator(repo, ExecutionPolicy(), auth)
    scan = orchestrator.queue(campaign, SuccessfulProvider(), principal=principal)
    assert repo.update_scan_state_if_current(scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING)
    repo.connection.execute("UPDATE scans SET heartbeat_at=%s WHERE execution_id=%s", ("2000-01-01T00:00:00+00:00", scan.execution_id))
    repo.connection.commit()

    dsn = os.getenv("THREATLENS_TEST_DATABASE_URL") or os.getenv("THREATLENS_DATABASE_URL")
    assert dsn
    repo2 = PostgresRepository(dsn)
    repo2.initialize()
    try:
        auth2 = AuthenticationService(repo2)
        principal2, _ = auth2.authenticate("distributed-analyst", "correct horse battery staple")
        orchestrator2 = ScanOrchestrator(repo2, ExecutionPolicy(), auth2)
        barrier = Barrier(2)
        results = []
        errors = []

        def recover(worker):
            try:
                barrier.wait(timeout=5)
                results.append(worker.recover_stale(scan.execution_id, principal=principal if worker is orchestrator else principal2))
            except Exception as exc:
                errors.append(exc)

        t1 = Thread(target=recover, args=(orchestrator,))
        t2 = Thread(target=recover, args=(orchestrator2,))
        t1.start(); t2.start(); t1.join(10); t2.join(10)
        assert not errors
        assert sorted(results) == [False, True]
        assert repo.scan_state(scan.execution_id) is LifecycleState.FAILED
        assert repo.connection.execute("SELECT COUNT(*) FROM audit_events WHERE action='SCAN_RECOVERED_STALE'").fetchone()[0] == 1
    finally:
        repo2.close()


def test_cross_instance_cancellation_and_finalization_have_single_lifecycle_winner(postgres_repository):
    import os
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    auth = AuthenticationService(repo)
    auth.create_user("race-analyst", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("race-analyst", "correct horse battery staple")
    orchestrator = ScanOrchestrator(repo, ExecutionPolicy(), auth)
    scan = orchestrator.queue(campaign, SuccessfulProvider(), principal=principal)
    assert repo.update_scan_state_if_current(scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING)

    dsn = os.getenv("THREATLENS_TEST_DATABASE_URL") or os.getenv("THREATLENS_DATABASE_URL")
    assert dsn
    repo2 = PostgresRepository(dsn)
    repo2.initialize()
    try:
        auth2 = AuthenticationService(repo2)
        principal2, _ = auth2.authenticate("race-analyst", "correct horse battery staple")
        barrier = Barrier(2)
        outcomes = []

        def cancel():
            barrier.wait(timeout=5)
            orchestrator2.cancel(scan.execution_id, principal=principal2)
            outcomes.append("cancel")

        def finalize():
            barrier.wait(timeout=5)
            won = repo.update_scan_state_if_current_with_audit(
                scan.execution_id,
                LifecycleState.RUNNING,
                LifecycleState.COMPLETED,
                AuditEvent(actor_user_id=principal.user_id, action="SCAN_FINALIZED", resource_type="SCAN", resource_id=scan.execution_id, outcome=LifecycleState.COMPLETED.value, detail="distributed finalization race"),
            )
            outcomes.append("finalize" if won else "lost")

        orchestrator2 = ScanOrchestrator(repo2, ExecutionPolicy(), auth2)
        t1 = Thread(target=cancel)
        t2 = Thread(target=finalize)
        t1.start(); t2.start(); t1.join(10); t2.join(10)
        assert sorted(outcomes) == ["cancel", "lost"] or sorted(outcomes) == ["cancel", "finalize"]
        assert repo.scan_state(scan.execution_id) in {LifecycleState.CANCELLED, LifecycleState.COMPLETED}
        terminal_audits = repo.connection.execute("SELECT COUNT(*) FROM audit_events WHERE resource_id=%s AND action IN ('SCAN_CANCELLED','SCAN_FINALIZED') AND outcome IN ('SUCCESS','COMPLETED')", (scan.execution_id,)).fetchone()[0]
        assert terminal_audits == 1
    finally:
        repo2.close()
