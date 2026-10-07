import sqlite3
from threading import Event, Thread
from time import sleep
from uuid import UUID

import pytest

from threatlens.auth import AuthenticationService, Role
from threatlens.domain.models import AuditEvent, Campaign, LifecycleState, Scope
from threatlens.orchestration.engine import ScanOrchestrator
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata, ProviderRegistry
from threatlens.safety.policy import ExecutionPolicy
from threatlens.storage.sqlite import SQLiteRepository


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


def make_orchestrator(tmp_path) -> tuple[SQLiteRepository, ScanOrchestrator, Campaign, object]:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    campaign = make_campaign()
    repo.save_campaign(campaign)
    auth = AuthenticationService(repo)
    auth.create_user("analyst", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("analyst", "correct horse battery staple")
    return repo, ScanOrchestrator(repo, ExecutionPolicy(), auth), campaign, principal


def test_successful_provider_reaches_completed(tmp_path) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(tmp_path)
    result = orchestrator.run(campaign, SuccessfulProvider(), principal=principal)
    assert result.state is LifecycleState.COMPLETED
    assert repo.scan_state(result.execution_id) is LifecycleState.COMPLETED
    repo.close()


def test_registered_provider_path_uses_runtime_and_observer(tmp_path) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(tmp_path)
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


def test_provider_failure_is_persisted_and_does_not_escape_as_success(tmp_path) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(tmp_path)
    result = orchestrator.run(campaign, FailingProvider(), principal=principal)
    assert result.state is LifecycleState.FAILED
    assert repo.scan_state(result.execution_id) is LifecycleState.FAILED
    repo.close()


def test_pre_cancelled_execution_never_enters_provider(tmp_path) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(tmp_path)
    event = Event()
    event.set()
    result = orchestrator.run(campaign, CancelAwareProvider(), event, principal=principal)
    assert result.state is LifecycleState.CANCELLED
    assert repo.scan_state(result.execution_id) is LifecycleState.CANCELLED
    repo.close()


def test_terminal_scan_cannot_transition_again(tmp_path) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(tmp_path)
    result = orchestrator.run(campaign, SuccessfulProvider(), principal=principal)
    with pytest.raises(ValueError, match="invalid lifecycle transition"):
        repo.update_scan_state(result.execution_id, LifecycleState.FAILED)
    repo.close()


def test_scan_requires_authenticated_principal(tmp_path):
    repo, orchestrator, campaign, _ = make_orchestrator(tmp_path)
    with pytest.raises(PermissionError, match="authentication required"):
        orchestrator.run(campaign, SuccessfulProvider())
    repo.close()


def test_scan_cancellation_requires_authenticated_principal(tmp_path):
    repo, orchestrator, campaign, principal = make_orchestrator(tmp_path)
    scan = orchestrator.queue(campaign, SuccessfulProvider(), principal=principal)
    with pytest.raises(PermissionError, match="authentication required"):
        orchestrator.cancel(scan.execution_id)
    orchestrator.cancel(scan.execution_id, principal=principal)
    assert repo.scan_state(scan.execution_id) is LifecycleState.CANCELLED
    repo.close()


def test_concurrent_cancellation_wins_over_provider_completion(tmp_path) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(tmp_path)
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


def test_external_cancellation_is_thread_safe_against_provider_finalization(tmp_path) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(tmp_path)
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


def test_queue_and_audit_are_atomic_on_audit_failure(tmp_path) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(tmp_path)
    repo.connection.execute(
        """CREATE TRIGGER fail_queue_audit BEFORE INSERT ON audit_events
           WHEN NEW.action = 'SCAN_QUEUED'
           BEGIN SELECT RAISE(ABORT, 'injected queue audit failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError, match="injected queue audit failure"):
        orchestrator.queue(campaign, SuccessfulProvider(), principal=principal)
    assert repo.count("scans") == 0
    repo.connection.execute("DROP TRIGGER fail_queue_audit")
    repo.close()


def test_successful_provider_is_not_marked_failed_when_finalization_persistence_fails(tmp_path) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(tmp_path)
    repo.connection.execute(
        """CREATE TRIGGER fail_finalization_audit BEFORE INSERT ON audit_events
           WHEN NEW.action = 'SCAN_FINALIZED'
           BEGIN SELECT RAISE(ABORT, 'injected finalization audit failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError, match="injected finalization audit failure"):
        orchestrator.run(campaign, SuccessfulProvider(), principal=principal)
    scan_id = repo.connection.execute("SELECT execution_id FROM scans ORDER BY queued_at DESC LIMIT 1").fetchone()[0]
    assert repo.scan_state(UUID(scan_id)) is LifecycleState.RUNNING
    repo.connection.execute("DROP TRIGGER fail_finalization_audit")
    repo.update_scan_state_if_current_with_audit(
        UUID(scan_id),
        LifecycleState.RUNNING,
        LifecycleState.COMPLETED,
        AuditEvent(actor_user_id=principal.user_id, action="SCAN_FINALIZED", resource_type="SCAN", resource_id=UUID(scan_id), outcome=LifecycleState.COMPLETED.value, detail="recovered after persistence failure"),
    )
    assert repo.scan_state(UUID(scan_id)) is LifecycleState.COMPLETED
    assert repo.count("audit_events") >= 3
    repo.close()


def test_cancellation_and_audit_are_atomic_on_audit_failure(tmp_path) -> None:
    repo, orchestrator, campaign, principal = make_orchestrator(tmp_path)
    scan = orchestrator.queue(campaign, SuccessfulProvider(), principal=principal)
    repo.connection.execute(
        """CREATE TRIGGER fail_cancel_audit BEFORE INSERT ON audit_events
           WHEN NEW.action = 'SCAN_CANCELLED'
           BEGIN SELECT RAISE(ABORT, 'injected cancel audit failure'); END"""
    )
    with pytest.raises(sqlite3.IntegrityError, match="injected cancel audit failure"):
        orchestrator.cancel(scan.execution_id, principal=principal)
    assert repo.scan_state(scan.execution_id) is LifecycleState.QUEUED
    repo.connection.execute("DROP TRIGGER fail_cancel_audit")
    orchestrator.cancel(scan.execution_id, principal=principal)
    assert repo.scan_state(scan.execution_id) is LifecycleState.CANCELLED
    repo.close()
