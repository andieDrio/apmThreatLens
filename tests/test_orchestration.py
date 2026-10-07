from threading import Event, Thread
from time import sleep

import pytest

from threatlens.auth import AuthenticationService, Role
from threatlens.domain.models import Campaign, LifecycleState, Scope
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

    def execute(self, campaign, execution_id, cancel_event) -> None:
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
    orchestrator.cancel(results[0].execution_id if results else repo.connection.execute("SELECT execution_id FROM scans ORDER BY queued_at DESC LIMIT 1").fetchone()[0], principal=principal)
    cancel_event.set()
    worker.join(1.0)

    assert not worker.is_alive()
    assert len(results) == 1
    assert results[0].state is LifecycleState.CANCELLED
    assert repo.scan_state(results[0].execution_id) is LifecycleState.CANCELLED
    repo.close()
