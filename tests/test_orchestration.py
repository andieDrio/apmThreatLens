from threading import Event

import pytest

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


def make_orchestrator(tmp_path) -> tuple[SQLiteRepository, ScanOrchestrator, Campaign]:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    campaign = make_campaign()
    repo.save_campaign(campaign)
    return repo, ScanOrchestrator(repo, ExecutionPolicy()), campaign


def test_successful_provider_reaches_completed(tmp_path) -> None:
    repo, orchestrator, campaign = make_orchestrator(tmp_path)
    result = orchestrator.run(campaign, SuccessfulProvider())
    assert result.state is LifecycleState.COMPLETED
    assert repo.scan_state(result.execution_id) is LifecycleState.COMPLETED
    repo.close()


def test_registered_provider_path_uses_runtime_and_observer(tmp_path) -> None:
    repo, orchestrator, campaign = make_orchestrator(tmp_path)
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
    result = orchestrator.run_registered(campaign, "test-provider", registry, observer=observed.append)
    assert result.state is LifecycleState.COMPLETED
    assert [event.event_type.value for event in observed] == ["STARTED", "COMPLETED"]
    repo.close()


def test_provider_failure_is_persisted_and_does_not_escape_as_success(tmp_path) -> None:
    repo, orchestrator, campaign = make_orchestrator(tmp_path)
    result = orchestrator.run(campaign, FailingProvider())
    assert result.state is LifecycleState.FAILED
    assert repo.scan_state(result.execution_id) is LifecycleState.FAILED
    repo.close()


def test_pre_cancelled_execution_never_enters_provider(tmp_path) -> None:
    repo, orchestrator, campaign = make_orchestrator(tmp_path)
    event = Event()
    event.set()
    result = orchestrator.run(campaign, CancelAwareProvider(), event)
    assert result.state is LifecycleState.CANCELLED
    assert repo.scan_state(result.execution_id) is LifecycleState.CANCELLED
    repo.close()


def test_terminal_scan_cannot_transition_again(tmp_path) -> None:
    repo, orchestrator, campaign = make_orchestrator(tmp_path)
    result = orchestrator.run(campaign, SuccessfulProvider())
    with pytest.raises(ValueError, match="invalid lifecycle transition"):
        repo.update_scan_state(result.execution_id, LifecycleState.FAILED)
    repo.close()
