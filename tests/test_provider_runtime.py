from threading import Event, Lock, Thread
from time import sleep
from uuid import uuid4

import pytest

from threatlens.domain.models import Campaign, Scope
from threatlens.providers.runtime import (
    ExecutionRuntime,
    ProviderCapability,
    ProviderEventType,
    ProviderMetadata,
    ProviderRegistry,
)
from threatlens.safety.policy import ExecutionPolicy


class ObservableProvider:
    name = "observable"

    def execute(self, campaign, execution_id, cancel_event) -> None:
        assert campaign.authorized


class FailingProvider:
    name = "failing"

    def execute(self, campaign, execution_id, cancel_event) -> None:
        raise RuntimeError("boom")


class SlowProvider:
    name = "slow"

    def execute(self, campaign, execution_id, cancel_event) -> None:
        while not cancel_event.is_set():
            sleep(0.005)


def campaign() -> Campaign:
    return Campaign(
        name="runtime-test",
        scope=Scope(include=("198.51.100.10",)),
        authorized=True,
    )


def metadata(name: str) -> ProviderMetadata:
    return ProviderMetadata(
        name=name,
        version="1.0.0",
        capabilities=frozenset({ProviderCapability.NETWORK}),
    )


def test_registry_enforces_identity_and_duplicate_registration() -> None:
    registry = ProviderRegistry()
    registry.register(metadata("observable"), ObservableProvider())
    assert registry.names() == ("observable",)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(metadata("observable"), ObservableProvider())


def test_registry_rejects_metadata_executor_name_mismatch() -> None:
    registry = ProviderRegistry()
    with pytest.raises(ValueError, match="must match"):
        registry.register(metadata("observable"), FailingProvider())


def test_runtime_emits_start_and_complete_events() -> None:
    runtime = ExecutionRuntime(ExecutionPolicy())
    provider = ObservableProvider()
    result = runtime.execute(campaign(), uuid4(), metadata(provider.name), provider, Event())
    assert result.success
    assert not result.cancelled
    assert not result.timed_out
    assert [event.event_type for event in result.events] == [
        ProviderEventType.STARTED,
        ProviderEventType.COMPLETED,
    ]
    assert result.metrics.event_count == 2
    assert result.metrics.duration_seconds >= 0


def test_runtime_converts_provider_failure_to_structured_error() -> None:
    runtime = ExecutionRuntime(ExecutionPolicy())
    provider = FailingProvider()
    result = runtime.execute(campaign(), uuid4(), metadata(provider.name), provider, Event())
    assert not result.success
    assert result.error == "RuntimeError: boom"
    assert not result.timed_out
    assert result.events[-1].event_type is ProviderEventType.ERROR


def test_runtime_cancels_cooperatively_on_timeout() -> None:
    runtime = ExecutionRuntime(ExecutionPolicy(timeout_seconds=0.01))
    provider = SlowProvider()
    cancel_event = Event()
    result = runtime.execute(campaign(), uuid4(), metadata(provider.name), provider, cancel_event)
    assert result.timed_out
    assert not result.success
    assert cancel_event.is_set()
    assert result.error == "TimeoutError: provider exceeded 0.010s execution budget"
    assert result.events[-1].event_type is ProviderEventType.ERROR


class StubbornProvider:
    name = "stubborn"

    def execute(self, campaign, execution_id, cancel_event) -> None:
        sleep(0.15)


def test_runtime_marks_non_cooperative_timeout_worker(tmp_path) -> None:
    runtime = ExecutionRuntime(
        ExecutionPolicy(timeout_seconds=0.01, cancellation_grace_seconds=0.001)
    )
    provider = StubbornProvider()
    result = runtime.execute(campaign(), uuid4(), metadata(provider.name), provider, Event())
    assert result.timed_out
    assert result.worker_still_running
    assert "cancellation grace period" in result.error
    sleep(0.2)


class ConcurrencyTrackingProvider:
    name = "concurrency-tracker"

    def __init__(self) -> None:
        self.active = 0
        self.max_active = 0
        self.lock = Lock()

    def execute(self, campaign, execution_id, cancel_event) -> None:
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
        try:
            sleep(0.03)
        finally:
            with self.lock:
                self.active -= 1


def test_runtime_enforces_max_concurrency_across_parallel_executions() -> None:
    runtime = ExecutionRuntime(ExecutionPolicy(max_concurrency=1, timeout_seconds=1.0))
    provider = ConcurrencyTrackingProvider()
    results = []

    def run_once() -> None:
        results.append(
            runtime.execute(campaign(), uuid4(), metadata(provider.name), provider, Event())
        )

    first = Thread(target=run_once)
    second = Thread(target=run_once)
    first.start()
    second.start()
    first.join()
    second.join()

    assert provider.max_active == 1
    assert len(results) == 2
    assert all(result.success for result in results)


def test_runtime_stops_heartbeat_after_non_cooperative_timeout() -> None:
    heartbeat_calls = 0
    lock = Lock()

    def heartbeat() -> None:
        nonlocal heartbeat_calls
        with lock:
            heartbeat_calls += 1

    runtime = ExecutionRuntime(
        ExecutionPolicy(
            timeout_seconds=0.01,
            cancellation_grace_seconds=0.001,
            heartbeat_interval_seconds=0.01,
            stale_after_seconds=0.1,
        )
    )
    result = runtime.execute(
        campaign(), uuid4(), metadata("stubborn"), StubbornProvider(), Event(), heartbeat=heartbeat
    )
    assert result.timed_out
    calls_at_return = heartbeat_calls
    sleep(0.05)
    assert heartbeat_calls == calls_at_return
