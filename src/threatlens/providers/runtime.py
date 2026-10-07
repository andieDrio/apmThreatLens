"""Provider registration, execution context, events, and runtime telemetry."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from threading import BoundedSemaphore, Event, Lock, Semaphore, Thread
from time import monotonic
from typing import Protocol
from collections.abc import Callable
from uuid import UUID

from threatlens.domain.models import Campaign
from threatlens.safety.policy import ExecutionPolicy


class ProviderCapability(StrEnum):
    DISCOVERY = "DISCOVERY"
    NETWORK = "NETWORK"
    WEB = "WEB"
    API = "API"
    TLS = "TLS"
    CONFIGURATION = "CONFIGURATION"
    VULNERABILITY = "VULNERABILITY"
    THREAT_INTEL = "THREAT_INTEL"
    EVIDENCE = "EVIDENCE"


class ProviderEventType(StrEnum):
    STARTED = "STARTED"
    PROGRESS = "PROGRESS"
    EVIDENCE = "EVIDENCE"
    FINDING = "FINDING"
    WARNING = "WARNING"
    ERROR = "ERROR"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class ProviderExecutor(Protocol):
    name: str

    def execute(self, campaign: Campaign, execution_id: UUID, cancel_event: Event) -> None:
        """Execute within the authorized scope and honor cancellation."""


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    name: str
    version: str
    capabilities: frozenset[ProviderCapability]
    safe_by_default: bool = True

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("provider metadata name cannot be blank")
        if not self.version.strip():
            raise ValueError("provider metadata version cannot be blank")
        if not self.capabilities:
            raise ValueError("provider metadata must declare at least one capability")


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    campaign_id: UUID
    execution_id: UUID
    provider: ProviderMetadata
    policy: ExecutionPolicy
    cancel_event: Event = field(default_factory=Event)


@dataclass(frozen=True, slots=True)
class ProviderEvent:
    execution_id: UUID
    provider_name: str
    event_type: ProviderEventType
    timestamp_monotonic: float
    message: str = ""
    attributes: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class ExecutionMetrics:
    duration_seconds: float
    event_count: int
    evidence_count: int
    finding_count: int


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    success: bool
    cancelled: bool
    timed_out: bool
    worker_still_running: bool
    error: str | None
    metrics: ExecutionMetrics
    events: tuple[ProviderEvent, ...]


class ProviderRegistry:
    """Explicit allowlist of providers available to the application."""

    def __init__(self) -> None:
        self._providers: dict[str, tuple[ProviderMetadata, ProviderExecutor]] = {}

    def register(self, metadata: ProviderMetadata, executor: ProviderExecutor) -> None:
        if executor.name != metadata.name:
            raise ValueError("provider executor name must match metadata name")
        if metadata.name in self._providers:
            raise ValueError(f"provider already registered: {metadata.name}")
        self._providers[metadata.name] = (metadata, executor)

    def get(self, name: str) -> tuple[ProviderMetadata, ProviderExecutor]:
        try:
            return self._providers[name]
        except KeyError as exc:
            raise KeyError(f"provider not registered: {name}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._providers))


class ExecutionRuntime:
    """Runs one provider with cooperative timeout/cancellation and structured telemetry."""

    def __init__(self, policy: ExecutionPolicy, concurrency_gate: Semaphore | None = None) -> None:
        self.policy = policy
        self._concurrency_gate = concurrency_gate or BoundedSemaphore(policy.max_concurrency)

    def execute(
        self,
        campaign: Campaign,
        execution_id: UUID,
        metadata: ProviderMetadata,
        executor: ProviderExecutor,
        cancel_event: Event,
        observer: Callable[[ProviderEvent], None] | None = None,
        heartbeat: Callable[[], None] | None = None,
    ) -> ExecutionResult:
        context = ExecutionContext(campaign.id, execution_id, metadata, self.policy, cancel_event)
        events: list[ProviderEvent] = []
        events_lock = Lock()
        started = monotonic()
        done = Event()
        heartbeat_stop = Event()
        provider_error: list[str] = []
        heartbeat_error: list[str] = []

        def emit(event_type: ProviderEventType, message: str = "", **attributes: str) -> None:
            event = ProviderEvent(
                execution_id=context.execution_id,
                provider_name=context.provider.name,
                event_type=event_type,
                timestamp_monotonic=monotonic(),
                message=message,
                attributes=tuple(sorted((str(k), str(v)) for k, v in attributes.items())),
            )
            with events_lock:
                events.append(event)
            if observer is not None:
                observer(event)

        acquired = False
        while not acquired:
            acquired = self._concurrency_gate.acquire(timeout=0.05)
            if not acquired and cancel_event.is_set():
                emit(
                    ProviderEventType.CANCELLED,
                    "provider cancellation requested before execution slot was available",
                )
                return ExecutionResult(
                    success=False,
                    cancelled=True,
                    timed_out=False,
                    worker_still_running=False,
                    error=None,
                    metrics=ExecutionMetrics(monotonic() - started, len(events), 0, 0),
                    events=tuple(events),
                )

        def heartbeat_loop() -> None:
            while not heartbeat_stop.wait(self.policy.heartbeat_interval_seconds):
                if heartbeat is None:
                    continue
                try:
                    heartbeat()
                except Exception as exc:
                    heartbeat_error.append(f"{type(exc).__name__}: {exc}")
                    emit(
                        ProviderEventType.WARNING,
                        "execution heartbeat update failed",
                        error=heartbeat_error[-1],
                    )
                    heartbeat_stop.set()

        def invoke() -> None:
            try:
                executor.execute(campaign, execution_id, cancel_event)
            except Exception as exc:
                provider_error.append(f"{type(exc).__name__}: {exc}")
            finally:
                done.set()
                self._concurrency_gate.release()

        emit(ProviderEventType.STARTED, version=metadata.version)
        worker = Thread(target=invoke, name=f"threatlens-provider-{execution_id}", daemon=True)
        heartbeat_worker = Thread(
            target=heartbeat_loop, name=f"threatlens-heartbeat-{execution_id}", daemon=True
        )
        try:
            worker.start()
            heartbeat_worker.start()
        except BaseException:
            self._concurrency_gate.release()
            raise
        completed_in_time = done.wait(self.policy.timeout_seconds)
        timed_out = not completed_in_time
        error: str | None = provider_error[0] if provider_error else None

        if timed_out:
            cancel_event.set()
            heartbeat_stop.set()
            worker.join(self.policy.cancellation_grace_seconds)
            heartbeat_worker.join(0.1)
            error = f"TimeoutError: provider exceeded {self.policy.timeout_seconds:.3f}s execution budget"
            if worker.is_alive():
                error += "; provider worker did not stop within cancellation grace period"
            emit(ProviderEventType.ERROR, error)
        elif error is not None:
            emit(ProviderEventType.ERROR, error)
        elif cancel_event.is_set():
            emit(ProviderEventType.CANCELLED, "provider cancellation requested")
        else:
            emit(ProviderEventType.COMPLETED)

        duration = monotonic() - started
        with events_lock:
            event_snapshot = tuple(events)
        evidence_count = sum(e.event_type is ProviderEventType.EVIDENCE for e in event_snapshot)
        finding_count = sum(e.event_type is ProviderEventType.FINDING for e in event_snapshot)
        return ExecutionResult(
            success=not timed_out and error is None and not cancel_event.is_set(),
            cancelled=cancel_event.is_set() and not timed_out,
            timed_out=timed_out,
            worker_still_running=worker.is_alive(),
            error=error,
            metrics=ExecutionMetrics(duration, len(event_snapshot), evidence_count, finding_count),
            events=event_snapshot,
        )
