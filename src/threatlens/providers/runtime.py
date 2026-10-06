"""Provider registration, execution context, events, and runtime telemetry."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from threading import Event, Thread
from time import monotonic
from typing import Callable, Protocol
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

    def __init__(self, policy: ExecutionPolicy) -> None:
        self.policy = policy

    def execute(
        self,
        campaign: Campaign,
        execution_id: UUID,
        metadata: ProviderMetadata,
        executor: ProviderExecutor,
        cancel_event: Event,
        observer: Callable[[ProviderEvent], None] | None = None,
    ) -> ExecutionResult:
        context = ExecutionContext(campaign.id, execution_id, metadata, self.policy, cancel_event)
        events: list[ProviderEvent] = []
        started = monotonic()
        done = Event()
        provider_error: list[str] = []

        def emit(event_type: ProviderEventType, message: str = "", **attributes: str) -> None:
            event = ProviderEvent(
                execution_id=context.execution_id,
                provider_name=context.provider.name,
                event_type=event_type,
                timestamp_monotonic=monotonic(),
                message=message,
                attributes=tuple(sorted((str(k), str(v)) for k, v in attributes.items())),
            )
            events.append(event)
            if observer is not None:
                observer(event)

        def invoke() -> None:
            try:
                executor.execute(campaign, execution_id, cancel_event)
            except Exception as exc:
                provider_error.append(f"{type(exc).__name__}: {exc}")
            finally:
                done.set()

        emit(ProviderEventType.STARTED, version=metadata.version)
        worker = Thread(target=invoke, name=f"threatlens-provider-{execution_id}", daemon=True)
        worker.start()
        completed_in_time = done.wait(self.policy.timeout_seconds)
        timed_out = not completed_in_time
        error: str | None = provider_error[0] if provider_error else None

        if timed_out:
            cancel_event.set()
            error = f"TimeoutError: provider exceeded {self.policy.timeout_seconds:.3f}s execution budget"
            emit(ProviderEventType.ERROR, error)
        elif error is not None:
            emit(ProviderEventType.ERROR, error)
        elif cancel_event.is_set():
            emit(ProviderEventType.CANCELLED, "provider cancellation requested")
        else:
            emit(ProviderEventType.COMPLETED)

        duration = monotonic() - started
        evidence_count = sum(e.event_type is ProviderEventType.EVIDENCE for e in events)
        finding_count = sum(e.event_type is ProviderEventType.FINDING for e in events)
        return ExecutionResult(
            success=not timed_out and error is None and not cancel_event.is_set(),
            cancelled=cancel_event.is_set() and not timed_out,
            timed_out=timed_out,
            error=error,
            metrics=ExecutionMetrics(duration, len(events), evidence_count, finding_count),
            events=tuple(events),
        )
