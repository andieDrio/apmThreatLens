"""Immutable domain models used across provider and orchestration boundaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Mapping, Tuple
from uuid import UUID, uuid4


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class LifecycleState(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    PARTIAL = "PARTIAL"


_ALLOWED_LIFECYCLE_TRANSITIONS: dict[LifecycleState, frozenset[LifecycleState]] = {
    LifecycleState.QUEUED: frozenset({LifecycleState.RUNNING, LifecycleState.CANCELLED}),
    LifecycleState.RUNNING: frozenset(
        {
            LifecycleState.COMPLETED,
            LifecycleState.FAILED,
            LifecycleState.CANCELLED,
            LifecycleState.PARTIAL,
        }
    ),
    LifecycleState.COMPLETED: frozenset(),
    LifecycleState.FAILED: frozenset(),
    LifecycleState.CANCELLED: frozenset(),
    LifecycleState.PARTIAL: frozenset(),
}


def validate_lifecycle_transition(current: LifecycleState, target: LifecycleState) -> None:
    """Fail closed when a scan attempts an invalid lifecycle transition."""
    if target not in _ALLOWED_LIFECYCLE_TRANSITIONS[current]:
        raise ValueError(f"invalid lifecycle transition: {current.value} -> {target.value}")


class FindingState(StrEnum):
    CONFIRMED = "CONFIRMED"
    LIKELY = "LIKELY"
    SUSPECTED = "SUSPECTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    MITIGATED = "MITIGATED"
    NOT_REPRODUCIBLE = "NOT_REPRODUCIBLE"
    INFORMATIONAL = "INFORMATIONAL"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass(frozen=True, slots=True)
class Scope:
    include: Tuple[str, ...]
    exclude: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.include:
            raise ValueError("scope.include must contain at least one target")
        if any(not value.strip() for value in self.include):
            raise ValueError("scope.include cannot contain blank targets")
        if any(not value.strip() for value in self.exclude):
            raise ValueError("scope.exclude cannot contain blank targets")


@dataclass(frozen=True, slots=True)
class Campaign:
    name: str
    scope: Scope
    authorized: bool
    id: UUID = field(default_factory=uuid4)
    state: LifecycleState = LifecycleState.QUEUED
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("campaign.name cannot be blank")
        if not self.authorized:
            raise ValueError("campaign must be explicitly authorized")


@dataclass(frozen=True, slots=True)
class Scan:
    campaign_id: UUID
    provider_name: str
    execution_id: UUID = field(default_factory=uuid4)
    state: LifecycleState = LifecycleState.QUEUED
    queued_at: datetime = field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        if not self.provider_name.strip():
            raise ValueError("scan.provider_name cannot be blank")
        if self.state is LifecycleState.QUEUED and self.started_at is not None:
            raise ValueError("queued scan cannot have started_at")


@dataclass(frozen=True, slots=True)
class Asset:
    canonical_id: str
    asset_type: str
    value: str
    id: UUID = field(default_factory=uuid4)
    first_seen_at: datetime = field(default_factory=utc_now)
    last_seen_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        for field_name in ("canonical_id", "asset_type", "value"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"asset.{field_name} cannot be blank")


@dataclass(frozen=True, slots=True)
class Service:
    asset_id: UUID
    protocol: str
    port: int
    service_name: str | None = None
    version: str | None = None
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.protocol.strip():
            raise ValueError("service.protocol cannot be blank")
        if not 1 <= self.port <= 65535:
            raise ValueError("service.port must be within 1..65535")


@dataclass(frozen=True, slots=True)
class Evidence:
    kind: str
    content: str
    source: str
    captured_at: datetime = field(default_factory=utc_now)
    sha256: str | None = None
    metadata: Mapping[str, str] = field(default_factory=dict)
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        for field_name in ("kind", "source"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"evidence.{field_name} cannot be blank")
        if not self.content:
            raise ValueError("evidence.content cannot be empty")


@dataclass(frozen=True, slots=True)
class Finding:
    title: str
    asset_id: UUID
    evidence_ids: Tuple[UUID, ...]
    state: FindingState = FindingState.SUSPECTED
    severity: Severity = Severity.INFORMATIONAL
    vulnerability_id: str | None = None
    cwe: str | None = None
    cve: str | None = None
    cvss: float | None = None
    confidence: float = 0.0
    source: str = ""
    id: UUID = field(default_factory=uuid4)
    detected_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.title.strip():
            raise ValueError("finding.title cannot be blank")
        if not self.evidence_ids:
            raise ValueError("finding must reference at least one evidence item")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("finding.confidence must be between 0 and 1")
        if self.cvss is not None and not 0.0 <= self.cvss <= 10.0:
            raise ValueError("finding.cvss must be between 0 and 10")


@dataclass(frozen=True, slots=True)
class User:
    username: str
    password_hash: str
    role: str
    active: bool = True
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        if not self.username.strip():
            raise ValueError("user.username cannot be blank")
        if not self.password_hash.strip():
            raise ValueError("user.password_hash cannot be blank")
        if not self.role.strip():
            raise ValueError("user.role cannot be blank")


@dataclass(frozen=True, slots=True)
class AuditEvent:
    action: str
    resource_type: str
    outcome: str
    detail: str
    actor_user_id: UUID | None = None
    resource_id: UUID | None = None
    id: UUID = field(default_factory=uuid4)
    created_at: datetime = field(default_factory=utc_now)

    def __post_init__(self) -> None:
        for field_name in ("action", "resource_type", "outcome", "detail"):
            if not getattr(self, field_name).strip():
                raise ValueError(f"audit_event.{field_name} cannot be blank")
