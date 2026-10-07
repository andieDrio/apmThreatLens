"""Pre-execution scope and safety validation."""

from __future__ import annotations

from dataclasses import dataclass

from threatlens.domain.models import Campaign


@dataclass(frozen=True, slots=True)
class ExecutionPolicy:
    safe_mode: bool = True
    max_concurrency: int = 4
    requests_per_second: float = 5.0
    timeout_seconds: float = 30.0
    cancellation_grace_seconds: float = 0.25
    heartbeat_interval_seconds: float = 5.0
    stale_after_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        if self.requests_per_second <= 0:
            raise ValueError("requests_per_second must be positive")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.cancellation_grace_seconds < 0:
            raise ValueError("cancellation_grace_seconds cannot be negative")
        if self.heartbeat_interval_seconds <= 0:
            raise ValueError("heartbeat_interval_seconds must be positive")
        if self.stale_after_seconds <= self.heartbeat_interval_seconds:
            raise ValueError("stale_after_seconds must exceed heartbeat_interval_seconds")


def validate_campaign_execution(campaign: Campaign, policy: ExecutionPolicy) -> None:
    """Fail closed before an execution path can reach a provider."""
    if not campaign.authorized:
        raise PermissionError("campaign authorization is required")
    if not campaign.scope.include:
        raise ValueError("campaign scope must include at least one target")
    if policy.max_concurrency < 1 or policy.requests_per_second <= 0:
        raise ValueError("invalid execution safety policy")
