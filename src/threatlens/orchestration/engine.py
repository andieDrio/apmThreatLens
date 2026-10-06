"""Synchronous campaign/scan orchestration with fail-closed lifecycle handling."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Event
from typing import Protocol
from uuid import UUID

from threatlens.domain.models import Campaign, LifecycleState, Scan
from threatlens.safety.policy import ExecutionPolicy, validate_campaign_execution


class ScanExecutor(Protocol):
    """Provider-facing execution boundary; implementations must honor cancellation."""

    name: str

    def execute(self, campaign: Campaign, execution_id: UUID, cancel_event: Event) -> None:
        """Execute an already-authorized scan without changing persisted lifecycle state."""


class ScanRepository(Protocol):
    def save_scan(self, scan: Scan) -> None: ...

    def update_scan_state(
        self, execution_id: UUID, target: LifecycleState, error: str | None = None
    ) -> None: ...


@dataclass(slots=True)
class ScanOrchestrator:
    repository: ScanRepository
    policy: ExecutionPolicy

    def queue(self, campaign: Campaign, provider: ScanExecutor) -> Scan:
        """Create a persisted queued execution after authorization/scope validation."""
        validate_campaign_execution(campaign, self.policy)
        if not provider.name.strip():
            raise ValueError("provider.name cannot be blank")
        scan = Scan(campaign_id=campaign.id, provider_name=provider.name)
        self.repository.save_scan(scan)
        return scan

    def cancel(self, execution_id: UUID) -> None:
        """Cancel only a queued or running execution; terminal scans cannot be altered."""
        self.repository.update_scan_state(execution_id, LifecycleState.CANCELLED)

    def run(self, campaign: Campaign, provider: ScanExecutor, cancel_event: Event | None = None) -> Scan:
        """Run one provider execution while keeping lifecycle state authoritative in storage."""
        validate_campaign_execution(campaign, self.policy)
        event = cancel_event or Event()
        scan = self.queue(campaign, provider)

        if event.is_set():
            self.repository.update_scan_state(scan.execution_id, LifecycleState.CANCELLED)
            return Scan(
                campaign_id=scan.campaign_id,
                provider_name=scan.provider_name,
                execution_id=scan.execution_id,
                state=LifecycleState.CANCELLED,
                queued_at=scan.queued_at,
                finished_at=scan.queued_at,
            )

        self.repository.update_scan_state(scan.execution_id, LifecycleState.RUNNING)
        try:
            provider.execute(campaign, scan.execution_id, event)
            final_state = LifecycleState.CANCELLED if event.is_set() else LifecycleState.COMPLETED
            self.repository.update_scan_state(scan.execution_id, final_state)
        except Exception as exc:
            self.repository.update_scan_state(
                scan.execution_id,
                LifecycleState.FAILED,
                error=f"{type(exc).__name__}: {exc}",
            )

        return Scan(
            campaign_id=scan.campaign_id,
            provider_name=scan.provider_name,
            execution_id=scan.execution_id,
            state=self.repository_state(scan.execution_id),
            queued_at=scan.queued_at,
        )

    def repository_state(self, execution_id: UUID) -> LifecycleState:
        getter = getattr(self.repository, "scan_state", None)
        if getter is None:
            raise RuntimeError("repository must expose scan_state for authoritative lifecycle reads")
        return getter(execution_id)
