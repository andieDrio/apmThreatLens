"""Synchronous campaign/scan orchestration with fail-closed lifecycle handling."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Event
from typing import Callable, Protocol
from uuid import UUID

from threatlens.auth import AuthenticationService, AuthenticatedPrincipal, Permission
from threatlens.domain.models import AuditEvent, Campaign, LifecycleState, Scan
from threatlens.providers.runtime import (
    ExecutionRuntime,
    ProviderEvent,
    ProviderRegistry,
)
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

    def scan_state(self, execution_id: UUID) -> LifecycleState: ...


@dataclass(slots=True)
class ScanOrchestrator:
    repository: ScanRepository
    policy: ExecutionPolicy
    authentication: AuthenticationService

    def queue(self, campaign: Campaign, provider: ScanExecutor, principal: AuthenticatedPrincipal | None = None) -> Scan:
        """Create a persisted queued execution after authorization/scope validation."""
        validate_campaign_execution(campaign, self.policy)
        self.authentication.authorize(principal, Permission.ASSESS)
        if not provider.name.strip():
            raise ValueError("provider.name cannot be blank")
        scan = Scan(campaign_id=campaign.id, provider_name=provider.name)
        self.repository.save_scan(scan)
        self.repository.save_audit_event(AuditEvent(actor_user_id=principal.user_id, action="SCAN_QUEUED", resource_type="SCAN", resource_id=scan.execution_id, outcome="SUCCESS", detail=f"provider={provider.name}"))
        return scan

    def cancel(self, execution_id: UUID) -> None:
        """Cancel only a queued or running execution; terminal scans cannot be altered."""
        self.repository.update_scan_state(execution_id, LifecycleState.CANCELLED)

    def run_registered(
        self,
        campaign: Campaign,
        provider_name: str,
        registry: ProviderRegistry,
        cancel_event: Event | None = None,
        observer: Callable[[ProviderEvent], None] | None = None,
        principal: AuthenticatedPrincipal | None = None,
    ) -> Scan:
        """Execute a provider selected from the explicit application registry."""
        validate_campaign_execution(campaign, self.policy)
        metadata, provider = registry.get(provider_name)
        event = cancel_event or Event()
        scan = self.queue(campaign, provider, principal)

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
        result = ExecutionRuntime(self.policy).execute(
            campaign,
            scan.execution_id,
            metadata,
            provider,
            event,
            observer,
        )

        if result.cancelled:
            final_state = LifecycleState.CANCELLED
            error = result.error
        elif result.success:
            final_state = LifecycleState.COMPLETED
            error = None
        else:
            final_state = LifecycleState.FAILED
            error = result.error or "provider execution failed"
        self.repository.update_scan_state(scan.execution_id, final_state, error=error)

        return Scan(
            campaign_id=scan.campaign_id,
            provider_name=scan.provider_name,
            execution_id=scan.execution_id,
            state=self.repository.scan_state(scan.execution_id),
            queued_at=scan.queued_at,
        )

    def run(
        self,
        campaign: Campaign,
        provider: ScanExecutor,
        cancel_event: Event | None = None,
        principal: AuthenticatedPrincipal | None = None,
    ) -> Scan:
        """Run one provider execution while storage remains authoritative for lifecycle state."""
        validate_campaign_execution(campaign, self.policy)
        event = cancel_event or Event()
        scan = self.queue(campaign, provider, principal)

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
            state=self.repository.scan_state(scan.execution_id),
            queued_at=scan.queued_at,
        )
