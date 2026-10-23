"""Synchronous campaign/scan orchestration with fail-closed lifecycle handling."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from hashlib import sha256
from threading import BoundedSemaphore, Event, Thread
from typing import Protocol
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
    def save_scan_with_audit(self, scan: Scan, event: AuditEvent) -> None: ...
    def save_scan_with_audit_idempotent(
        self, scan: Scan, event: AuditEvent, actor_user_id: UUID,
        idempotency_key: str, request_hash: str,
    ) -> tuple[Scan, bool]: ...

    def update_scan_state(
        self, execution_id: UUID, target: LifecycleState, error: str | None = None
    ) -> None: ...

    def scan_state(self, execution_id: UUID) -> LifecycleState: ...

    def update_scan_state_if_current(
        self,
        execution_id: UUID,
        expected: LifecycleState,
        target: LifecycleState,
        error: str | None = None,
    ) -> bool: ...

    def update_scan_state_if_current_with_audit(
        self,
        execution_id: UUID,
        expected: LifecycleState,
        target: LifecycleState,
        event: AuditEvent,
        error: str | None = None,
    ) -> bool: ...

    def heartbeat_scan(self, execution_id: UUID) -> bool: ...
    def recover_stale_scan(
        self, execution_id: UUID, stale_after_seconds: float, event: AuditEvent
    ) -> bool: ...

    def cancel_scan(self, execution_id: UUID) -> bool: ...

    def cancel_scan_with_audit(
        self, execution_id: UUID, success_event: AuditEvent, noop_event: AuditEvent
    ) -> bool: ...

    def execute_scan_lifecycle_command(
        self, execution_id: UUID, action: str, actor_user_id: UUID,
        idempotency_key: str, request_hash: str, stale_after_seconds: float,
        success_event: AuditEvent, noop_event: AuditEvent,
    ) -> tuple[bool, bool]: ...


@dataclass(slots=True)
class ScanOrchestrator:
    repository: ScanRepository
    policy: ExecutionPolicy
    authentication: AuthenticationService
    runtime: ExecutionRuntime = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.runtime = ExecutionRuntime(
            self.policy,
            concurrency_gate=BoundedSemaphore(self.policy.max_concurrency),
        )

    def queue(
        self,
        campaign: Campaign,
        provider: ScanExecutor,
        principal: AuthenticatedPrincipal | None = None,
    ) -> Scan:
        """Create a persisted queued execution after authorization/scope validation."""
        validate_campaign_execution(campaign, self.policy)
        self.authentication.authorize(principal, Permission.ASSESS)
        if not provider.name.strip():
            raise ValueError("provider.name cannot be blank")
        scan = Scan(campaign_id=campaign.id, provider_name=provider.name)
        self.repository.save_scan_with_audit(
            scan,
            AuditEvent(
                actor_user_id=principal.user_id,
                action="SCAN_QUEUED",
                resource_type="SCAN",
                resource_id=scan.execution_id,
                outcome="SUCCESS",
                detail=f"provider={provider.name}",
            ),
        )
        return scan

    def queue_idempotent(
        self,
        campaign: Campaign,
        provider: ScanExecutor,
        idempotency_key: str,
        principal: AuthenticatedPrincipal | None = None,
    ) -> tuple[Scan, bool]:
        """Queue once per authenticated principal and idempotency key across instances."""
        validate_campaign_execution(campaign, self.policy)
        self.authentication.authorize(principal, Permission.ASSESS)
        if not provider.name.strip():
            raise ValueError("provider.name cannot be blank")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", idempotency_key):
            raise ValueError("idempotency key must be 16..128 safe ASCII characters")
        request_hash = sha256(
            f"{campaign.id}\n{provider.name}".encode()
        ).hexdigest()
        scan = Scan(campaign_id=campaign.id, provider_name=provider.name)
        event = AuditEvent(
            actor_user_id=principal.user_id,
            action="SCAN_QUEUED",
            resource_type="SCAN",
            resource_id=scan.execution_id,
            outcome="SUCCESS",
            detail=f"provider={provider.name}",
        )
        return self.repository.save_scan_with_audit_idempotent(
            scan, event, principal.user_id, idempotency_key, request_hash
        )

    def recover_stale(
        self, execution_id: UUID, principal: AuthenticatedPrincipal | None = None
    ) -> bool:
        self.authentication.authorize(principal, Permission.ASSESS)
        return self.repository.recover_stale_scan(
            execution_id,
            self.policy.stale_after_seconds,
            AuditEvent(
                actor_user_id=principal.user_id,
                action="SCAN_RECOVERED_STALE",
                resource_type="SCAN",
                resource_id=execution_id,
                outcome="SUCCESS",
                detail="execution heartbeat lease expired",
            ),
        )

    def cancel(self, execution_id: UUID, principal: AuthenticatedPrincipal | None = None) -> bool:
        """Cancel only a queued or running execution after authenticated authorization."""
        self.authentication.authorize(principal, Permission.ASSESS)
        return self.repository.cancel_scan_with_audit(
            execution_id,
            AuditEvent(
                actor_user_id=principal.user_id,
                action="SCAN_CANCELLED",
                resource_type="SCAN",
                resource_id=execution_id,
                outcome="SUCCESS",
                detail="scan cancellation requested",
            ),
            AuditEvent(
                actor_user_id=principal.user_id,
                action="SCAN_CANCELLED",
                resource_type="SCAN",
                resource_id=execution_id,
                outcome="NOOP",
                detail="scan already terminal",
            ),
        )

    def recover_stale_idempotent(
        self, execution_id: UUID, idempotency_key: str,
        principal: AuthenticatedPrincipal | None = None,
    ) -> tuple[bool, bool]:
        """Recover a stale execution once per authenticated idempotency key."""
        self.authentication.authorize(principal, Permission.ASSESS)
        if not re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", idempotency_key):
            raise ValueError("idempotency key must be 16..128 safe ASCII characters")
        request_hash = sha256(
            f"RECOVER_STALE\n{execution_id}\n{self.policy.stale_after_seconds}".encode()
        ).hexdigest()
        return self.repository.execute_scan_lifecycle_command(
            execution_id, "RECOVER_STALE", principal.user_id, idempotency_key,
            request_hash, self.policy.stale_after_seconds,
            AuditEvent(actor_user_id=principal.user_id, action="SCAN_RECOVERED_STALE",
                resource_type="SCAN", resource_id=execution_id, outcome="SUCCESS",
                detail="execution heartbeat lease expired"),
            AuditEvent(actor_user_id=principal.user_id, action="SCAN_RECOVERED_STALE",
                resource_type="SCAN", resource_id=execution_id, outcome="NOOP",
                detail="execution heartbeat lease has not expired"),
        )

    def cancel_idempotent(
        self, execution_id: UUID, idempotency_key: str,
        principal: AuthenticatedPrincipal | None = None,
    ) -> tuple[bool, bool]:
        """Cancel a scan once per authenticated idempotency key."""
        self.authentication.authorize(principal, Permission.ASSESS)
        if not re.fullmatch(r"[A-Za-z0-9._:-]{16,128}", idempotency_key):
            raise ValueError("idempotency key must be 16..128 safe ASCII characters")
        request_hash = sha256(f"CANCEL\n{execution_id}".encode()).hexdigest()
        return self.repository.execute_scan_lifecycle_command(
            execution_id, "CANCEL", principal.user_id, idempotency_key,
            request_hash, self.policy.stale_after_seconds,
            AuditEvent(actor_user_id=principal.user_id, action="SCAN_CANCELLED",
                resource_type="SCAN", resource_id=execution_id, outcome="SUCCESS",
                detail="scan cancellation requested"),
            AuditEvent(actor_user_id=principal.user_id, action="SCAN_CANCELLED",
                resource_type="SCAN", resource_id=execution_id, outcome="NOOP",
                detail="scan already terminal"),
        )

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
            self.repository.cancel_scan_with_audit(
                scan.execution_id,
                AuditEvent(
                    actor_user_id=principal.user_id,
                    action="SCAN_CANCELLED",
                    resource_type="SCAN",
                    resource_id=scan.execution_id,
                    outcome="SUCCESS",
                    detail="pre-start cancellation",
                ),
                AuditEvent(
                    actor_user_id=principal.user_id,
                    action="SCAN_CANCELLED",
                    resource_type="SCAN",
                    resource_id=scan.execution_id,
                    outcome="NOOP",
                    detail="scan already terminal",
                ),
            )
            return Scan(
                campaign_id=scan.campaign_id,
                provider_name=scan.provider_name,
                execution_id=scan.execution_id,
                state=LifecycleState.CANCELLED,
                queued_at=scan.queued_at,
                finished_at=scan.queued_at,
            )

        if not self.repository.update_scan_state_if_current(
            scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING
        ):
            return Scan(
                campaign_id=scan.campaign_id,
                provider_name=scan.provider_name,
                execution_id=scan.execution_id,
                state=self.repository.scan_state(scan.execution_id),
                queued_at=scan.queued_at,
            )
        result = self.runtime.execute(
            campaign,
            scan.execution_id,
            metadata,
            provider,
            event,
            observer,
            heartbeat=lambda: self.repository.heartbeat_scan(scan.execution_id),
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
        if not self.repository.update_scan_state_if_current_with_audit(
            scan.execution_id,
            LifecycleState.RUNNING,
            final_state,
            AuditEvent(
                actor_user_id=principal.user_id,
                action="SCAN_FINALIZED",
                resource_type="SCAN",
                resource_id=scan.execution_id,
                outcome=final_state.value,
                detail=error or "provider execution finalized",
            ),
            error=error,
        ):
            final_state = self.repository.scan_state(scan.execution_id)

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
            self.repository.cancel_scan_with_audit(
                scan.execution_id,
                AuditEvent(
                    actor_user_id=principal.user_id,
                    action="SCAN_CANCELLED",
                    resource_type="SCAN",
                    resource_id=scan.execution_id,
                    outcome="SUCCESS",
                    detail="pre-start cancellation",
                ),
                AuditEvent(
                    actor_user_id=principal.user_id,
                    action="SCAN_CANCELLED",
                    resource_type="SCAN",
                    resource_id=scan.execution_id,
                    outcome="NOOP",
                    detail="scan already terminal",
                ),
            )
            return Scan(
                campaign_id=scan.campaign_id,
                provider_name=scan.provider_name,
                execution_id=scan.execution_id,
                state=LifecycleState.CANCELLED,
                queued_at=scan.queued_at,
                finished_at=scan.queued_at,
            )

        if not self.repository.update_scan_state_if_current(
            scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING
        ):
            return Scan(
                campaign_id=scan.campaign_id,
                provider_name=scan.provider_name,
                execution_id=scan.execution_id,
                state=self.repository.scan_state(scan.execution_id),
                queued_at=scan.queued_at,
            )
        heartbeat_stop = Event()
        heartbeat_error: list[str] = []

        def heartbeat_loop() -> None:
            while not heartbeat_stop.wait(self.policy.heartbeat_interval_seconds):
                try:
                    renewed = self.repository.heartbeat_scan(scan.execution_id)
                    if renewed is False:
                        raise RuntimeError(
                            "heartbeat lease is no longer owned by this execution"
                        )
                except Exception as exc:
                    heartbeat_error.append(f"{type(exc).__name__}: {exc}")
                    event.set()
                    heartbeat_stop.set()
                    return

        heartbeat_thread = Thread(
            target=heartbeat_loop, name=f"threatlens-heartbeat-{scan.execution_id}", daemon=True
        )
        provider_error: str | None = None
        try:
            renewed = self.repository.heartbeat_scan(scan.execution_id)
            if renewed is False:
                raise RuntimeError("initial heartbeat lease could not be established")
            heartbeat_thread.start()
            provider.execute(campaign, scan.execution_id, event)
        except Exception as exc:
            provider_error = f"{type(exc).__name__}: {exc}"
        finally:
            heartbeat_stop.set()
            if heartbeat_thread.ident is not None:
                heartbeat_thread.join(0.1)

        if heartbeat_error:
            error = f"heartbeat lease renewal failed: {heartbeat_error[0]}"
        else:
            error = provider_error

        if error is not None:
            final_state = LifecycleState.FAILED
            detail = error
        else:
            final_state = LifecycleState.CANCELLED if event.is_set() else LifecycleState.COMPLETED
            detail = "provider execution finalized"

        self.repository.update_scan_state_if_current_with_audit(
            scan.execution_id,
            LifecycleState.RUNNING,
            final_state,
            AuditEvent(
                actor_user_id=principal.user_id,
                action="SCAN_FINALIZED",
                resource_type="SCAN",
                resource_id=scan.execution_id,
                outcome=final_state.value,
                detail=detail,
            ),
            error=error,
        )

        return Scan(
            campaign_id=scan.campaign_id,
            provider_name=scan.provider_name,
            execution_id=scan.execution_id,
            state=self.repository.scan_state(scan.execution_id),
            queued_at=scan.queued_at,
        )
