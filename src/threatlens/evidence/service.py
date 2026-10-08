"""Application service for authenticated evidence-validation lifecycle control."""

from __future__ import annotations

from uuid import UUID

from threatlens.domain.models import AuditEvent
from threatlens.evidence.validation import EvidenceValidation, EvidenceValidationState


class EvidenceValidationService:
    """Apply authenticated validation decisions through the repository boundary."""

    def __init__(self, repository) -> None:
        self.repository = repository

    def create(
        self,
        *,
        evidence_id: UUID,
        state: EvidenceValidationState,
        validator: str,
        rationale: str,
        supporting_evidence_ids: tuple[UUID, ...],
    ) -> EvidenceValidation:
        validation = EvidenceValidation(
            evidence_id=evidence_id,
            state=state,
            validator=validator,
            rationale=rationale,
            supporting_evidence_ids=supporting_evidence_ids,
        )
        event = AuditEvent(
            actor_user_id=self.repository.user_id_for_validator(validator),
            action="EVIDENCE_VALIDATION_CREATED",
            resource_type="EVIDENCE_VALIDATION",
            resource_id=validation.id,
            outcome="SUCCESS",
            detail=f"evidence_id={evidence_id} state={state.value}",
        )
        self.repository.save_evidence_validation(validation, audit_event=event)
        return validation

    def transition(
        self,
        *,
        previous_id: UUID,
        evidence_id: UUID,
        state: EvidenceValidationState,
        validator: str,
        rationale: str,
        supporting_evidence_ids: tuple[UUID, ...],
    ) -> EvidenceValidation:
        if state is EvidenceValidationState.SUPERSEDED:
            raise ValueError("use supersede for SUPERSEDED lifecycle state")
        replacement = EvidenceValidation(
            evidence_id=evidence_id,
            state=state,
            validator=validator,
            rationale=rationale,
            supporting_evidence_ids=supporting_evidence_ids,
        )
        event = AuditEvent(
            actor_user_id=self.repository.user_id_for_validator(validator),
            action="EVIDENCE_VALIDATION_TRANSITIONED",
            resource_type="EVIDENCE_VALIDATION",
            resource_id=replacement.id,
            outcome="SUCCESS",
            detail=f"previous_id={previous_id} evidence_id={evidence_id} state={state.value}",
        )
        self.repository.transition_evidence_validation(
            previous_id, replacement, audit_event=event
        )
        return replacement

    def supersede(
        self,
        *,
        previous_id: UUID,
        evidence_id: UUID,
        validator: str,
        rationale: str,
        supporting_evidence_ids: tuple[UUID, ...],
    ) -> EvidenceValidation:
        replacement = EvidenceValidation(
            evidence_id=evidence_id,
            state=EvidenceValidationState.SUPERSEDED,
            validator=validator,
            rationale=rationale,
            supporting_evidence_ids=supporting_evidence_ids,
        )
        event = AuditEvent(
            actor_user_id=self.repository.user_id_for_validator(validator),
            action="EVIDENCE_VALIDATION_SUPERSEDED",
            resource_type="EVIDENCE_VALIDATION",
            resource_id=replacement.id,
            outcome="SUCCESS",
            detail=f"previous_id={previous_id} evidence_id={evidence_id}",
        )
        self.repository.supersede_evidence_validation(
            previous_id, replacement, audit_event=event
        )
        return replacement
