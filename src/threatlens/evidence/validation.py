"""Fail-closed evidence integrity and validation lifecycle contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from datetime import datetime, timezone
from enum import StrEnum
from uuid import UUID, uuid4

from threatlens.domain.models import Evidence


class EvidenceValidationState(StrEnum):
    """Explicit lifecycle for a validation decision about immutable evidence."""

    PENDING = "PENDING"
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    SUPERSEDED = "SUPERSEDED"


_ALLOWED_TRANSITIONS: dict[EvidenceValidationState, frozenset[EvidenceValidationState]] = {
    EvidenceValidationState.PENDING: frozenset({EvidenceValidationState.VALIDATED, EvidenceValidationState.REJECTED}),
    EvidenceValidationState.VALIDATED: frozenset({EvidenceValidationState.SUPERSEDED}),
    EvidenceValidationState.REJECTED: frozenset({EvidenceValidationState.SUPERSEDED}),
    EvidenceValidationState.SUPERSEDED: frozenset(),
}


def validate_evidence_transition(
    current: EvidenceValidationState,
    target: EvidenceValidationState,
) -> None:
    """Reject lifecycle changes that could silently rewrite a validation decision."""
    if target not in _ALLOWED_TRANSITIONS[current]:
        raise ValueError(f"invalid evidence validation transition: {current.value} -> {target.value}")


def validate_evidence_integrity(evidence: Evidence) -> None:
    """Fail closed unless the immutable evidence content matches its sealed digest."""
    if not evidence.sha256:
        raise ValueError("evidence must be sealed before validation")
    digest = sha256(evidence.content.encode("utf-8")).hexdigest()
    if evidence.sha256 != digest:
        raise ValueError("evidence integrity validation failed")


@dataclass(frozen=True, slots=True)
class EvidenceValidation:
    """An auditable validation decision that never changes raw evidence."""

    evidence_id: UUID
    state: EvidenceValidationState
    validator: str
    rationale: str
    validated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    supporting_evidence_ids: tuple[UUID, ...] = ()
    id: UUID = field(default_factory=uuid4)

    def __post_init__(self) -> None:
        if not self.validator.strip():
            raise ValueError("validation.validator cannot be blank")
        if not self.rationale.strip():
            raise ValueError("validation.rationale cannot be blank")
        if self.state is EvidenceValidationState.PENDING:
            if self.supporting_evidence_ids:
                raise ValueError("pending validation cannot cite supporting validation evidence")
        elif self.state in {EvidenceValidationState.VALIDATED, EvidenceValidationState.REJECTED}:
            if not self.supporting_evidence_ids:
                raise ValueError("final validation decisions require supporting evidence")
