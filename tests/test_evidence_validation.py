from uuid import uuid4

import pytest

from threatlens.domain.models import Evidence
from threatlens.evidence.validation import (
    EvidenceValidation,
    EvidenceValidationState,
    validate_evidence_integrity,
    validate_evidence_transition,
)
from threatlens.providers.handoff import ProviderHandoff


def sealed_evidence() -> Evidence:
    return ProviderHandoff.seal_evidence(
        Evidence(kind="http-response", content="HTTP/1.1 200 OK", source="test")
    )


def test_integrity_validation_accepts_sealed_unchanged_evidence() -> None:
    validate_evidence_integrity(sealed_evidence())


def test_integrity_validation_rejects_unsealed_evidence() -> None:
    evidence = Evidence(kind="http-response", content="HTTP/1.1 200 OK", source="test")
    with pytest.raises(ValueError, match="sealed"):
        validate_evidence_integrity(evidence)


def test_integrity_validation_rejects_tampered_content() -> None:
    evidence = sealed_evidence()
    tampered = Evidence(
        id=evidence.id,
        kind=evidence.kind,
        content="HTTP/1.1 500 Internal Server Error",
        source=evidence.source,
        captured_at=evidence.captured_at,
        sha256=evidence.sha256,
        metadata=evidence.metadata,
    )
    with pytest.raises(ValueError, match="integrity"):
        validate_evidence_integrity(tampered)


def test_validation_requires_supporting_evidence_for_final_decision() -> None:
    with pytest.raises(ValueError, match="supporting evidence"):
        EvidenceValidation(
            evidence_id=uuid4(),
            state=EvidenceValidationState.VALIDATED,
            validator="analyst",
            rationale="Observed and reproduced.",
        )


def test_validation_lifecycle_is_fail_closed() -> None:
    validate_evidence_transition(EvidenceValidationState.PENDING, EvidenceValidationState.VALIDATED)
    validate_evidence_transition(
        EvidenceValidationState.VALIDATED, EvidenceValidationState.SUPERSEDED
    )
    with pytest.raises(ValueError, match="invalid evidence validation transition"):
        validate_evidence_transition(
            EvidenceValidationState.VALIDATED, EvidenceValidationState.REJECTED
        )
