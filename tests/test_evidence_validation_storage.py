from uuid import uuid4

import pytest

from threatlens.domain.models import Evidence
from threatlens.evidence.validation import EvidenceValidation, EvidenceValidationState
from threatlens.storage.sqlite import SQLiteRepository


def test_evidence_validation_is_durable_and_requires_existing_evidence(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    evidence = Evidence(kind="banner", content="SSH-2.0-test", source="test")
    repo.save_evidence(evidence)

    validation = EvidenceValidation(
        evidence_id=evidence.id,
        state=EvidenceValidationState.VALIDATED,
        validator="analyst",
        rationale="Observed evidence was independently reviewed.",
        supporting_evidence_ids=(evidence.id,),
    )
    repo.save_evidence_validation(validation)
    assert repo.count("evidence_validations") == 1
    repo.close()


def test_validation_rejects_missing_supporting_evidence(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    evidence = Evidence(kind="banner", content="SSH-2.0-test", source="test")
    repo.save_evidence(evidence)
    validation = EvidenceValidation(
        evidence_id=evidence.id,
        state=EvidenceValidationState.VALIDATED,
        validator="analyst",
        rationale="Reviewed.",
        supporting_evidence_ids=(uuid4(),),
    )
    with pytest.raises(KeyError, match="supporting"):
        repo.save_evidence_validation(validation)
    repo.close()


def test_pending_validation_transitions_append_only(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    evidence = Evidence(kind="banner", content="SSH-2.0-test", source="test")
    repo.save_evidence(evidence)
    pending = EvidenceValidation(
        evidence_id=evidence.id,
        state=EvidenceValidationState.PENDING,
        validator="analyst",
        rationale="Awaiting independent review.",
    )
    repo.save_evidence_validation(pending)
    validated = EvidenceValidation(
        evidence_id=evidence.id,
        state=EvidenceValidationState.VALIDATED,
        validator="reviewer",
        rationale="Independently confirmed.",
        supporting_evidence_ids=(evidence.id,),
    )
    repo.transition_evidence_validation(pending.id, validated)
    assert repo.count("evidence_validations") == 2
    repo.close()


def test_validation_cannot_be_rewritten_without_supersession(tmp_path) -> None:
    repo = SQLiteRepository(tmp_path / "threatlens.db")
    repo.initialize()
    evidence = Evidence(kind="banner", content="SSH-2.0-test", source="test")
    repo.save_evidence(evidence)
    validation = EvidenceValidation(
        evidence_id=evidence.id,
        state=EvidenceValidationState.VALIDATED,
        validator="analyst",
        rationale="Reviewed.",
        supporting_evidence_ids=(evidence.id,),
    )
    repo.save_evidence_validation(validation)
    replacement = EvidenceValidation(
        evidence_id=evidence.id,
        state=EvidenceValidationState.SUPERSEDED,
        validator="reviewer",
        rationale="Superseded by a later review.",
        supporting_evidence_ids=(evidence.id,),
    )
    repo.supersede_evidence_validation(validation.id, replacement)
    assert repo.count("evidence_validations") == 2
    repo.close()
