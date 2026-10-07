from uuid import uuid4
import pytest
from threatlens.domain.models import Evidence
from threatlens.evidence.validation import EvidenceValidation, EvidenceValidationState
from threatlens.providers.handoff import ProviderHandoff

def evidence(): return ProviderHandoff.seal_evidence(Evidence(kind="banner",content="SSH-2.0-test",source="test"))

def test_evidence_validation_is_durable_and_requires_existing_evidence(postgres_repository):
    e=evidence(); postgres_repository.save_evidence(e)
    v=EvidenceValidation(evidence_id=e.id,state=EvidenceValidationState.VALIDATED,validator="analyst",rationale="Reviewed.",supporting_evidence_ids=(e.id,))
    postgres_repository.save_evidence_validation(v); assert postgres_repository.count("evidence_validations")==1

def test_validation_rejects_missing_supporting_evidence(postgres_repository):
    e=evidence(); postgres_repository.save_evidence(e)
    v=EvidenceValidation(evidence_id=e.id,state=EvidenceValidationState.VALIDATED,validator="analyst",rationale="Reviewed.",supporting_evidence_ids=(uuid4(),))
    with pytest.raises(KeyError,match="supporting"): postgres_repository.save_evidence_validation(v)

def test_pending_validation_transitions_append_only(postgres_repository):
    e=evidence(); postgres_repository.save_evidence(e)
    p=EvidenceValidation(evidence_id=e.id,state=EvidenceValidationState.PENDING,validator="analyst",rationale="Awaiting review.")
    postgres_repository.save_evidence_validation(p)
    v=EvidenceValidation(evidence_id=e.id,state=EvidenceValidationState.VALIDATED,validator="reviewer",rationale="Confirmed.",supporting_evidence_ids=(e.id,))
    postgres_repository.transition_evidence_validation(p.id,v); assert postgres_repository.count("evidence_validations")==2

def test_validation_cannot_be_rewritten_without_supersession(postgres_repository):
    e=evidence(); postgres_repository.save_evidence(e)
    v=EvidenceValidation(evidence_id=e.id,state=EvidenceValidationState.VALIDATED,validator="analyst",rationale="Reviewed.",supporting_evidence_ids=(e.id,))
    postgres_repository.save_evidence_validation(v)
    replacement=EvidenceValidation(evidence_id=e.id,state=EvidenceValidationState.SUPERSEDED,validator="reviewer",rationale="Superseded.",supporting_evidence_ids=(e.id,))
    postgres_repository.supersede_evidence_validation(v.id,replacement); assert postgres_repository.count("evidence_validations")==2
