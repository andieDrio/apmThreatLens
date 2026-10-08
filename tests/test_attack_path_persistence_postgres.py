from uuid import uuid4

import pytest

from threatlens.attack_paths.engine import AttackPathRelation, AttackPathRelationType
from threatlens.auth import AuthenticationService, Role
from threatlens.domain.models import Asset, Evidence
from threatlens.evidence.validation import EvidenceValidation, EvidenceValidationState
from threatlens.providers.handoff import ProviderHandoff


def _relation_fixture(repo):
    source = Asset(canonical_id="host:10.0.0.10", asset_type="ip", value="10.0.0.10")
    target = Asset(canonical_id="host:10.0.0.20", asset_type="ip", value="10.0.0.20")
    evidence = ProviderHandoff.seal_evidence(
        Evidence(kind="relationship", content="10.0.0.10 -> 10.0.0.20", source="test")
    )
    repo.save_asset(source)
    repo.save_asset(target)
    repo.save_evidence(evidence)
    relation = AttackPathRelation(
        source_asset_id=source.id,
        target_asset_id=target.id,
        relationship_type=AttackPathRelationType.NETWORK_REACHABILITY,
        evidence_ids=(evidence.id,),
    )
    return source, target, evidence, relation


def test_attack_path_relation_starts_unvalidated_and_is_audited(postgres_repository):
    repo = postgres_repository
    _, _, _, relation = _relation_fixture(repo)
    auth = AuthenticationService(repo)
    auth.create_user("attack-path-validator", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("attack-path-validator", "correct horse battery staple")

    repo.save_attack_path_relation_with_audit(relation, principal.user_id)

    assert repo.count("attack_path_relations") == 1
    assert repo.count("attack_path_relation_evidence") == 1
    with repo.connection.cursor() as cursor:
        cursor.execute(
            "SELECT validated FROM attack_path_relations WHERE id=%s", (relation.id,)
        )
        assert cursor.fetchone()[0] is False
        cursor.execute(
            """SELECT action, outcome FROM audit_events
               WHERE resource_id=%s ORDER BY created_at DESC, id DESC LIMIT 1""",
            (relation.id,),
        )
        assert cursor.fetchone() == ("ATTACK_PATH_RELATION_CREATED", "SUCCESS")


def test_attack_path_relation_validation_requires_current_validated_evidence(postgres_repository):
    repo = postgres_repository
    _, _, evidence, relation = _relation_fixture(repo)
    auth = AuthenticationService(repo)
    auth.create_user("attack-path-reviewer", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("attack-path-reviewer", "correct horse battery staple")
    repo.save_attack_path_relation_with_audit(relation, principal.user_id)

    with pytest.raises(ValueError, match="current VALIDATED"):
        repo.validate_attack_path_relation_with_audit(relation.id, principal.user_id)


def test_attack_path_relation_validation_is_atomic_and_idempotent(postgres_repository):
    repo = postgres_repository
    _, _, evidence, relation = _relation_fixture(repo)
    auth = AuthenticationService(repo)
    auth.create_user("attack-path-auditor", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("attack-path-auditor", "correct horse battery staple")
    repo.save_attack_path_relation_with_audit(relation, principal.user_id)

    pending = EvidenceValidation(
        evidence_id=evidence.id,
        state=EvidenceValidationState.PENDING,
        validator=principal.username,
        rationale="Pending relationship review.",
    )
    repo.save_evidence_validation(pending)
    validated = EvidenceValidation(
        evidence_id=evidence.id,
        state=EvidenceValidationState.VALIDATED,
        validator=principal.username,
        rationale="Evidence independently confirms the relationship.",
        supporting_evidence_ids=(evidence.id,),
    )
    repo.transition_evidence_validation(pending.id, validated)

    assert repo.validate_attack_path_relation_with_audit(relation.id, principal.user_id) is True
    assert repo.validate_attack_path_relation_with_audit(relation.id, principal.user_id) is False

    with repo.connection.cursor() as cursor:
        cursor.execute(
            "SELECT validated, validated_by FROM attack_path_relations WHERE id=%s",
            (relation.id,),
        )
        row = cursor.fetchone()
        assert row[0] is True
        assert row[1] == principal.user_id
        cursor.execute(
            """SELECT action, outcome FROM audit_events
               WHERE resource_id=%s ORDER BY created_at, id""",
            (relation.id,),
        )
        events = cursor.fetchall()
        assert events[-2:] == [
            ("ATTACK_PATH_RELATION_VALIDATED", "SUCCESS"),
            ("ATTACK_PATH_RELATION_VALIDATED", "NOOP"),
        ]
