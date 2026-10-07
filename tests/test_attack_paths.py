from uuid import uuid4

import pytest

from threatlens.attack_paths.engine import (
    AttackPathAnalyzer,
    AttackPathRelation,
    AttackPathRelationType,
)
from threatlens.domain.models import Finding, Severity


def _finding(asset_id, severity=Severity.HIGH):
    return Finding(
        title="Exposed administrative service",
        asset_id=asset_id,
        evidence_ids=(uuid4(),),
        severity=severity,
        confidence=0.95,
        vulnerability_id="VULN-1",
        source="scanner-a",
    )


def test_analyzer_follows_only_validated_evidence_backed_relationships():
    entry = uuid4()
    middle = uuid4()
    objective = uuid4()
    evidence_a = uuid4()
    evidence_b = uuid4()

    relations = [
        AttackPathRelation(
            source_asset_id=entry,
            target_asset_id=middle,
            relationship_type=AttackPathRelationType.NETWORK_REACHABILITY,
            evidence_ids=(evidence_a,),
            validated=True,
        ),
        AttackPathRelation(
            source_asset_id=middle,
            target_asset_id=objective,
            relationship_type=AttackPathRelationType.AUTHENTICATED_ACCESS,
            evidence_ids=(evidence_b,),
            validated=True,
        ),
    ]

    finding = _finding(objective)
    result = AttackPathAnalyzer().analyze(
        entry_asset_ids=(entry,),
        objective_asset_ids=(objective,),
        relations=relations,
        findings=(finding,),
        risk_scores={finding.id: 0.82},
        risk_levels={finding.id: "HIGH"},
        max_hops=4,
    )

    assert len(result.paths) == 1
    path = result.paths[0]
    assert path.asset_ids == (entry, middle, objective)
    assert len(path.relation_ids) == 2
    assert path.finding_ids == (finding.id,)
    assert path.score == 0.82
    assert path.risk_level == "HIGH"
    assert "validated relationships" in path.explanation[0]


def test_unvalidated_relationships_are_ignored_and_missing_evidence_is_rejected():
    entry = uuid4()
    objective = uuid4()

    ignored_unvalidated = AttackPathRelation(
        source_asset_id=entry,
        target_asset_id=objective,
        relationship_type=AttackPathRelationType.NETWORK_REACHABILITY,
        evidence_ids=(uuid4(),),
        validated=False,
    )

    with pytest.raises(ValueError):
        AttackPathRelation(
            source_asset_id=entry,
            target_asset_id=objective,
            relationship_type=AttackPathRelationType.NETWORK_REACHABILITY,
            evidence_ids=(),
        )

    result = AttackPathAnalyzer().analyze(
        entry_asset_ids=(entry,),
        objective_asset_ids=(objective,),
        relations=(ignored_unvalidated,),
        findings=(_finding(objective),),
    )

    assert result.paths == ()
    assert result.ignored_relation_ids == (ignored_unvalidated.id,)


def test_cycles_do_not_create_infinite_paths_and_paths_are_deterministic():
    entry = uuid4()
    middle = uuid4()
    objective = uuid4()

    relations = (
        AttackPathRelation(
            entry, middle, AttackPathRelationType.NETWORK_REACHABILITY, (uuid4(),), validated=True
        ),
        AttackPathRelation(
            middle, entry, AttackPathRelationType.NETWORK_REACHABILITY, (uuid4(),), validated=True
        ),
        AttackPathRelation(
            middle,
            objective,
            AttackPathRelationType.NETWORK_REACHABILITY,
            (uuid4(),),
            validated=True,
        ),
    )
    finding = _finding(objective)

    analyzer = AttackPathAnalyzer()
    first = analyzer.analyze(
        entry_asset_ids=(entry,),
        objective_asset_ids=(objective,),
        relations=relations,
        findings=(finding,),
        risk_scores={finding.id: 0.7},
    )
    second = analyzer.analyze(
        entry_asset_ids=(entry,),
        objective_asset_ids=(objective,),
        relations=relations,
        findings=(finding,),
        risk_scores={finding.id: 0.7},
    )

    assert first == second
    assert len(first.paths) == 1


def test_invalid_limits_are_rejected():
    with pytest.raises(ValueError):
        AttackPathAnalyzer().analyze(
            entry_asset_ids=(uuid4(),),
            objective_asset_ids=(uuid4(),),
            relations=(),
            findings=(),
            max_hops=0,
        )
