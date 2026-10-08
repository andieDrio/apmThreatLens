from threatlens.domain.models import Asset, Evidence, Finding, FindingState, Severity, User


def test_postgres_finding_remediation_is_atomic_and_audited(postgres_repository):
    repository = postgres_repository
    actor = User(
        username="remediator",
        password_hash="test-password-hash",
        role="ANALYST",
    )
    repository.save_user(actor)

    asset = Asset(canonical_id="host:10.0.0.10", asset_type="HOST", value="10.0.0.10")
    repository.save_asset(asset)
    evidence = Evidence(
        kind="test",
        content="evidence",
        source="test",
    )
    repository.save_evidence(evidence)
    finding = Finding(
        title="Confirmed test finding",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
        state=FindingState.CONFIRMED,
        severity=Severity.HIGH,
        confidence=1.0,
        source="test",
    )
    repository.save_finding(finding)

    changed, state, allowed = repository.transition_finding_remediation_with_audit(
        finding_id=finding.id,
        target_state=FindingState.MITIGATED,
        actor_user_id=actor.id,
        rationale="remediation verified",
    )

    assert changed is True
    assert state is FindingState.MITIGATED
    assert allowed is True
    with repository.connection.cursor() as cursor:
        cursor.execute("SELECT state FROM findings WHERE id=%s", (finding.id,))
        assert cursor.fetchone()[0] == "MITIGATED"
        cursor.execute(
            """SELECT action, outcome, actor_user_id
               FROM audit_events
               WHERE resource_id=%s
               ORDER BY created_at DESC, id DESC
               LIMIT 1""",
            (finding.id,),
        )
        action, outcome, actor_user_id = cursor.fetchone()
    assert action == "FINDING_REMEDIATION"
    assert outcome == "SUCCESS"
    assert actor_user_id == actor.id


def test_postgres_finding_remediation_rejects_invalid_transition_with_audit(
    postgres_repository,
):
    repository = postgres_repository
    actor = User(
        username="remediator",
        password_hash="test-password-hash",
        role="ANALYST",
    )
    repository.save_user(actor)

    asset = Asset(canonical_id="host:10.0.0.11", asset_type="HOST", value="10.0.0.11")
    repository.save_asset(asset)
    evidence = Evidence(
        kind="test",
        content="evidence",
        source="test",
    )
    repository.save_evidence(evidence)
    finding = Finding(
        title="Suspected test finding",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
        state=FindingState.SUSPECTED,
        severity=Severity.MEDIUM,
        confidence=0.5,
        source="test",
    )
    repository.save_finding(finding)

    changed, state, allowed = repository.transition_finding_remediation_with_audit(
        finding_id=finding.id,
        target_state=FindingState.MITIGATED,
        actor_user_id=actor.id,
        rationale="attempted remediation",
    )

    assert changed is False
    assert state is FindingState.SUSPECTED
    assert allowed is False
    with repository.connection.cursor() as cursor:
        cursor.execute("SELECT state FROM findings WHERE id=%s", (finding.id,))
        assert cursor.fetchone()[0] == "SUSPECTED"
        cursor.execute(
            """SELECT action, outcome, actor_user_id
               FROM audit_events
               WHERE resource_id=%s
               ORDER BY created_at DESC, id DESC
               LIMIT 1""",
            (finding.id,),
        )
        action, outcome, actor_user_id = cursor.fetchone()
    assert action == "FINDING_REMEDIATION"
    assert outcome == "DENIED"
    assert actor_user_id == actor.id


def test_postgres_risk_assessment_persists_with_audit(postgres_repository):
    from threatlens.risk.engine import RiskContext, RiskEngine

    repository = postgres_repository
    actor = User(
        username="risk-analyst",
        password_hash="test-password-hash",
        role="ANALYST",
    )
    repository.save_user(actor)

    asset = Asset(canonical_id="host:10.0.0.12", asset_type="HOST", value="10.0.0.12")
    repository.save_asset(asset)
    evidence = Evidence(kind="test", content="evidence", source="test")
    repository.save_evidence(evidence)
    finding = Finding(
        title="Risk assessment finding",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
        state=FindingState.CONFIRMED,
        severity=Severity.HIGH,
        cvss=8.0,
        confidence=0.9,
        source="test",
    )
    repository.save_finding(finding)

    context = RiskContext(
        exploitability=0.9,
        exposure=0.8,
        asset_criticality=0.7,
        business_impact=0.6,
        threat_relevance=0.5,
        control_coverage=0.2,
        source="assessment-context",
    )
    assessment = RiskEngine().assess(finding, context)
    assessment_id = repository.save_risk_assessment_with_audit(
        assessment,
        {
            "exploitability": context.exploitability,
            "exposure": context.exposure,
            "asset_criticality": context.asset_criticality,
            "business_impact": context.business_impact,
            "threat_relevance": context.threat_relevance,
            "control_coverage": context.control_coverage,
            "source": context.source,
        },
        actor.id,
    )

    assert assessment_id
    with repository.connection.cursor() as cursor:
        cursor.execute(
            "SELECT finding_id, level, score, context_source FROM risk_assessments WHERE id=%s",
            (assessment_id,),
        )
        finding_id, level, score, source = cursor.fetchone()
        assert finding_id == finding.id
        assert level == "HIGH"
        assert score == assessment.score
        assert source == "assessment-context"
        cursor.execute(
            """SELECT action, outcome, actor_user_id
               FROM audit_events
               WHERE resource_id=%s
               ORDER BY created_at DESC, id DESC
               LIMIT 1""",
            (finding.id,),
        )
        action, outcome, actor_user_id = cursor.fetchone()
    assert action == "RISK_ASSESSMENT_CREATED"
    assert outcome == "SUCCESS"
    assert actor_user_id == actor.id
