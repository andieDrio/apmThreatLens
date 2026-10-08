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
