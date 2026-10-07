from uuid import uuid4

import pytest

from threatlens.domain.models import Finding, Severity
from threatlens.risk.engine import RiskContext, RiskEngine, RiskLevel


def _finding(*, severity=Severity.HIGH, confidence=0.9, cvss=8.5):
    return Finding(
        title="Remote service weakness",
        asset_id=uuid4(),
        evidence_ids=(uuid4(),),
        severity=severity,
        confidence=confidence,
        cvss=cvss,
        vulnerability_id="CVE-TEST-1",
        source="scanner-a",
    )


def test_risk_is_deterministic_and_explainable():
    finding = _finding()
    context = RiskContext(
        exploitability=0.9,
        exposure=0.8,
        asset_criticality=0.9,
        business_impact=0.8,
        threat_relevance=0.7,
        control_coverage=0.1,
    )

    first = RiskEngine().assess(finding, context)
    second = RiskEngine().assess(finding, context)

    assert first == second
    assert first.score == 0.779
    assert first.level is RiskLevel.HIGH
    assert "Finding.severity" in first.inputs_used
    assert any("Control coverage" in item for item in first.explanation)


def test_cvss_is_supporting_input_not_sole_risk_determinant():
    finding = _finding(severity=Severity.LOW, confidence=0.8, cvss=10.0)
    low_context = RiskContext(
        exposure=0.0,
        asset_criticality=0.0,
        business_impact=0.0,
        threat_relevance=0.0,
        control_coverage=1.0,
    )

    assessment = RiskEngine().assess(finding, low_context)

    assert assessment.level is RiskLevel.LOW
    assert assessment.score < 0.40
    assert any(
        "CVSS is not used as the sole risk determinant" in item for item in assessment.explanation
    )


def test_missing_environmental_context_is_not_treated_as_zero():
    finding = _finding(severity=Severity.HIGH, confidence=1.0, cvss=None)

    assessment = RiskEngine().assess(finding)

    assert assessment.score == 0.8333
    assert assessment.level is RiskLevel.HIGH
    assert "exposure" in assessment.missing_inputs
    assert "asset_criticality" in assessment.missing_inputs
    assert "business_impact" in assessment.missing_inputs
    assert "threat_relevance" in assessment.missing_inputs
    assert "control_coverage" in assessment.missing_inputs


def test_invalid_context_rejected():
    with pytest.raises(ValueError):
        RiskContext(exposure=1.1)


def test_full_context_can_reach_critical():
    finding = _finding(severity=Severity.CRITICAL, confidence=1.0, cvss=9.8)
    context = RiskContext(
        exploitability=1.0,
        exposure=1.0,
        asset_criticality=1.0,
        business_impact=1.0,
        threat_relevance=1.0,
        control_coverage=0.0,
        source="assessment-context",
    )

    assessment = RiskEngine().assess(finding, context)

    assert assessment.score == 1.0
    assert assessment.level is RiskLevel.CRITICAL
