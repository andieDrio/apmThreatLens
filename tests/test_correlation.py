from uuid import uuid4

from threatlens.domain.models import Finding, FindingState, Severity
from threatlens.providers.correlation import correlation_key, correlate_findings


def _finding(*, source: str, evidence_id, severity=Severity.MEDIUM, title="Weak TLS") -> Finding:
    return Finding(
        title=title,
        asset_id=asset_id,
        evidence_ids=(evidence_id,),
        state=FindingState.CONFIRMED,
        severity=severity,
        vulnerability_id="TLS-WEAK-CIPHER",
        cwe="CWE-326",
        confidence=0.8,
        source=source,
    )


asset_id = uuid4()


def test_same_asset_and_vulnerability_correlate_into_one_logical_finding() -> None:
    first = _finding(source="scanner-a", evidence_id=uuid4())
    second = _finding(source="scanner-b", evidence_id=uuid4(), severity=Severity.HIGH)

    result = correlate_findings((first, second))

    assert len(result) == 1
    merged = result[0]
    assert merged.id == correlate_findings((first, second))[0].id
    assert set(merged.evidence_ids) == {first.evidence_ids[0], second.evidence_ids[0]}
    assert merged.severity is Severity.HIGH
    assert merged.source == "scanner-a,scanner-b"
    assert merged.confidence == 0.8


def test_different_assets_do_not_correlate() -> None:
    first = _finding(source="scanner-a", evidence_id=uuid4())
    second = Finding(
        title=first.title,
        asset_id=uuid4(),
        evidence_ids=(uuid4(),),
        vulnerability_id=first.vulnerability_id,
        cwe=first.cwe,
        source="scanner-b",
    )

    assert len(correlate_findings((first, second))) == 2


def test_same_asset_without_vulnerability_id_uses_normalized_title_and_cwe() -> None:
    first = Finding(
        title="  Weak   TLS  ",
        asset_id=asset_id,
        evidence_ids=(uuid4(),),
        cwe="CWE-326",
        source="scanner-a",
    )
    second = Finding(
        title="weak tls",
        asset_id=asset_id,
        evidence_ids=(uuid4(),),
        cwe="CWE-326",
        source="scanner-b",
    )

    assert len(correlate_findings((first, second))) == 1


def test_correlation_key_is_provider_independent() -> None:
    first = _finding(source="scanner-a", evidence_id=uuid4())
    second = _finding(source="scanner-b", evidence_id=uuid4())

    assert correlation_key(first) == correlation_key(second)
