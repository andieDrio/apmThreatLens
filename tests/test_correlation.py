from uuid import uuid4

import pytest

from threatlens.domain.models import Finding, FindingState, Severity
from threatlens.providers.correlation import correlation_key, correlate_findings


def _finding(
    *,
    source: str,
    evidence_id,
    severity=Severity.MEDIUM,
    title="Weak TLS",
    **context,
) -> Finding:
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
        **context,
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


def test_same_vulnerability_different_service_context_does_not_correlate() -> None:
    first = _finding(source="scanner-a", evidence_id=uuid4(), service_id=uuid4())
    second = _finding(source="scanner-b", evidence_id=uuid4(), service_id=uuid4())

    assert len(correlate_findings((first, second))) == 2


def test_same_service_endpoint_and_parameter_correlate() -> None:
    service_id = uuid4()
    first = _finding(
        source="scanner-a",
        evidence_id=uuid4(),
        service_id=service_id,
        endpoint="/api/users",
        parameter="id",
        location="query",
    )
    second = _finding(
        source="scanner-b",
        evidence_id=uuid4(),
        service_id=service_id,
        endpoint=" /API/users ",
        parameter=" ID ",
        location="QUERY",
        severity=Severity.HIGH,
    )

    result = correlate_findings((first, second))

    assert len(result) == 1
    assert result[0].severity is Severity.HIGH


def test_context_present_vs_missing_never_correlates() -> None:
    contextual = _finding(
        source="scanner-a",
        evidence_id=uuid4(),
        service_id=uuid4(),
        endpoint="/admin",
    )
    uncontextual = _finding(source="scanner-b", evidence_id=uuid4())

    assert len(correlate_findings((contextual, uncontextual))) == 2


def test_blank_context_is_rejected() -> None:
    with pytest.raises(ValueError, match="endpoint"):
        _finding(source="scanner-a", evidence_id=uuid4(), endpoint="  ")
