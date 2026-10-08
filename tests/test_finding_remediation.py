import pytest

from threatlens.domain.models import (
    FindingState,
    validate_finding_remediation_transition,
)


@pytest.mark.parametrize(
    "target",
    [FindingState.MITIGATED, FindingState.ACCEPTED_RISK],
)
def test_confirmed_finding_allows_remediation_targets(target):
    validate_finding_remediation_transition(FindingState.CONFIRMED, target)


@pytest.mark.parametrize(
    ("current", "target"),
    [
        (FindingState.SUSPECTED, FindingState.MITIGATED),
        (FindingState.LIKELY, FindingState.ACCEPTED_RISK),
        (FindingState.FALSE_POSITIVE, FindingState.MITIGATED),
        (FindingState.MITIGATED, FindingState.ACCEPTED_RISK),
    ],
)
def test_finding_remediation_rejects_invalid_transitions(current, target):
    with pytest.raises(ValueError):
        validate_finding_remediation_transition(current, target)


@pytest.mark.parametrize(
    "target",
    [
        FindingState.CONFIRMED,
        FindingState.FALSE_POSITIVE,
        FindingState.INFORMATIONAL,
    ],
)
def test_finding_remediation_rejects_non_remediation_targets(target):
    with pytest.raises(ValueError):
        validate_finding_remediation_transition(FindingState.CONFIRMED, target)
