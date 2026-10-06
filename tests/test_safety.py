import pytest

from threatlens.domain.models import Campaign, Scope
from threatlens.safety.policy import ExecutionPolicy, validate_campaign_execution


def test_safe_execution_policy_accepts_authorized_campaign() -> None:
    campaign = Campaign(
        name="authorized-vapt",
        scope=Scope(include=("198.51.100.10",)),
        authorized=True,
    )
    validate_campaign_execution(campaign, ExecutionPolicy())


def test_invalid_authorization_fails_closed() -> None:
    campaign = object.__new__(Campaign)
    object.__setattr__(campaign, "authorized", False)
    object.__setattr__(campaign, "scope", Scope(include=("198.51.100.10",)))
    with pytest.raises(PermissionError, match="authorization is required"):
        validate_campaign_execution(campaign, ExecutionPolicy())
