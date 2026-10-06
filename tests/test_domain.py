import pytest

from threatlens.domain.models import Asset, Campaign, Evidence, Finding, Scope, Service


def test_campaign_requires_explicit_authorization() -> None:
    with pytest.raises(ValueError, match="explicitly authorized"):
        Campaign(name="test", scope=Scope(include=("192.0.2.10",)), authorized=False)


def test_scope_rejects_blank_include() -> None:
    with pytest.raises(ValueError, match="blank targets"):
        Scope(include=("192.0.2.10", " "))


def test_service_validates_port_range() -> None:
    asset = Asset(canonical_id="ip:192.0.2.10", asset_type="ipv4", value="192.0.2.10")
    with pytest.raises(ValueError, match="1..65535"):
        Service(asset_id=asset.id, protocol="tcp", port=0)


def test_finding_requires_evidence_and_valid_cvss() -> None:
    asset = Asset(canonical_id="ip:192.0.2.10", asset_type="ipv4", value="192.0.2.10")
    with pytest.raises(ValueError, match="at least one evidence"):
        Finding(title="example", asset_id=asset.id, evidence_ids=())

    evidence = Evidence(kind="service-banner", content="raw output", source="test")
    with pytest.raises(ValueError, match="0 and 10"):
        Finding(
            title="example",
            asset_id=asset.id,
            evidence_ids=(evidence.id,),
            cvss=11.0,
        )
