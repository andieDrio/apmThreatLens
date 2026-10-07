import pytest
from psycopg.errors import ForeignKeyViolation
from threatlens.domain.models import Asset, Campaign, Evidence, Finding, Scope, Service
from threatlens.providers.handoff import ProviderHandoff
from uuid import uuid4

def test_repository_persists_domain_relationships(postgres_repository):
    repo=postgres_repository
    campaign=Campaign(name="authorized-campaign",scope=Scope(include=("198.51.100.10",),exclude=("198.51.100.20",)),authorized=True)
    asset=Asset(canonical_id="ip:198.51.100.10",asset_type="ipv4",value="198.51.100.10")
    service=Service(asset_id=asset.id,protocol="tcp",port=443,service_name="https")
    evidence=ProviderHandoff.seal_evidence(Evidence(kind="http-response",content="HTTP/1.1 200 OK",source="unit-test"))
    finding=Finding(title="Example finding",asset_id=asset.id,evidence_ids=(evidence.id,),confidence=0.9,source="unit-test")
    repo.save_campaign(campaign); repo.save_asset(asset); repo.save_service(service); repo.save_evidence(evidence); repo.save_finding(finding)
    assert repo.count("campaigns")==1; assert repo.count("assets")==1; assert repo.count("services")==1
    assert repo.count("evidence")==1; assert repo.count("findings")==1; assert repo.count("finding_evidence")==1
    assert repo.asset_id(asset.canonical_id)==asset.id

def test_asset_identity_is_idempotent(postgres_repository):
    first=Asset(canonical_id="fqdn:example.internal",asset_type="fqdn",value="example.internal")
    second=Asset(canonical_id="fqdn:example.internal",asset_type="fqdn",value="example.internal")
    postgres_repository.save_asset(first); postgres_repository.save_asset(second)
    assert postgres_repository.count("assets")==1
    assert postgres_repository.asset_id(first.canonical_id)==first.id

def test_foreign_keys_prevent_orphan_service(postgres_repository):
    with pytest.raises(ForeignKeyViolation):
        postgres_repository.save_service(Service(asset_id=uuid4(),protocol="tcp",port=443))
