from datetime import UTC, datetime
from threading import Barrier, Thread
from uuid import UUID, uuid4

import pytest
import httpx
from psycopg.errors import ForeignKeyViolation

from threatlens.api.app import create_app
from threatlens.auth import AuthenticationService, Role
from threatlens.domain.models import (
    Asset,
    AuditEvent,
    Campaign,
    Evidence,
    Finding,
    FindingState,
    LifecycleState,
    Scope,
    Scan,
    Service,
    Severity,
    User,
)
from threatlens.evidence.validation import EvidenceValidation, EvidenceValidationState
from threatlens.orchestration.engine import ScanOrchestrator
from threatlens.providers.handoff import ProviderHandoff
from threatlens.safety.policy import ExecutionPolicy
from threatlens.providers.runtime import ProviderCapability, ProviderMetadata
from threatlens.storage.auth import DEFAULT_ORGANIZATION_ID
from threatlens.storage.postgres import PostgresRepository
from threatlens.storage.finding_correlation import DurableFindingCorrelator


def make_campaign():
    return Campaign(
        name="authorized-postgres-campaign",
        scope=Scope(include=("198.51.100.10",)),
        authorized=True,
    )



def running_execution(repo, campaign, provider_name):
    scan = Scan(campaign_id=campaign.id, provider_name=provider_name)
    repo.save_scan_with_audit(
        scan,
        AuditEvent(
            action="SCAN_QUEUED",
            resource_type="SCAN",
            resource_id=scan.execution_id,
            outcome="SUCCESS",
            detail=f"provider={provider_name}",
        ),
    )
    assert repo.update_scan_state_if_current(
        scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING
    )
    return scan.execution_id


def test_postgres_persists_domain_relationships(postgres_repository):
    repo = postgres_repository
    c = make_campaign()
    asset = Asset(canonical_id="ip:198.51.100.10", asset_type="ipv4", value="198.51.100.10")
    service = Service(asset_id=asset.id, protocol="tcp", port=443, service_name="https")
    evidence = ProviderHandoff.seal_evidence(
        Evidence(kind="http-response", content="HTTP/1.1 200 OK", source="unit-test")
    )
    finding = Finding(
        title="Example finding",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
        confidence=0.9,
        source="unit-test",
    )
    repo.save_campaign(c)
    repo.save_asset(asset)
    repo.save_service(service)
    repo.save_evidence(evidence)
    repo.save_finding(finding)
    assert repo.count("campaigns") == 1
    assert repo.count("assets") == 1
    assert repo.count("services") == 1
    assert repo.count("evidence") == 1
    assert repo.count("findings") == 1
    assert repo.count("finding_evidence") == 1
    assert repo.asset_id(asset.canonical_id) == asset.id


def test_postgres_asset_and_finding_data_isolated_by_campaign_organization(
    postgres_repository,
):
    repo = postgres_repository
    default_campaign = make_campaign()
    other_campaign = make_campaign()
    repo.save_campaign(default_campaign)
    repo.save_campaign(other_campaign)
    other_organization_id = uuid4()
    with repo.connection.transaction():
        with repo.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO organizations (id,name,slug,created_at) "
                "VALUES (%s,'Asset Isolation','asset-' || %s,NOW())",
                (other_organization_id, str(other_organization_id)),
            )
            cursor.execute(
                "UPDATE campaigns SET organization_id=%s WHERE id=%s",
                (other_organization_id, other_campaign.id),
            )

    default_execution = running_execution(repo, default_campaign, "asset-isolation-a")
    other_execution = running_execution(repo, other_campaign, "asset-isolation-b")
    canonical_id = "fqdn:shared-customer-host.example"
    default_asset = repo.save_asset_for_execution(
        default_execution,
        Asset(canonical_id=canonical_id, asset_type="fqdn", value="shared-customer-host.example"),
    )
    other_asset = repo.save_asset_for_execution(
        other_execution,
        Asset(canonical_id=canonical_id, asset_type="fqdn", value="shared-customer-host.example"),
    )
    repeated_asset = repo.save_asset_for_execution(
        default_execution,
        Asset(canonical_id=canonical_id, asset_type="fqdn", value="shared-customer-host.example"),
    )
    assert default_asset.id != other_asset.id
    assert repeated_asset.id == default_asset.id
    assert repo.asset_id(canonical_id, DEFAULT_ORGANIZATION_ID) == default_asset.id
    assert repo.asset_id(canonical_id, other_organization_id) == other_asset.id

    default_service = Service(asset_id=default_asset.id, protocol="tcp", port=443)
    other_service = Service(asset_id=other_asset.id, protocol="tcp", port=443)
    repo.save_service_for_execution(default_execution, default_service)
    repo.save_service_for_execution(other_execution, other_service)
    with pytest.raises(KeyError):
        repo.save_service_for_execution(default_execution, other_service)

    default_evidence = ProviderHandoff.seal_evidence(
        Evidence(kind="asset-isolation", content="default tenant", source="isolation-test")
    )
    other_evidence = ProviderHandoff.seal_evidence(
        Evidence(kind="asset-isolation", content="other tenant", source="isolation-test")
    )
    repo.save_evidence_for_execution(default_execution, default_evidence)
    repo.save_evidence_for_execution(other_execution, other_evidence)
    default_finding = Finding(
        title="Default tenant finding",
        asset_id=default_asset.id,
        evidence_ids=(default_evidence.id,),
        service_id=default_service.id,
        severity=Severity.HIGH,
        confidence=0.9,
        source="isolation-test",
    )
    other_finding = Finding(
        title="Other tenant finding",
        asset_id=other_asset.id,
        evidence_ids=(other_evidence.id,),
        service_id=other_service.id,
        severity=Severity.CRITICAL,
        confidence=0.95,
        source="isolation-test",
    )
    correlator = DurableFindingCorrelator(repo)
    correlator.persist_for_execution(default_execution, default_finding)
    correlator.persist_for_execution(other_execution, other_finding)
    with pytest.raises(KeyError):
        repo.save_finding_for_execution(default_execution, other_finding)
    with pytest.raises(KeyError):
        correlator.persist_for_execution(default_execution, other_finding)

    assert repo.assets_read_model(organization_id=DEFAULT_ORGANIZATION_ID)["total"] == 1
    assert repo.assets_read_model(organization_id=other_organization_id)["total"] == 1
    assert repo.findings_read_model(organization_id=DEFAULT_ORGANIZATION_ID)["total"] == 1
    assert repo.findings_read_model(organization_id=other_organization_id)["total"] == 1
    assert repo.dashboard_summary(DEFAULT_ORGANIZATION_ID) == {
        "campaigns": 1,
        "assets": 1,
        "services": 1,
        "findings": 1,
        "findings_by_severity": {"HIGH": 1},
        "scans_by_state": {"RUNNING": 1},
    }
    assert repo.dashboard_summary(other_organization_id)["findings_by_severity"] == {
        "CRITICAL": 1
    }
    with pytest.raises(KeyError):
        repo.finding_by_id(other_finding.id, DEFAULT_ORGANIZATION_ID)
    with pytest.raises(KeyError):
        repo.transition_finding_remediation_idempotent(
            finding_id=other_finding.id,
            target_state=FindingState.MITIGATED,
            actor_user_id=uuid4(),
            rationale="cross-organization attempt",
            idempotency_key="cross-org-finding-control-0001",
            organization_id=DEFAULT_ORGANIZATION_ID,
        )


@pytest.mark.anyio
async def test_postgres_asset_finding_and_dashboard_api_are_organization_scoped(
    postgres_repository,
):
    repo = postgres_repository
    default_campaign = make_campaign()
    other_campaign = make_campaign()
    repo.save_campaign(default_campaign)
    repo.save_campaign(other_campaign)
    other_organization_id = uuid4()
    with repo.connection.transaction():
        with repo.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO organizations (id,name,slug,created_at) "
                "VALUES (%s,'API Isolation','api-' || %s,NOW())",
                (other_organization_id, str(other_organization_id)),
            )
            cursor.execute(
                "UPDATE campaigns SET organization_id=%s WHERE id=%s",
                (other_organization_id, other_campaign.id),
            )

    executions = (
        running_execution(repo, default_campaign, "asset-api-a"),
        running_execution(repo, other_campaign, "asset-api-b"),
    )
    assets = [
        repo.save_asset_for_execution(
            execution_id,
            Asset(
                canonical_id="fqdn:api-shared.example",
                asset_type="fqdn",
                value="api-shared.example",
            ),
        )
        for execution_id in executions
    ]
    findings = []
    for index, (execution_id, asset) in enumerate(zip(executions, assets, strict=True)):
        evidence = ProviderHandoff.seal_evidence(
            Evidence(
                kind="api-tenant-isolation",
                content=f"tenant-{index}",
                source="api-isolation-test",
            )
        )
        repo.save_evidence_for_execution(execution_id, evidence)
        finding = Finding(
            title=f"Tenant {index} finding",
            asset_id=asset.id,
            evidence_ids=(evidence.id,),
            severity=Severity.HIGH if index == 0 else Severity.CRITICAL,
            confidence=0.9,
            source="api-isolation-test",
        )
        repo.save_finding_for_execution(execution_id, finding)
        findings.append(finding)

    auth = AuthenticationService(repo)
    password = "correct horse battery staple"
    auth.create_user("asset-api-default", password, Role.ANALYST)
    other_user = auth.create_user("asset-api-other", password, Role.ANALYST)
    with repo.connection.cursor() as cursor:
        cursor.execute(
            "UPDATE organization_memberships SET organization_id=%s "
            "WHERE user_id=%s AND organization_id=%s",
            (other_organization_id, other_user.id, DEFAULT_ORGANIZATION_ID),
        )
    repo.connection.commit()

    app = create_app(repository=repo, auth_service=auth)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        tokens = {}
        for username in ("asset-api-default", "asset-api-other"):
            login = await client.post(
                "/api/v1/auth/login", json={"username": username, "password": password}
            )
            assert login.status_code == 200
            tokens[username] = login.json()["access_token"]

        default_headers = {"Authorization": f"Bearer {tokens['asset-api-default']}"}
        other_headers = {"Authorization": f"Bearer {tokens['asset-api-other']}"}
        default_assets = await client.get("/api/v1/assets", headers=default_headers)
        other_assets = await client.get("/api/v1/assets", headers=other_headers)
        default_findings = await client.get("/api/v1/findings", headers=default_headers)
        other_findings = await client.get("/api/v1/findings", headers=other_headers)
        default_summary = await client.get(
            "/api/v1/dashboard/summary", headers=default_headers
        )
        other_summary = await client.get(
            "/api/v1/dashboard/summary", headers=other_headers
        )
        hidden_risk = await client.get(
            f"/api/v1/findings/{findings[1].id}/risk-assessments",
            headers=default_headers,
        )
        hidden_remediation = await client.post(
            f"/api/v1/findings/{findings[1].id}/remediation",
            headers={**default_headers, "Idempotency-Key": "tenant-api-remediation-0001"},
            json={"state": "MITIGATED", "rationale": "must remain tenant isolated"},
        )

    assert default_assets.status_code == other_assets.status_code == 200
    assert default_assets.json()["total"] == other_assets.json()["total"] == 1
    assert default_assets.json()["items"][0]["id"] != other_assets.json()["items"][0]["id"]
    assert default_findings.json()["items"][0]["title"] == "Tenant 0 finding"
    assert other_findings.json()["items"][0]["title"] == "Tenant 1 finding"
    assert default_summary.json()["findings_by_severity"] == {"HIGH": 1}
    assert other_summary.json()["findings_by_severity"] == {"CRITICAL": 1}
    assert hidden_risk.status_code == hidden_remediation.status_code == 404


def test_postgres_campaign_report_is_campaign_scoped_and_excludes_raw_evidence(
    postgres_repository,
):
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    execution_id = running_execution(repo, campaign, "report-provider")
    asset = Asset(canonical_id="ip:198.51.100.88", asset_type="ipv4", value="198.51.100.88")
    repo.save_asset(asset)
    evidence = ProviderHandoff.seal_evidence(
        Evidence(
            kind="http-response",
            content="private raw payload must stay out of a report",
            source="report-provider",
            metadata={"execution_id": str(execution_id)},
        )
    )
    repo.save_evidence_for_execution(execution_id, evidence)
    finding = Finding(
        title="Missing transport header",
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
        severity=Severity.HIGH,
        confidence=0.95,
        source="report-provider",
    )
    repo.save_finding_for_execution(execution_id, finding)

    other_campaign = make_campaign()
    repo.save_campaign(other_campaign)
    other_execution_id = running_execution(repo, other_campaign, "other-report-provider")
    other_evidence = ProviderHandoff.seal_evidence(
        Evidence(
            kind="http-response",
            content="evidence from another campaign",
            source="other-report-provider",
            metadata={"execution_id": str(other_execution_id)},
        )
    )
    repo.save_evidence_for_execution(other_execution_id, other_evidence)
    repo.add_finding_evidence(finding.id, (other_evidence.id,))

    report = repo.campaign_report_read_model(campaign.id, DEFAULT_ORGANIZATION_ID)
    assert report["campaign"]["id"] == str(campaign.id)
    assert report["scan_summary"] == {"total": 1, "by_state": {"RUNNING": 1}}
    assert report["finding_summary"]["by_severity"] == {"HIGH": 1}
    assert len(report["findings"]) == 1
    assert report["findings"][0]["evidence_total"] == 1
    assert report["findings"][0]["evidence"][0]["id"] == str(evidence.id)
    assert "content" not in str(report)


def test_postgres_campaign_report_export_audit_is_atomic(postgres_repository):
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    actor = User(
        username="campaign-report-exporter",
        password_hash="test-hash",
        role=Role.ANALYST.value,
    )
    repo.save_user(actor)
    before = repo.count("audit_events")

    report = repo.campaign_report_export_with_audit(
        campaign.id, actor.id, DEFAULT_ORGANIZATION_ID
    )

    assert report["campaign"]["id"] == str(campaign.id)
    assert repo.count("audit_events") == before + 1
    with repo.connection.cursor() as cursor:
        cursor.execute(
            """SELECT actor_user_id, action, resource_type, resource_id, outcome, detail
               FROM audit_events WHERE action='CAMPAIGN_REPORT_EXPORTED'
               ORDER BY created_at DESC, id DESC LIMIT 1"""
        )
        event = cursor.fetchone()
    assert event[:5] == (
        actor.id,
        "CAMPAIGN_REPORT_EXPORTED",
        "CAMPAIGN_REPORT",
        campaign.id,
        "SUCCESS",
    )
    assert event[5] == "scan_count=0;finding_count=0;findings_returned=0;findings_truncated=false"

    before_failed_export = repo.count("audit_events")
    with pytest.raises(ForeignKeyViolation):
        repo.campaign_report_export_with_audit(
            campaign.id, uuid4(), DEFAULT_ORGANIZATION_ID
        )
    assert repo.count("audit_events") == before_failed_export


def test_postgres_campaign_report_export_missing_campaign_is_not_audited(postgres_repository):
    with pytest.raises(KeyError):
        postgres_repository.campaign_report_export_with_audit(
            uuid4(), uuid4(), DEFAULT_ORGANIZATION_ID
        )
    assert postgres_repository.count("audit_events") == 0


def test_postgres_campaign_reads_and_reports_enforce_organization_ownership(
    postgres_repository,
):
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    other_organization_id = uuid4()
    execution_id = uuid4()
    with repo.connection.transaction():
        with repo.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO organizations (id,name,slug,created_at) "
                "VALUES (%s,'Isolation Test','isolation-' || %s,NOW())",
                (other_organization_id, str(other_organization_id)),
            )
            cursor.execute(
                "UPDATE campaigns SET organization_id=%s WHERE id=%s",
                (other_organization_id, campaign.id),
            )
            cursor.execute(
                """INSERT INTO scans
                       (execution_id,campaign_id,provider_name,state,queued_at)
                   VALUES (%s,%s,'isolation-test','QUEUED',NOW())""",
                (execution_id, campaign.id),
            )

    default_campaigns = repo.campaigns_read_model(DEFAULT_ORGANIZATION_ID)
    other_campaigns = repo.campaigns_read_model(other_organization_id)
    default_ids = {item["id"] for item in default_campaigns["items"]}
    other_ids = {item["id"] for item in other_campaigns["items"]}
    assert str(campaign.id) not in default_ids
    assert str(campaign.id) in other_ids
    default_scans = repo.scans_read_model(DEFAULT_ORGANIZATION_ID)
    other_scans = repo.scans_read_model(other_organization_id)
    assert str(execution_id) not in {
        item["execution_id"] for item in default_scans["items"]
    }
    assert str(execution_id) in {
        item["execution_id"] for item in other_scans["items"]
    }
    with pytest.raises(KeyError):
        repo.campaign_by_id(campaign.id, DEFAULT_ORGANIZATION_ID)
    assert repo.campaign_by_id(campaign.id, other_organization_id).id == campaign.id
    with pytest.raises(KeyError):
        repo.campaign_report_read_model(campaign.id, DEFAULT_ORGANIZATION_ID)
    assert repo.campaign_report_read_model(campaign.id, other_organization_id)[
        "campaign"
    ]["id"] == str(campaign.id)


def test_postgres_rejects_service_for_unknown_asset(postgres_repository):
    # Tenant-scoped writes reject an unknown asset before SQL reaches the FK.
    with pytest.raises(KeyError):
        postgres_repository.save_service(Service(asset_id=uuid4(), protocol="tcp", port=443))


def test_postgres_auth_persistence(postgres_repository):
    auth = AuthenticationService(postgres_repository)
    auth.create_user("postgres-analyst", "correct horse battery staple", Role.ANALYST)
    assert postgres_repository.count("users") == 1
    assert postgres_repository.count("audit_events") >= 1


def test_postgres_audit_events_read_model_is_bounded_ordered_and_excludes_detail(
    postgres_repository,
):
    repo = postgres_repository
    created_at = datetime(2026, 10, 13, tzinfo=UTC)
    older = AuditEvent(
        action="OLDER_EVENT",
        resource_type="AUTH",
        outcome="SUCCESS",
        detail="password=must-not-be-exposed",
        id=UUID(int=1),
        created_at=created_at,
    )
    newer = AuditEvent(
        action="NEWER_EVENT",
        resource_type="AUTH",
        outcome="DENIED",
        detail="session_token=must-not-be-exposed",
        id=UUID(int=2),
        created_at=created_at,
    )
    repo.save_audit_event(older)
    repo.save_audit_event(newer)

    first_page = repo.audit_events_read_model(limit=1, offset=0)
    assert first_page["total"] == 2
    assert first_page["limit"] == 1
    assert first_page["offset"] == 0
    assert first_page["items"][0]["id"] == str(newer.id)
    assert first_page["items"][0]["action"] == "NEWER_EVENT"
    assert "detail" not in first_page["items"][0]
    assert "password" not in str(first_page["items"][0])
    assert "session_token" not in str(first_page["items"][0])

    second_page = repo.audit_events_read_model(limit=1, offset=1)
    assert second_page["items"][0]["id"] == str(older.id)


def test_postgres_audit_events_read_model_empty(postgres_repository):
    result = postgres_repository.audit_events_read_model()
    assert result == {"total": 0, "limit": 50, "offset": 0, "items": []}



def test_postgres_scan_queue_idempotency_rejects_changed_request(postgres_repository):
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    auth = AuthenticationService(repo)
    auth.create_user("idempotency-analyst", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("idempotency-analyst", "correct horse battery staple")
    orchestrator = ScanOrchestrator(repo, ExecutionPolicy(), auth)

    class Provider:
        name = "idempotency-provider"

        def execute(self, campaign, execution_id, cancel_event):
            raise AssertionError("queueing must not execute providers")

    class DifferentProvider:
        name = "different-provider"

        def execute(self, campaign, execution_id, cancel_event):
            raise AssertionError("queueing must not execute providers")

    first, created = orchestrator.queue_idempotent(
        campaign, Provider(), "same-idempotency-key-0001", principal=principal
    )
    replay, replay_created = orchestrator.queue_idempotent(
        campaign, Provider(), "same-idempotency-key-0001", principal=principal
    )
    assert created is True
    assert replay_created is False
    assert replay.execution_id == first.execution_id
    with pytest.raises(ValueError, match="different scan request"):
        orchestrator.queue_idempotent(
            campaign, DifferentProvider(), "same-idempotency-key-0001", principal=principal
        )
    assert repo.count("scans") == 1
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='SCAN_QUEUED'"
    ).fetchone()[0] == 1



def test_postgres_scan_idempotency_and_audit_are_atomic_on_audit_failure(
    postgres_repository,
):
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    auth = AuthenticationService(repo)
    auth.create_user("atomic-idempotency", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("atomic-idempotency", "correct horse battery staple")
    orchestrator = ScanOrchestrator(repo, ExecutionPolicy(), auth)

    class Provider:
        name = "atomic-idempotency-provider"

        def execute(self, campaign, execution_id, cancel_event):
            raise AssertionError("queueing must not execute providers")

    repo.connection.execute(
        """
        CREATE OR REPLACE FUNCTION fail_idempotent_queue_audit_fn()
        RETURNS trigger AS $$
        BEGIN
            IF NEW.action = 'SCAN_QUEUED' THEN
                RAISE EXCEPTION 'injected idempotent queue audit failure';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER fail_idempotent_queue_audit
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_idempotent_queue_audit_fn()
        """
    )
    repo.connection.commit()
    key = "atomic-idempotency-key-0001"
    with pytest.raises(Exception, match="injected idempotent queue audit failure"):
        orchestrator.queue_idempotent(campaign, Provider(), key, principal=principal)
    assert repo.count("scans") == 0
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM scan_command_idempotency"
    ).fetchone()[0] == 0

    repo.connection.execute(
        "DROP TRIGGER fail_idempotent_queue_audit ON audit_events; "
        "DROP FUNCTION fail_idempotent_queue_audit_fn()"
    )
    repo.connection.commit()
    scan, created = orchestrator.queue_idempotent(
        campaign, Provider(), key, principal=principal
    )
    assert created is True
    assert repo.scan_state(scan.execution_id) is LifecycleState.QUEUED
    assert repo.count("scans") == 1
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM scan_command_idempotency"
    ).fetchone()[0] == 1


def test_postgres_cross_instance_scan_queue_idempotency_has_single_winner(
    postgres_repository,
):
    import os

    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    auth = AuthenticationService(repo)
    auth.create_user("distributed-idempotency", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("distributed-idempotency", "correct horse battery staple")
    dsn = os.getenv("THREATLENS_TEST_DATABASE_URL") or os.getenv("THREATLENS_DATABASE_URL")
    assert dsn
    repo2 = PostgresRepository(dsn)
    repo2.initialize()
    try:
        auth2 = AuthenticationService(repo2)
        principal2, _ = auth2.authenticate(
            "distributed-idempotency", "correct horse battery staple"
        )
        orchestrator1 = ScanOrchestrator(repo, ExecutionPolicy(), auth)
        orchestrator2 = ScanOrchestrator(repo2, ExecutionPolicy(), auth2)
        barrier = Barrier(2)
        results = []
        errors = []

        class Provider:
            name = "distributed-idempotency-provider"

            def execute(self, campaign, execution_id, cancel_event):
                raise AssertionError("queueing must not execute providers")

        def queue(orchestrator, worker_principal):
            try:
                barrier.wait(timeout=5)
                results.append(
                    orchestrator.queue_idempotent(
                        campaign,
                        Provider(),
                        "distributed-idempotency-key-0001",
                        principal=worker_principal,
                    )
                )
            except Exception as exc:
                errors.append(exc)

        workers = [
            Thread(target=queue, args=(orchestrator1, principal)),
            Thread(target=queue, args=(orchestrator2, principal2)),
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)

        assert all(not worker.is_alive() for worker in workers)
        assert not errors
        assert len(results) == 2
        assert len({item[0].execution_id for item in results}) == 1
        assert sorted(item[1] for item in results) == [False, True]
        assert repo.count("scans") == 1
        assert repo.connection.execute(
            "SELECT COUNT(*) FROM audit_events WHERE action='SCAN_QUEUED'"
        ).fetchone()[0] == 1
    finally:
        repo2.close()


def test_postgres_durable_correlation_merges_provider_findings(postgres_repository):
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    execution_a = running_execution(repo, campaign, "scanner-a")
    execution_b = running_execution(repo, campaign, "scanner-b")
    asset = Asset(canonical_id="host:10.0.0.10", asset_type="ip", value="10.0.0.10")
    repo.save_asset(asset)
    a = ProviderMetadata(
        "scanner-a",
        "1.0.0",
        frozenset({ProviderCapability.VULNERABILITY, ProviderCapability.EVIDENCE}),
    )
    b = ProviderMetadata(
        "scanner-b",
        "1.0.0",
        frozenset({ProviderCapability.VULNERABILITY, ProviderCapability.EVIDENCE}),
    )
    correlator = DurableFindingCorrelator(repo)
    ha = ProviderHandoff(repo, correlator=correlator)
    hb = ProviderHandoff(repo, correlator=correlator)
    ea = ha.persist_evidence(execution_a, a, Evidence(kind="scan", content="a", source="a"))
    eb = hb.persist_evidence(execution_b, b, Evidence(kind="scan", content="b", source="b"))

    def make_finding(evidence_id, severity):
        return Finding(
            title="Weak TLS",
            asset_id=asset.id,
            evidence_ids=(evidence_id,),
            state=FindingState.CONFIRMED,
            severity=severity,
            vulnerability_id="TLS-WEAK-CIPHER",
            cwe="CWE-326",
            confidence=0.8,
        )

    first = ha.persist_finding(
        execution_a, a, asset, make_finding(ea.id, Severity.MEDIUM), (ea,)
    )
    second = hb.persist_finding(
        execution_b, b, asset, make_finding(eb.id, Severity.HIGH), (eb,)
    )
    assert first.id == second.id
    assert repo.count("findings") == 1
    assert repo.count("finding_evidence") == 2


def test_postgres_evidence_validation_is_append_only(postgres_repository):
    repo = postgres_repository
    evidence = ProviderHandoff.seal_evidence(
        Evidence(kind="banner", content="SSH-2.0-test", source="test")
    )
    repo.save_evidence(evidence)
    pending = EvidenceValidation(
        evidence_id=evidence.id,
        state=EvidenceValidationState.PENDING,
        validator="analyst",
        rationale="Awaiting independent review.",
    )
    repo.save_evidence_validation(pending)
    validated = EvidenceValidation(
        evidence_id=evidence.id,
        state=EvidenceValidationState.VALIDATED,
        validator="reviewer",
        rationale="Independently confirmed.",
        supporting_evidence_ids=(evidence.id,),
    )
    repo.transition_evidence_validation(pending.id, validated)
    assert repo.count("evidence_validations") == 2


def test_postgres_scan_lifecycle_cas_is_authoritative(postgres_repository):
    repo = postgres_repository
    c = make_campaign()
    repo.save_campaign(c)
    auth = AuthenticationService(repo)
    auth.create_user("lifecycle-analyst", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("lifecycle-analyst", "correct horse battery staple")

    class Provider:
        name = "postgres-test-provider"

        def execute(self, campaign, execution_id, cancel_event):
            return None

    orchestrator = ScanOrchestrator(repo, ExecutionPolicy(), auth)
    scan = orchestrator.queue(c, Provider(), principal=principal)
    assert repo.update_scan_state_if_current(
        scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING
    )
    assert not repo.update_scan_state_if_current(
        scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING
    )
    assert repo.scan_state(scan.execution_id) is LifecycleState.RUNNING



def test_postgres_lifecycle_command_idempotency_serializes_cross_instance_retries(
    postgres_repository,
):
    import os

    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    auth = AuthenticationService(repo)
    auth.create_user("lifecycle-idempotency", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("lifecycle-idempotency", "correct horse battery staple")
    orchestrator = ScanOrchestrator(repo, ExecutionPolicy(), auth)

    class Provider:
        name = "lifecycle-idempotency-provider"

        def execute(self, campaign, execution_id, cancel_event):
            raise AssertionError("queueing must not execute providers")

    scan, _ = orchestrator.queue_idempotent(
        campaign, Provider(), "lifecycle-queue-key-0001", principal=principal
    )
    assert repo.update_scan_state_if_current(
        scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING
    )
    dsn = os.getenv("THREATLENS_TEST_DATABASE_URL") or os.getenv("THREATLENS_DATABASE_URL")
    assert dsn
    repo2 = PostgresRepository(dsn)
    repo2.initialize()
    try:
        auth2 = AuthenticationService(repo2)
        principal2, _ = auth2.authenticate(
            "lifecycle-idempotency", "correct horse battery staple"
        )
        orchestrator2 = ScanOrchestrator(repo2, ExecutionPolicy(), auth2)
        barrier = Barrier(2)
        results = []
        errors = []

        def cancel(worker, worker_principal):
            try:
                barrier.wait(timeout=5)
                results.append(
                    worker.cancel_idempotent(
                        scan.execution_id,
                        "lifecycle-cancel-command-0001",
                        principal=worker_principal,
                    )
                )
            except Exception as exc:
                errors.append(exc)

        workers = [
            Thread(target=cancel, args=(orchestrator, principal)),
            Thread(target=cancel, args=(orchestrator2, principal2)),
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(10)

        assert all(not worker.is_alive() for worker in workers)
        assert not errors
        assert len(results) == 2
        assert all(changed for changed, _ in results)
        assert sorted(created for _, created in results) == [False, True]
        assert repo.scan_state(scan.execution_id) is LifecycleState.CANCELLED
        assert repo.connection.execute(
            "SELECT COUNT(*) FROM audit_events WHERE action='SCAN_CANCELLED'"
        ).fetchone()[0] == 1
        assert repo.count("scan_lifecycle_command_idempotency") == 1

        with pytest.raises(ValueError, match="different lifecycle command"):
            orchestrator2.recover_stale_idempotent(
                scan.execution_id,
                "lifecycle-cancel-command-0001",
                principal=principal2,
            )
    finally:
        repo2.close()


def test_postgres_lifecycle_idempotency_and_audit_are_atomic_on_audit_failure(
    postgres_repository,
):
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    auth = AuthenticationService(repo)
    auth.create_user("lifecycle-atomic", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate("lifecycle-atomic", "correct horse battery staple")
    orchestrator = ScanOrchestrator(repo, ExecutionPolicy(), auth)

    class Provider:
        name = "lifecycle-atomic-provider"

        def execute(self, campaign, execution_id, cancel_event):
            raise AssertionError("queueing must not execute providers")

    scan, _ = orchestrator.queue_idempotent(
        campaign, Provider(), "lifecycle-atomic-queue-0001", principal=principal
    )
    assert repo.update_scan_state_if_current(
        scan.execution_id, LifecycleState.QUEUED, LifecycleState.RUNNING
    )
    repo.connection.execute(
        """
        CREATE OR REPLACE FUNCTION fail_lifecycle_cancel_audit_fn()
        RETURNS trigger AS $$
        BEGIN
            IF NEW.action = 'SCAN_CANCELLED' THEN
                RAISE EXCEPTION 'injected lifecycle audit failure';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER fail_lifecycle_cancel_audit
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_lifecycle_cancel_audit_fn()
        """
    )
    repo.connection.commit()

    key = "lifecycle-atomic-cancel-0001"
    with pytest.raises(Exception, match="injected lifecycle audit failure"):
        orchestrator.cancel_idempotent(scan.execution_id, key, principal=principal)
    assert repo.scan_state(scan.execution_id) is LifecycleState.RUNNING
    assert repo.count("scan_lifecycle_command_idempotency") == 0

    repo.connection.execute(
        "DROP TRIGGER fail_lifecycle_cancel_audit ON audit_events; "
        "DROP FUNCTION fail_lifecycle_cancel_audit_fn()"
    )
    repo.connection.commit()
    changed, created = orchestrator.cancel_idempotent(
        scan.execution_id, key, principal=principal
    )
    assert changed is True
    assert created is True
    assert repo.scan_state(scan.execution_id) is LifecycleState.CANCELLED
    assert repo.count("scan_lifecycle_command_idempotency") == 1
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='SCAN_CANCELLED'"
    ).fetchone()[0] == 1


def test_postgres_lifecycle_commands_hide_and_preserve_cross_organization_scans(
    postgres_repository,
):
    repo = postgres_repository
    campaign = make_campaign()
    repo.save_campaign(campaign)
    other_organization_id = uuid4()
    execution_id = uuid4()
    with repo.connection.transaction():
        with repo.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO organizations (id,name,slug,created_at) "
                "VALUES (%s,'Lifecycle Isolation','lifecycle-' || %s,NOW())",
                (other_organization_id, str(other_organization_id)),
            )
            cursor.execute(
                "UPDATE campaigns SET organization_id=%s WHERE id=%s",
                (other_organization_id, campaign.id),
            )
            cursor.execute(
                """INSERT INTO scans
                       (execution_id,campaign_id,provider_name,state,queued_at,
                        started_at,heartbeat_at)
                   VALUES (%s,%s,'isolation-test','RUNNING',NOW(),
                           NOW()-INTERVAL '10 minutes',NOW()-INTERVAL '10 minutes')""",
                (execution_id, campaign.id),
            )

    auth = AuthenticationService(repo)
    auth.create_user("scan-isolation-operator", "correct horse battery staple", Role.ANALYST)
    principal, _ = auth.authenticate(
        "scan-isolation-operator", "correct horse battery staple"
    )
    orchestrator = ScanOrchestrator(repo, ExecutionPolicy(), auth)
    lifecycle_records_before = repo.count("scan_lifecycle_command_idempotency")
    with pytest.raises(KeyError):
        orchestrator.cancel_idempotent(
            execution_id, "cross-org-cancel-command-0001", principal=principal
        )
    with pytest.raises(KeyError):
        orchestrator.recover_stale_idempotent(
            execution_id, "cross-org-recover-command-01", principal=principal
        )

    assert repo.scan_state(execution_id) is LifecycleState.RUNNING
    assert repo.count("scan_lifecycle_command_idempotency") == lifecycle_records_before
    with repo.connection.cursor() as cursor:
        cursor.execute(
            "SELECT COUNT(*) FROM audit_events WHERE resource_id=%s "
            "AND action IN ('SCAN_CANCELLED','SCAN_RECOVERED_STALE')",
            (execution_id,),
        )
        assert cursor.fetchone()[0] == 0

    replay_campaign = make_campaign()
    repo.save_campaign(replay_campaign)
    replay_execution_id = uuid4()
    repo.save_scan_with_audit(
        Scan(campaign_id=replay_campaign.id, provider_name="replay-isolation-test",
             execution_id=replay_execution_id),
        AuditEvent(
            action="SCAN_QUEUED",
            resource_type="SCAN",
            resource_id=replay_execution_id,
            outcome="SUCCESS",
            detail="idempotency isolation regression",
        ),
    )
    replay_key = "cross-org-replay-command-0001"
    changed, created = orchestrator.cancel_idempotent(
        replay_execution_id, replay_key, principal=principal
    )
    assert changed is True and created is True
    with repo.connection.cursor() as cursor:
        cursor.execute(
            "UPDATE campaigns SET organization_id=%s WHERE id=%s",
            (other_organization_id, replay_campaign.id),
        )
    repo.connection.commit()
    with pytest.raises(KeyError):
        orchestrator.cancel_idempotent(
            replay_execution_id, replay_key, principal=principal
        )
    assert repo.scan_state(replay_execution_id) is LifecycleState.CANCELLED


def test_postgres_login_session_and_success_audit_are_atomic_on_audit_failure(
    postgres_repository,
):
    repo = postgres_repository
    auth = AuthenticationService(repo)
    auth.create_user("atomic-login", "correct horse battery staple", Role.ANALYST)
    sessions_before = repo.count("auth_sessions")
    repo.connection.execute(
        """
        CREATE OR REPLACE FUNCTION fail_login_success_audit_fn()
        RETURNS trigger AS $$
        BEGIN
            IF NEW.action = 'LOGIN' AND NEW.outcome = 'SUCCESS' THEN
                RAISE EXCEPTION 'injected login audit failure';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER fail_login_success_audit
        BEFORE INSERT ON audit_events
        FOR EACH ROW EXECUTE FUNCTION fail_login_success_audit_fn()
        """
    )
    repo.connection.commit()
    with pytest.raises(Exception, match="injected login audit failure"):
        auth.authenticate("atomic-login", "correct horse battery staple")
    assert repo.count("auth_sessions") == sessions_before
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='LOGIN' AND outcome='SUCCESS'"
    ).fetchone()[0] == 0
    repo.connection.execute(
        "DROP TRIGGER fail_login_success_audit ON audit_events; "
        "DROP FUNCTION fail_login_success_audit_fn()"
    )
    repo.connection.commit()
    principal, token = auth.authenticate("atomic-login", "correct horse battery staple")
    assert auth.authenticate_session(token) == principal
    assert repo.count("auth_sessions") == sessions_before + 1
    assert repo.connection.execute(
        "SELECT COUNT(*) FROM audit_events WHERE action='LOGIN' AND outcome='SUCCESS'"
    ).fetchone()[0] == 1
