"""PostgreSQL integration tests for versioned schema migrations."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import psycopg
import pytest

from threatlens.domain.models import Asset, AuditEvent, Service
from threatlens.domain.indicators import normalize_ioc_indicator
from threatlens.providers.vulnerability_intelligence import normalize_vulnerability_record
from threatlens.storage.postgres import PostgresRepository
from threatlens.storage.schema_migrations import (
    Migration,
    _verify_single_user_schema,
    run_migrations,
)


def _dsn() -> str:
    return os.getenv("THREATLENS_TEST_DATABASE_URL") or os.getenv(
        "THREATLENS_DATABASE_URL", ""
    )


def test_postgres_baseline_is_recorded_and_repeat_initialize_preserves_data(
    postgres_repository,
):
    repository = postgres_repository
    with repository.connection.cursor() as cursor:
        cursor.execute(
            "SELECT version, name FROM threatlens_schema_migrations ORDER BY version"
        )
        assert cursor.fetchall() == [
            (1, "legacy_schema_baseline"),
            (2, "audit_events_append_only"),
            (3, "audit_events_no_truncate"),
            (4, "organization_membership_foundation"),
            (5, "campaign_organization_ownership"),
            (6, "asset_organization_ownership"),
            (7, "evidence_organization_ownership"),
            (8, "audit_event_organization_ownership"),
            (9, "single_user_workspace"),
            (10, "service_product_fingerprint"),
            (11, "single_user_schema_reconciliation"),
            (12, "vulnerability_intelligence_store"),
            (13, "vendor_aware_vulnerability_intelligence"),
            (14, "personal_ioc_indicator_store"),
            (15, "vendor_aware_intelligence_identity"),
        ]

        campaign_id = uuid4()
        cursor.execute(
            """INSERT INTO campaigns (id, name, authorized, state, created_at)
               VALUES (%s, %s, TRUE, %s, NOW())""",
            (campaign_id, "gate54-preservation", "ACTIVE"),
        )
    repository.connection.commit()

    repository.initialize()

    with repository.connection.cursor() as cursor:
        cursor.execute("SELECT name FROM campaigns WHERE id=%s", (campaign_id,))
        assert cursor.fetchone() == ("gate54-preservation",)
        cursor.execute("SELECT COUNT(*) FROM threatlens_schema_migrations")
        assert cursor.fetchone()[0] == 15


def test_postgres_initialize_leaves_connection_idle_after_audit_verification(
    postgres_repository,
):
    repository = postgres_repository
    repository.connection.commit()

    repository.initialize()

    assert repository.connection.info.transaction_status.name == "IDLE"


def test_postgres_migration_failure_is_not_recorded_and_can_be_retried(
    postgres_repository,
):
    repository = postgres_repository
    with repository.connection.cursor() as cursor:
        cursor.execute(
            """CREATE TEMP TABLE gate54_migration_probe (
                id INTEGER PRIMARY KEY
            ) ON COMMIT PRESERVE ROWS"""
        )
        cursor.execute(
            """CREATE TEMP TABLE gate54_failure_migrations (
                version INTEGER PRIMARY KEY CHECK (version > 0),
                name TEXT NOT NULL,
                checksum TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            ) ON COMMIT PRESERVE ROWS"""
        )
    repository.connection.commit()

    def fail(_repository):
        with _repository.connection.cursor() as cursor:
            cursor.execute("INSERT INTO gate54_migration_probe (id) VALUES (1)")
        raise RuntimeError("injected migration failure")

    migration = Migration(
        version=1,
        name="failure-retry-test",
        revision="test-revision-1",
        apply=fail,
    )
    with pytest.raises(RuntimeError, match="injected migration failure"):
        run_migrations(repository, (migration,), table_name="gate54_failure_migrations")

    with repository.connection.cursor() as cursor:
        cursor.execute("SELECT COUNT(*) FROM gate54_failure_migrations")
        assert cursor.fetchone()[0] == 0
        cursor.execute("SELECT COUNT(*) FROM gate54_migration_probe")
        assert cursor.fetchone()[0] == 0
    repository.connection.commit()

    def succeed(_repository):
        with _repository.connection.cursor() as cursor:
            cursor.execute("INSERT INTO gate54_migration_probe (id) VALUES (2)")

    run_migrations(
        repository,
        (
            Migration(
                version=1,
                name="failure-retry-test",
                revision="test-revision-1",
                apply=succeed,
            ),
        ),
        table_name="gate54_failure_migrations",
    )
    with repository.connection.cursor() as cursor:
        cursor.execute("SELECT version, name FROM gate54_failure_migrations")
        assert cursor.fetchall() == [(1, "failure-retry-test")]
        cursor.execute("SELECT id FROM gate54_migration_probe")
        assert cursor.fetchall() == [(2,)]
    repository.connection.commit()


def test_postgres_audit_events_reject_update_and_delete(postgres_repository):
    repository = postgres_repository
    event_id = uuid4()
    with repository.connection.cursor() as cursor:
        cursor.execute(
            """INSERT INTO audit_events
                   (id, actor_user_id, action, resource_type, resource_id,
                    outcome, detail, created_at)
               VALUES (%s, NULL, 'GATE55_TEST', 'AUDIT_EVENT', %s,
                       'SUCCESS', 'original', NOW())""",
            (event_id, event_id),
        )
    repository.connection.commit()

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="append-only"):
        with repository.connection.cursor() as cursor:
            cursor.execute(
                "UPDATE audit_events SET detail='tampered' WHERE id=%s",
                (event_id,),
            )
    repository.connection.rollback()

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="append-only"):
        with repository.connection.cursor() as cursor:
            cursor.execute("DELETE FROM audit_events WHERE id=%s", (event_id,))
    repository.connection.rollback()

    with pytest.raises(psycopg.errors.ObjectNotInPrerequisiteState, match="append-only"):
        with repository.connection.cursor() as cursor:
            cursor.execute("TRUNCATE TABLE audit_events")
    repository.connection.rollback()

    with repository.connection.cursor() as cursor:
        cursor.execute("SELECT detail FROM audit_events WHERE id=%s", (event_id,))
        assert cursor.fetchone() == ("original",)
    repository.connection.commit()


def test_postgres_concurrent_initialize_serializes_migrations(postgres_repository):
    dsn = _dsn()
    if not dsn:
        pytest.skip("PostgreSQL integration tests require THREATLENS_TEST_DATABASE_URL")

    def initialize_once():
        repository = PostgresRepository(dsn)
        try:
            repository.initialize()
        finally:
            repository.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(initialize_once) for _ in range(2)]
        for future in futures:
            future.result(timeout=30)

    with postgres_repository.connection.cursor() as cursor:
        cursor.execute(
            "SELECT version, name FROM threatlens_schema_migrations ORDER BY version"
        )
        assert cursor.fetchall() == [
            (1, "legacy_schema_baseline"),
            (2, "audit_events_append_only"),
            (3, "audit_events_no_truncate"),
            (4, "organization_membership_foundation"),
            (5, "campaign_organization_ownership"),
            (6, "asset_organization_ownership"),
            (7, "evidence_organization_ownership"),
            (8, "audit_event_organization_ownership"),
            (9, "single_user_workspace"),
            (10, "service_product_fingerprint"),
            (11, "single_user_schema_reconciliation"),
            (12, "vulnerability_intelligence_store"),
            (13, "vendor_aware_vulnerability_intelligence"),
            (14, "personal_ioc_indicator_store"),
            (15, "vendor_aware_intelligence_identity"),
        ]


def test_service_product_migration_preserves_existing_services(postgres_repository):
    repository = postgres_repository
    asset = Asset(canonical_id="host:192.0.2.140", asset_type="ipv4", value="192.0.2.140")
    service = Service(
        asset_id=asset.id,
        protocol="tcp",
        port=22,
        service_name="ssh",
        version="9.6p1",
        product="OpenSSH",
    )
    repository.save_asset(asset)
    repository.save_service(service)
    with repository.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE services DROP COLUMN product")
        cursor.execute("DELETE FROM threatlens_schema_migrations WHERE version=10")
        cursor.execute("DELETE FROM threatlens_schema_migrations WHERE version=11")
        cursor.execute("DELETE FROM threatlens_schema_migrations WHERE version=12")
        cursor.execute("DELETE FROM threatlens_schema_migrations WHERE version BETWEEN 13 AND 15")
    repository.connection.commit()

    run_migrations(repository)

    with repository.connection.cursor() as cursor:
        cursor.execute(
            "SELECT service_name,version,product FROM services WHERE asset_id=%s",
            (asset.id,),
        )
        assert cursor.fetchone() == ("ssh", "9.6p1", None)
        cursor.execute("SELECT count(*) FROM threatlens_schema_migrations")
        assert cursor.fetchone()[0] == 15


def test_vulnerability_intelligence_store_upserts_with_audit(postgres_repository):
    repository = postgres_repository
    record = normalize_vulnerability_record(
        vulnerability_id="CVE-2026-3456",
        title="Sample advisory",
        severity="HIGH",
        cve="CVE-2026-3456",
        vendor="sample_vendor",
        product="sample_app",
        affected_versions=("1.2.3",),
        cvss=8.1,
        confidence=0.95,
        references=("https://vendor.example/advisory",),
        source="NVD CVE API 2.0",
    )
    event = AuditEvent(
        action="VULNERABILITY_INTELLIGENCE_IMPORTED",
        resource_type="vulnerability_intelligence",
        outcome="SUCCESS",
        detail='{"record_count":1}',
    )

    assert repository.save_vulnerability_intelligence((record,), event) == 1
    result = repository.vulnerability_intelligence_read_model()

    assert result["total"] == 1
    stored = result["items"][0]
    assert stored.cve == "CVE-2026-3456"
    assert stored.vendor == "sample_vendor"
    assert stored.product == "sample_app"
    assert stored.affected_versions == ("1.2.3",)
    assert stored.source == "NVD CVE API 2.0"
    with repository.connection.cursor() as cursor:
        cursor.execute(
            "SELECT action,detail FROM audit_events WHERE id=%s",
            (event.id,),
        )
        assert cursor.fetchone() == ("VULNERABILITY_INTELLIGENCE_IMPORTED", '{"record_count":1}')


def test_vulnerability_intelligence_lookup_requires_exact_product_and_version(
    postgres_repository,
):
    repository = postgres_repository
    records = (
        normalize_vulnerability_record(
            vulnerability_id="CVE-2026-3456",
            title="Affected OpenSSH version",
            severity="HIGH",
            cve="CVE-2026-3456",
            product="OpenSSH",
            affected_versions=("9.6p1",),
            source="NVD CVE API 2.0",
        ),
        normalize_vulnerability_record(
            vulnerability_id="CVE-2026-4567",
            title="Different OpenSSH version",
            severity="MEDIUM",
            cve="CVE-2026-4567",
            product="OpenSSH",
            affected_versions=("9.7p1",),
            source="NVD CVE API 2.0",
        ),
    )
    event = AuditEvent(
        action="VULNERABILITY_INTELLIGENCE_IMPORTED",
        resource_type="vulnerability_intelligence",
        outcome="SUCCESS",
        detail='{"record_count":2}',
    )
    repository.save_vulnerability_intelligence(records, event)

    matches = repository.vulnerability_intelligence_for_service("openssh", "9.6p1")

    assert [record.cve for record in matches] == ["CVE-2026-3456"]
    assert repository.vulnerability_intelligence_for_service("openssh", "9.6") == ()
    assert repository.vulnerability_intelligence_for_service("other", "9.6p1") == ()


def test_vulnerability_intelligence_identity_keeps_distinct_cpe_vendors(
    postgres_repository,
):
    repository = postgres_repository
    records = tuple(
        normalize_vulnerability_record(
            vulnerability_id="CVE-2026-6543",
            title=f"Vendor {vendor} advisory",
            severity="HIGH",
            cve="CVE-2026-6543",
            vendor=vendor,
            product="shared_product",
            affected_versions=("1.0",),
            source="NVD CVE API 2.0",
        )
        for vendor in ("vendor_a", "vendor_b")
    )
    event = AuditEvent(
        action="VULNERABILITY_INTELLIGENCE_IMPORTED",
        resource_type="vulnerability_intelligence",
        outcome="SUCCESS",
        detail='{"record_count":2}',
    )

    assert repository.save_vulnerability_intelligence(records, event) == 2
    result = repository.vulnerability_intelligence_read_model()
    assert {(item.vendor, item.product) for item in result["items"]} == {
        ("vendor_a", "shared_product"),
        ("vendor_b", "shared_product"),
    }


def test_ioc_store_upserts_with_audit_and_returns_canonical_records(postgres_repository):
    repository = postgres_repository
    indicator = normalize_ioc_indicator(
        indicator_type="ipv6",
        value="2001:0DB8::7",
        source="personal-collection",
        confidence=0.9,
        tags=("suspicious",),
    )
    event = AuditEvent(
        action="IOC_INDICATORS_IMPORTED",
        resource_type="ioc_indicators",
        outcome="SUCCESS",
        detail='{"indicator_count":1}',
    )

    assert repository.save_ioc_indicators((indicator,), event) == 1
    result = repository.ioc_indicators_read_model(limit=1, offset=0)
    assert result["total"] == 1
    assert result["items"][0]["value"] == "2001:db8::7"
    assert result["items"][0]["tags"] == ["suspicious"]
    with repository.connection.cursor() as cursor:
        cursor.execute(
            "SELECT action FROM audit_events WHERE id=%s", (event.id,)
        )
        assert cursor.fetchone() == ("IOC_INDICATORS_IMPORTED",)


def test_postgres_initialize_fails_closed_when_audit_trigger_is_disabled(postgres_repository):
    repository = postgres_repository
    with repository.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_truncate")
    repository.connection.commit()

    try:
        with pytest.raises(RuntimeError, match="audit protection trigger is disabled"):
            repository.initialize()
        assert repository.connection.info.transaction_status.name == "IDLE"
    finally:
        with repository.connection.cursor() as cursor:
            cursor.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_truncate")
        repository.connection.commit()

    repository.initialize()


def test_postgres_initialize_fails_closed_when_audit_trigger_is_missing(postgres_repository):
    repository = postgres_repository
    with repository.connection.cursor() as cursor:
        cursor.execute("DROP TRIGGER audit_events_no_truncate ON audit_events")
    repository.connection.commit()

    try:
        with pytest.raises(RuntimeError, match="audit protection trigger is missing"):
            repository.initialize()
        assert repository.connection.info.transaction_status.name == "IDLE"
    finally:
        with repository.connection.cursor() as cursor:
            cursor.execute(
                """CREATE TRIGGER audit_events_no_truncate
                   BEFORE TRUNCATE ON audit_events
                   FOR EACH STATEMENT
                   EXECUTE FUNCTION threatlens_reject_audit_mutation()"""
            )
        repository.connection.commit()

    repository.initialize()

def test_postgres_initialize_fails_closed_when_audit_function_behavior_drifts(
    postgres_repository,
):
    repository = postgres_repository
    with repository.connection.cursor() as cursor:
        # Preserve the old marker strings while weakening behavior: UPDATE/DELETE
        # return NULL and the statement-level TRUNCATE trigger no longer raises.
        cursor.execute(
            """
            CREATE OR REPLACE FUNCTION threatlens_reject_audit_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF TG_OP = 'SELECT' THEN
                    RAISE EXCEPTION 'audit_events is append-only'
                        USING ERRCODE = '55000';
                END IF;
                RETURN NULL;
            END;
            $$
            """
        )
    repository.connection.commit()

    try:
        with pytest.raises(RuntimeError, match="audit protection function drifted"):
            repository.initialize()
        assert repository.connection.info.transaction_status.name == "IDLE"
    finally:
        with repository.connection.cursor() as cursor:
            cursor.execute(
                """
                CREATE OR REPLACE FUNCTION threatlens_reject_audit_mutation()
                RETURNS trigger
                LANGUAGE plpgsql
                AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_events is append-only'
                        USING ERRCODE = '55000';
                END;
                $$
                """
            )
        repository.connection.commit()

    repository.initialize()


def test_single_user_migration_removes_tenant_schema_and_preserves_assessment_rows(
    postgres_repository,
):
    repository = postgres_repository
    campaign_id, asset_id, evidence_id, audit_id = (uuid4() for _ in range(4))
    with repository.connection.transaction():
        with repository.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO campaigns (id,name,authorized,state,created_at) "
                "VALUES (%s,'personal-data',TRUE,'ACTIVE',NOW())",
                (campaign_id,),
            )
            cursor.execute(
                "INSERT INTO assets "
                "(id,canonical_id,asset_type,value,first_seen_at,last_seen_at) "
                "VALUES (%s,'host:192.0.2.123','ipv4','192.0.2.123',NOW(),NOW())",
                (asset_id,),
            )
            cursor.execute(
                "INSERT INTO evidence "
                "(id,kind,content,source,captured_at,sha256,metadata_json) "
                "VALUES (%s,'migration-test','preserve me','test',NOW(),NULL,'{}')",
                (evidence_id,),
            )
            cursor.execute(
                "INSERT INTO audit_events "
                "(id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) "
                "VALUES (%s,NULL,'MIGRATION_TEST','CAMPAIGN',%s,'SUCCESS','preserve me',NOW())",
                (audit_id, campaign_id),
            )
            for table in ("campaigns", "assets", "evidence", "audit_events"):
                cursor.execute(
                    f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS organization_id UUID"
                )
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS organizations (id UUID PRIMARY KEY)"
            )
            cursor.execute(
                "CREATE TABLE IF NOT EXISTS organization_memberships "
                "(organization_id UUID, user_id UUID)"
            )

    with pytest.raises(RuntimeError, match="single-user workspace"):
        _verify_single_user_schema(repository)

    with repository.connection.transaction():
        with repository.connection.cursor() as cursor:
            cursor.execute(
                "DELETE FROM threatlens_schema_migrations WHERE version IN (11, 12, 13, 14, 15)"
            )
    repository.initialize()
    _verify_single_user_schema(repository)

    with repository.connection.cursor() as cursor:
        cursor.execute("SELECT name FROM campaigns WHERE id=%s", (campaign_id,))
        assert cursor.fetchone() == ("personal-data",)
        cursor.execute("SELECT value FROM assets WHERE id=%s", (asset_id,))
        assert cursor.fetchone() == ("192.0.2.123",)
        cursor.execute("SELECT content FROM evidence WHERE id=%s", (evidence_id,))
        assert cursor.fetchone() == ("preserve me",)
        cursor.execute("SELECT detail FROM audit_events WHERE id=%s", (audit_id,))
        assert cursor.fetchone() == ("preserve me",)
        cursor.execute(
            """SELECT count(*) FROM information_schema.columns
               WHERE table_schema=current_schema() AND column_name='organization_id'
                 AND table_name = ANY(%s)""",
            (["campaigns", "assets", "evidence", "audit_events"],),
        )
        assert cursor.fetchone()[0] == 0
        cursor.execute(
            "SELECT to_regclass('organizations'), to_regclass('organization_memberships')"
        )
        assert cursor.fetchone() == (None, None)

