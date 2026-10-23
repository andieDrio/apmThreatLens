"""PostgreSQL integration-test support; never falls back to SQLite."""

from __future__ import annotations
import os

import psycopg
import pytest
from psycopg.conninfo import conninfo_to_dict
from threatlens.storage.postgres import PostgresRepository


@pytest.fixture
def postgres_repository():
    dsn = os.getenv("THREATLENS_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("PostgreSQL integration tests require THREATLENS_TEST_DATABASE_URL")
    if conninfo_to_dict(dsn).get("dbname") != "threatlens_test":
        pytest.fail(
            "PostgreSQL integration tests require the dedicated threatlens_test database; "
            "runtime and development databases are never test targets"
        )
    repository = PostgresRepository(dsn)
    repository.initialize()
    with repository.connection.transaction():
        with repository.connection.cursor() as cursor:
            # Test-only reset: the audit append-only guard must remain enabled in
            # application behavior, but each integration test needs an isolated log.
            cursor.execute(
                "ALTER TABLE audit_events "
                "DISABLE TRIGGER audit_events_no_truncate"
            )
            cursor.execute(
                "TRUNCATE TABLE finding_remediation_idempotency, ioc_indicators, vulnerability_intelligence, finding_evidence, finding_correlations, evidence_validations, risk_assessments, findings, evidence, services, assets, scan_command_idempotency, scan_lifecycle_command_idempotency, scans, scope_entries, scopes, campaigns, auth_login_rate_limits, auth_sessions, audit_events, users CASCADE"
            )
            cursor.execute(
                "ALTER TABLE audit_events "
                "ENABLE TRIGGER audit_events_no_truncate"
            )
    yield repository
    try:
        if not repository.connection.closed:
            repository.close()
    finally:
        with psycopg.connect(dsn) as cleanup_connection:
            with cleanup_connection.cursor() as cursor:
                # This bypass is confined to disposable integration-test cleanup.
                cursor.execute(
                    "ALTER TABLE audit_events "
                    "DISABLE TRIGGER audit_events_no_truncate"
                )
                cursor.execute(
                    "TRUNCATE TABLE ioc_indicators, vulnerability_intelligence, finding_evidence, finding_correlations, evidence_validations, risk_assessments, findings, evidence, services, assets, scan_command_idempotency, scan_lifecycle_command_idempotency, scans, scope_entries, scopes, campaigns, auth_login_rate_limits, auth_sessions, audit_events, users CASCADE"
                )
                cursor.execute(
                    "ALTER TABLE audit_events "
                    "ENABLE TRIGGER audit_events_no_truncate"
                )
