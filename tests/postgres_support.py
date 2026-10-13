"""PostgreSQL integration-test support; never falls back to SQLite."""

from __future__ import annotations
import os

import psycopg
import pytest
from threatlens.storage.postgres import PostgresRepository


@pytest.fixture
def postgres_repository():
    dsn = os.getenv("THREATLENS_TEST_DATABASE_URL") or os.getenv("THREATLENS_DATABASE_URL")
    if not dsn:
        pytest.skip("PostgreSQL integration tests require THREATLENS_TEST_DATABASE_URL")
    repository = PostgresRepository(dsn)
    repository.initialize()
    with repository.connection.transaction():
        with repository.connection.cursor() as cursor:
            cursor.execute(
                "TRUNCATE TABLE finding_evidence, finding_correlations, evidence_validations, risk_assessments, findings, evidence, services, assets, scan_command_idempotency, scan_lifecycle_command_idempotency, scans, scope_entries, scopes, campaigns, auth_login_rate_limits, auth_sessions, audit_events, users CASCADE"
            )
    yield repository
    try:
        if not repository.connection.closed:
            repository.close()
    finally:
        with psycopg.connect(dsn) as cleanup_connection:
            with cleanup_connection.cursor() as cursor:
                cursor.execute(
                    "TRUNCATE TABLE finding_evidence, finding_correlations, evidence_validations, risk_assessments, findings, evidence, services, assets, scan_command_idempotency, scan_lifecycle_command_idempotency, scans, scope_entries, scopes, campaigns, auth_login_rate_limits, auth_sessions, audit_events, users CASCADE"
                )
