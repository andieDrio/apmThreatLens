"""PostgreSQL integration-test support; never falls back to SQLite."""
from __future__ import annotations
import os
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
            cursor.execute("TRUNCATE TABLE finding_evidence, finding_correlations, evidence_validations, findings, evidence, services, scans, scope_entries, scopes, campaigns, auth_sessions, audit_events, users CASCADE")
    yield repository
    with repository.connection.transaction():
        with repository.connection.cursor() as cursor:
            cursor.execute("TRUNCATE TABLE finding_evidence, finding_correlations, evidence_validations, findings, evidence, services, scans, scope_entries, scopes, campaigns, auth_sessions, audit_events, users CASCADE")
    repository.close()
