"""PostgreSQL integration tests for versioned schema migrations."""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import psycopg
import pytest

from threatlens.storage.postgres import PostgresRepository
from threatlens.storage.schema_migrations import Migration, run_migrations


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
        assert cursor.fetchone()[0] == 3


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
        ]


def test_postgres_initialize_fails_closed_when_audit_trigger_is_disabled(postgres_repository):
    repository = postgres_repository
    with repository.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_truncate")
    repository.connection.commit()

    try:
        with pytest.raises(RuntimeError, match="audit protection trigger is disabled"):
            repository.initialize()
    finally:
        repository.connection.rollback()
        with repository.connection.cursor() as cursor:
            cursor.execute("ALTER TABLE audit_events ENABLE TRIGGER audit_events_no_truncate")
        repository.connection.commit()

    repository.initialize()
