"""PostgreSQL integration tests for runtime/migration privilege separation."""

from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql

from threatlens.storage.postgres import PostgresRepository


def _dsn() -> str:
    return os.getenv("THREATLENS_TEST_DATABASE_URL") or os.getenv(
        "THREATLENS_DATABASE_URL", ""
    )


def test_runtime_schema_readiness_check_is_read_only(postgres_repository):
    repository = postgres_repository

    repository.verify_schema_ready()

    assert repository.schema_migrations_managed is True
    assert repository.connection.info.transaction_status.name == "IDLE"


def test_runtime_role_cannot_alter_audit_protection(postgres_repository):
    """A non-owner runtime role can use the schema but cannot change audit DDL."""
    repository = postgres_repository
    role_name = f"tl_runtime_test_{uuid4().hex[:16]}"
    connection = repository.connection
    role_created = False

    try:
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL("CREATE ROLE {} NOLOGIN").format(sql.Identifier(role_name))
                )
                cursor.execute(
                    sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
                        sql.Identifier(role_name)
                    )
                )
                cursor.execute(
                    sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}").format(
                        sql.Identifier(role_name)
                    )
                )
                cursor.execute(
                    sql.SQL("REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON audit_events FROM {}").format(
                        sql.Identifier(role_name)
                    )
                )
                cursor.execute(
                    sql.SQL("REVOKE CREATE ON SCHEMA public FROM {}").format(
                        sql.Identifier(role_name)
                    )
                )
        role_created = True

        statements = (
            "ALTER TABLE audit_events DISABLE TRIGGER audit_events_no_truncate",
            "DROP TRIGGER audit_events_no_truncate ON audit_events",
            """CREATE OR REPLACE FUNCTION threatlens_reject_audit_mutation()
               RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN RETURN NULL; END; $$""",
        )
        with connection.transaction():
            with connection.cursor() as cursor:
                cursor.execute(
                    sql.SQL("SET LOCAL ROLE {}").format(sql.Identifier(role_name))
                )
            for statement in statements:
                with pytest.raises(psycopg.errors.InsufficientPrivilege):
                    with connection.transaction():
                        with connection.cursor() as cursor:
                            cursor.execute(statement)
    finally:
        connection.rollback()
        if role_created and not connection.closed:
            with connection.transaction():
                with connection.cursor() as cursor:
                    cursor.execute(
                        sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role_name))
                    )
                    cursor.execute(
                        sql.SQL("DROP ROLE {}").format(sql.Identifier(role_name))
                    )

    repository.verify_schema_ready()
