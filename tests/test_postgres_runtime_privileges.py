"""PostgreSQL integration tests for runtime/migration privilege separation."""

from __future__ import annotations

import os
from uuid import uuid4

import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import make_conninfo

from threatlens.storage.postgres import PostgresRepository


def _dsn() -> str:
    return os.getenv("THREATLENS_TEST_DATABASE_URL") or os.getenv(
        "THREATLENS_DATABASE_URL", ""
    )


def _runtime_role(
    repository, *, schema_create=False, inherited_ddl=False, audit_update=False, registry_update=False
):
    connection = repository.connection
    role_name = f"tl_runtime_test_{uuid4().hex[:12]}"
    password = uuid4().hex + uuid4().hex
    owner_role = f"tl_ddl_test_{uuid4().hex[:12]}" if inherited_ddl else None
    with connection.transaction():
        with connection.cursor() as cursor:
            cursor.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(
                    sql.Identifier(role_name), sql.Literal(password)
                )
            )
            cursor.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(
                    sql.Identifier(connection.info.dbname), sql.Identifier(role_name)
                )
            )
            cursor.execute(
                sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(
                    sql.Identifier(role_name)
                )
            )
            cursor.execute(
                sql.SQL(
                    "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}"
                ).format(sql.Identifier(role_name))
            )
            cursor.execute(
                sql.SQL(
                    "REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER "
                    "ON audit_events FROM {}"
                ).format(sql.Identifier(role_name))
            )
            cursor.execute(
                sql.SQL("GRANT SELECT, INSERT ON audit_events TO {}").format(
                    sql.Identifier(role_name)
                )
            )
            cursor.execute(
                sql.SQL(
                    "REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER "
                    "ON threatlens_schema_migrations FROM {}"
                ).format(sql.Identifier(role_name))
            )
            cursor.execute(
                sql.SQL("GRANT SELECT ON threatlens_schema_migrations TO {}").format(
                    sql.Identifier(role_name)
                )
            )
            if audit_update:
                cursor.execute(
                    sql.SQL("GRANT UPDATE ON audit_events TO {}").format(
                        sql.Identifier(role_name)
                    )
                )
            if registry_update:
                cursor.execute(
                    sql.SQL("GRANT UPDATE ON threatlens_schema_migrations TO {}").format(
                        sql.Identifier(role_name)
                    )
                )
            cursor.execute(
                sql.SQL("REVOKE CREATE ON SCHEMA public FROM {}").format(
                    sql.Identifier(role_name)
                )
            )
            if schema_create:
                cursor.execute(
                    sql.SQL("GRANT CREATE ON SCHEMA public TO {}").format(
                        sql.Identifier(role_name)
                    )
                )
            if inherited_ddl:
                cursor.execute(
                    sql.SQL("CREATE ROLE {} NOLOGIN").format(
                        sql.Identifier(owner_role)
                    )
                )
                cursor.execute(
                    sql.SQL("GRANT CREATE ON SCHEMA public TO {}").format(
                        sql.Identifier(owner_role)
                    )
                )
                cursor.execute(
                    sql.SQL("GRANT {} TO {}").format(
                        sql.Identifier(owner_role), sql.Identifier(role_name)
                    )
                )
    dsn = make_conninfo(_dsn(), user=role_name, password=password)
    return role_name, owner_role, dsn


def _drop_roles(repository, role_name, owner_role=None):
    connection = repository.connection
    with connection.transaction():
        with connection.cursor() as cursor:
            if owner_role:
                cursor.execute(
                    sql.SQL("DROP OWNED BY {}").format(sql.Identifier(owner_role))
                )
            cursor.execute(
                sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role_name))
            )
            cursor.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role_name)))
            if owner_role:
                cursor.execute(
                    sql.SQL("DROP ROLE {}").format(sql.Identifier(owner_role))
                )


def test_runtime_schema_readiness_check_is_read_only(postgres_repository):
    repository = postgres_repository

    repository.verify_schema_ready()

    assert repository.schema_migrations_managed is True
    assert repository.connection.info.transaction_status.name == "IDLE"


def test_runtime_role_with_least_privilege_passes_readiness_and_privilege_checks(
    postgres_repository,
):
    admin_repository = postgres_repository
    role_name, owner_role, dsn = _runtime_role(admin_repository)
    runtime_repository = None
    try:
        runtime_repository = PostgresRepository(dsn)
        runtime_repository.verify_schema_ready()
        runtime_repository.verify_runtime_privileges()
        assert runtime_repository.connection.info.transaction_status.name == "IDLE"
    finally:
        if runtime_repository is not None:
            runtime_repository.close()
        _drop_roles(admin_repository, role_name, owner_role)


def test_runtime_role_with_schema_create_privilege_fails_closed(postgres_repository):
    admin_repository = postgres_repository
    role_name, owner_role, dsn = _runtime_role(
        admin_repository, schema_create=True
    )
    runtime_repository = None
    try:
        runtime_repository = PostgresRepository(dsn)
        with pytest.raises(RuntimeError, match="schema CREATE privilege"):
            runtime_repository.verify_runtime_privileges()
    finally:
        if runtime_repository is not None:
            runtime_repository.close()
        _drop_roles(admin_repository, role_name, owner_role)


def test_runtime_role_rejects_inherited_ddl_privilege(postgres_repository):
    admin_repository = postgres_repository
    role_name, owner_role, dsn = _runtime_role(
        admin_repository, inherited_ddl=True
    )
    runtime_repository = None
    try:
        runtime_repository = PostgresRepository(dsn)
        with pytest.raises(RuntimeError, match="schema CREATE privilege"):
            runtime_repository.verify_runtime_privileges()
    finally:
        if runtime_repository is not None:
            runtime_repository.close()
        _drop_roles(admin_repository, role_name, owner_role)



@pytest.mark.parametrize(
    ("privilege_option", "expected_detail"),
    [
        ({"audit_update": True}, "audit-table mutation or trigger privilege"),
        ({"registry_update": True}, "migration-registry mutation privilege"),
    ],
)
def test_runtime_role_with_protected_table_write_privilege_fails_closed(
    postgres_repository, privilege_option, expected_detail
):
    admin_repository = postgres_repository
    role_name, owner_role, dsn = _runtime_role(admin_repository, **privilege_option)
    runtime_repository = None
    try:
        runtime_repository = PostgresRepository(dsn)
        with pytest.raises(RuntimeError, match=expected_detail):
            runtime_repository.verify_runtime_privileges()
    finally:
        if runtime_repository is not None:
            runtime_repository.close()
        _drop_roles(admin_repository, role_name, owner_role)

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
                    sql.SQL(
                        "GRANT SELECT, INSERT, UPDATE, DELETE "
                        "ON ALL TABLES IN SCHEMA public TO {}"
                    ).format(sql.Identifier(role_name))
                )
                cursor.execute(
                    sql.SQL(
                        "REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER "
                        "ON audit_events FROM {}"
                    ).format(sql.Identifier(role_name))
                )
                cursor.execute(
                    sql.SQL(
                        "REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER "
                        "ON threatlens_schema_migrations FROM {}"
                    ).format(sql.Identifier(role_name))
                )
                cursor.execute(
                    sql.SQL(
                        "GRANT SELECT ON threatlens_schema_migrations TO {}"
                    ).format(sql.Identifier(role_name))
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
            "UPDATE audit_events SET detail='tampered' WHERE FALSE",
            "DELETE FROM audit_events WHERE FALSE",
            "TRUNCATE TABLE audit_events",
            "DELETE FROM threatlens_schema_migrations WHERE FALSE",
            """CREATE OR REPLACE FUNCTION threatlens_reject_audit_mutation()
               RETURNS trigger LANGUAGE plpgsql AS $gate58$
               BEGIN RETURN NULL; END; $gate58$""",
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
