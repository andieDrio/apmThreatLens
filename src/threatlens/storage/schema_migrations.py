"""Ordered PostgreSQL schema migrations with durable version tracking.

The first migration adopts installations created before schema version tracking.
New migrations must be append-only, ordered, and transactional where supported.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from hashlib import sha256


MIGRATION_LOCK_ID = 1414286419
REGISTRY_TABLE = "threatlens_schema_migrations"


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    revision: str
    apply: Callable[[object], None]
    transactional: bool = True

    @property
    def checksum(self) -> str:
        descriptor = f"{self.version}:{self.name}:{self.revision}"
        return sha256(descriptor.encode("utf-8")).hexdigest()


def _baseline(repository: object) -> None:
    # The legacy initializer commits internally; its DDL is idempotent and retry-safe.
    repository._initialize_legacy_schema()


def _audit_events_append_only(repository: object) -> None:
    """Prevent ordinary SQL UPDATE/DELETE from rewriting durable audit history."""
    with repository.connection.cursor() as cursor:
        cursor.execute(
            """CREATE OR REPLACE FUNCTION threatlens_reject_audit_mutation()
               RETURNS trigger
               LANGUAGE plpgsql
               AS $$
               BEGIN
                   RAISE EXCEPTION 'audit_events is append-only'
                       USING ERRCODE = '55000';
               END;
               $$"""
        )
        cursor.execute(
            """CREATE TRIGGER audit_events_append_only
               BEFORE UPDATE OR DELETE ON audit_events
               FOR EACH ROW
               EXECUTE FUNCTION threatlens_reject_audit_mutation()"""
        )


def _audit_events_no_truncate(repository: object) -> None:
    """Reject TRUNCATE so ordinary table privileges cannot erase the audit trail."""
    with repository.connection.cursor() as cursor:
        cursor.execute(
            """CREATE TRIGGER audit_events_no_truncate
               BEFORE TRUNCATE ON audit_events
               FOR EACH STATEMENT
               EXECUTE FUNCTION threatlens_reject_audit_mutation()"""
        )


MIGRATIONS = (
    Migration(
        version=1,
        name="legacy_schema_baseline",
        revision="baseline-v1-idempotent-existing-schema",
        apply=_baseline,
        transactional=False,
    ),
    Migration(
        version=2,
        name="audit_events_append_only",
        revision="postgresql-trigger-blocks-update-delete-v1",
        apply=_audit_events_append_only,
    ),
    Migration(
        version=3,
        name="audit_events_no_truncate",
        revision="postgresql-trigger-blocks-truncate-v1",
        apply=_audit_events_no_truncate,
    ),
)



def _verify_audit_protection(repository: object) -> None:
    """Fail closed if the append-only audit protections drift after migration."""
    with repository.connection.cursor() as cursor:
        cursor.execute(
            """SELECT t.tgname, t.tgenabled, pg_get_triggerdef(t.oid),
                      pg_get_functiondef(t.tgfoid)
               FROM pg_trigger t
               JOIN pg_class c ON c.oid = t.tgrelid
               JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname = current_schema()
                 AND c.relname = 'audit_events'
                 AND NOT t.tgisinternal
                 AND t.tgname = ANY(%s)""",
            (["audit_events_append_only", "audit_events_no_truncate"],),
        )
        rows = {row[0]: row[1:] for row in cursor.fetchall()}
    expected = {
        "audit_events_append_only": ("BEFORE UPDATE OR DELETE", "FOR EACH ROW"),
        "audit_events_no_truncate": ("BEFORE TRUNCATE", "FOR EACH STATEMENT"),
    }
    for name, fragments in expected.items():
        row = rows.get(name)
        if row is None:
            raise RuntimeError(f"required audit protection trigger is missing: {name}")
        enabled, definition, function_definition = row
        if enabled not in ("O", "A"):
            raise RuntimeError(f"required audit protection trigger is disabled: {name}")
        normalized_definition = " ".join(definition.upper().split())
        if any(fragment not in normalized_definition for fragment in fragments):
            raise RuntimeError(f"required audit protection trigger definition drifted: {name}")
        normalized_function = function_definition.lower()
        if "append-only" not in normalized_function or "55000" not in normalized_function:
            raise RuntimeError(f"required audit protection function drifted: {name}")


def _validate_migrations(migrations: tuple[Migration, ...]) -> None:
    versions = [migration.version for migration in migrations]
    if versions != list(range(1, len(migrations) + 1)):
        raise ValueError("schema migrations must be uniquely ordered from version 1")
    if any(not migration.name or not migration.revision for migration in migrations):
        raise ValueError("schema migrations require stable names and revision descriptors")


def run_migrations(
    repository: object,
    migrations: tuple[Migration, ...] = MIGRATIONS,
    *,
    table_name: str = REGISTRY_TABLE,
) -> None:
    """Apply missing migrations serially and record each successful version.

    A session advisory lock survives commits performed by the legacy baseline.
    New transactional migrations and their version rows commit atomically.
    """
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", table_name):
        raise ValueError("invalid schema migration registry table name")
    _validate_migrations(migrations)
    connection = repository.connection

    with connection.cursor() as cursor:
        cursor.execute("SELECT pg_advisory_lock(%s)", (MIGRATION_LOCK_ID,))
    connection.commit()
    try:
        # The lock must cover registry creation too; otherwise first-start races
        # could collide before the migration serialization boundary is acquired.
        with connection.cursor() as cursor:
            cursor.execute(
                f"""CREATE TABLE IF NOT EXISTS {table_name} (
                    version INTEGER PRIMARY KEY CHECK (version > 0),
                    name TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
                )"""
            )
        connection.commit()

        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT version, name, checksum FROM {table_name} ORDER BY version"
            )
            rows = cursor.fetchall()
        connection.commit()

        known = {migration.version: migration for migration in migrations}
        applied: dict[int, tuple[str, str]] = {
            int(version): (name, checksum) for version, name, checksum in rows
        }
        unknown_versions = sorted(set(applied) - set(known))
        if unknown_versions:
            raise RuntimeError(
                "database schema is newer than this application; "
                f"unknown migration versions: {unknown_versions}"
            )

        for version, (name, checksum) in applied.items():
            migration = known[version]
            if name != migration.name or checksum != migration.checksum:
                raise RuntimeError(
                    f"schema migration {version} identity/checksum mismatch; "
                    "applied migrations must not be edited"
                )

        expected_applied = sorted(applied)
        if expected_applied != list(range(1, len(expected_applied) + 1)):
            raise RuntimeError("schema migration history has a missing version")

        for migration in migrations:
            if migration.version in applied:
                continue
            if migration.transactional:
                with connection.transaction():
                    migration.apply(repository)
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"""INSERT INTO {table_name} (version, name, checksum)
                                VALUES (%s, %s, %s)""",
                            (migration.version, migration.name, migration.checksum),
                        )
            else:
                migration.apply(repository)
                with connection.transaction():
                    with connection.cursor() as cursor:
                        cursor.execute(
                            f"""INSERT INTO {table_name} (version, name, checksum)
                                VALUES (%s, %s, %s)""",
                            (migration.version, migration.name, migration.checksum),
                        )
    finally:
        connection.rollback()
        with connection.cursor() as cursor:
            cursor.execute("SELECT pg_advisory_unlock(%s)", (MIGRATION_LOCK_ID,))
            unlocked = cursor.fetchone()[0]
        connection.commit()
        if not unlocked:
            raise RuntimeError("schema migration advisory lock was not held")
    if table_name == REGISTRY_TABLE and migrations == MIGRATIONS:
        _verify_audit_protection(repository)
        repository.schema_migrations_managed = True
