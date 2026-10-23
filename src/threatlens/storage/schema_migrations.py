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
_LEGACY_DEFAULT_ORGANIZATION_ID = "00000000-0000-4000-8000-000000000001"
_LEGACY_DEFAULT_ORGANIZATION_NAME = "Default Organization"


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


def _organizations_and_memberships(repository: object) -> None:
    """Create the initial tenant and attach existing accounts without data loss."""
    with repository.connection.cursor() as cursor:
        # Older installations may already have recorded the baseline migration
        # before initialize_auth() created these tables. Keep this migration
        # independently responsible for the schema it introduces.
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS organizations (
                   id UUID PRIMARY KEY,
                   name TEXT NOT NULL,
                   slug TEXT NOT NULL UNIQUE,
                   created_at TIMESTAMPTZ NOT NULL
               )"""
        )
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS organization_memberships (
                   organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
                   user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                   role TEXT NOT NULL CHECK (role IN ('ADMIN','ANALYST','VIEWER')),
                   active BOOLEAN NOT NULL,
                   created_at TIMESTAMPTZ NOT NULL,
                   PRIMARY KEY (organization_id, user_id)
               )"""
        )
        cursor.execute(
            """INSERT INTO organizations (id,name,slug,created_at)
               VALUES (%s,%s,'default',NOW())
               ON CONFLICT (id) DO NOTHING""",
            (_LEGACY_DEFAULT_ORGANIZATION_ID, _LEGACY_DEFAULT_ORGANIZATION_NAME),
        )
        cursor.execute(
            "SELECT name,slug FROM organizations WHERE id=%s",
            (_LEGACY_DEFAULT_ORGANIZATION_ID,),
        )
        if cursor.fetchone() != (_LEGACY_DEFAULT_ORGANIZATION_NAME, "default"):
            raise RuntimeError("default organization identity is inconsistent")
        cursor.execute(
            """INSERT INTO organization_memberships
                   (organization_id,user_id,role,active,created_at)
               SELECT %s,id,role,active,created_at FROM users
               ON CONFLICT (organization_id,user_id) DO NOTHING""",
            (_LEGACY_DEFAULT_ORGANIZATION_ID,),
        )


def _campaign_organization_ownership(repository: object) -> None:
    """Assign every campaign to an organization and enforce ownership on writes."""
    with repository.connection.cursor() as cursor:
        cursor.execute(
            "ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS organization_id UUID"
        )
        cursor.execute(
            "UPDATE campaigns SET organization_id=%s WHERE organization_id IS NULL",
            (_LEGACY_DEFAULT_ORGANIZATION_ID,),
        )
        cursor.execute(
            "ALTER TABLE campaigns ALTER COLUMN organization_id SET NOT NULL"
        )
        cursor.execute(
            """DO $$ BEGIN
                   IF NOT EXISTS (
                       SELECT 1 FROM pg_constraint
                       WHERE conname='campaigns_organization_id_fkey'
                         AND conrelid='campaigns'::regclass
                   ) THEN
                       ALTER TABLE campaigns
                           ADD CONSTRAINT campaigns_organization_id_fkey
                           FOREIGN KEY (organization_id) REFERENCES organizations(id)
                           ON DELETE RESTRICT;
                   END IF;
               END $$"""
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS campaigns_organization_created_idx "
            "ON campaigns (organization_id, created_at DESC, id DESC)"
        )


def _asset_organization_ownership(repository: object) -> None:
    """Backfill assets into the default tenant and make canonical identity tenant-local."""
    with repository.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE assets ADD COLUMN IF NOT EXISTS organization_id UUID")
        cursor.execute(
            "UPDATE assets SET organization_id=%s WHERE organization_id IS NULL",
            (_LEGACY_DEFAULT_ORGANIZATION_ID,),
        )
        cursor.execute("ALTER TABLE assets ALTER COLUMN organization_id SET NOT NULL")
        cursor.execute(
            """DO $$ BEGIN
                   IF NOT EXISTS (
                       SELECT 1 FROM pg_constraint
                       WHERE conname='assets_organization_id_fkey'
                         AND conrelid='assets'::regclass
                   ) THEN
                       ALTER TABLE assets
                           ADD CONSTRAINT assets_organization_id_fkey
                           FOREIGN KEY (organization_id) REFERENCES organizations(id)
                           ON DELETE RESTRICT;
                   END IF;
               END $$"""
        )
        cursor.execute(
            """DO $$ DECLARE constraint_name TEXT;
               BEGIN
                   FOR constraint_name IN
                       SELECT conname FROM pg_constraint
                       WHERE conrelid='assets'::regclass AND contype='u'
                         AND pg_get_constraintdef(oid)='UNIQUE (canonical_id)'
                   LOOP
                       EXECUTE format('ALTER TABLE assets DROP CONSTRAINT %I', constraint_name);
                   END LOOP;
               END $$"""
        )
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS assets_organization_canonical_uq "
            "ON assets (organization_id, canonical_id)"
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS assets_organization_last_seen_idx "
            "ON assets (organization_id, last_seen_at DESC, id)"
        )


def _evidence_organization_ownership(repository: object) -> None:
    """Resolve evidence ownership from its scan, then safely backfill legacy leftovers."""
    with repository.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE evidence ADD COLUMN IF NOT EXISTS organization_id UUID")
        cursor.execute(
            """UPDATE evidence AS e
               SET organization_id=c.organization_id
               FROM scans AS s
               JOIN campaigns AS c ON c.id=s.campaign_id
               WHERE e.organization_id IS NULL
                 AND e.metadata_json->>'execution_id'=s.execution_id::TEXT"""
        )
        cursor.execute(
            "UPDATE evidence SET organization_id=%s WHERE organization_id IS NULL",
            (_LEGACY_DEFAULT_ORGANIZATION_ID,),
        )
        cursor.execute("ALTER TABLE evidence ALTER COLUMN organization_id SET NOT NULL")
        cursor.execute(
            """DO $$ BEGIN
                   IF NOT EXISTS (
                       SELECT 1 FROM pg_constraint
                       WHERE conname='evidence_organization_id_fkey'
                         AND conrelid='evidence'::regclass
                   ) THEN
                       ALTER TABLE evidence
                           ADD CONSTRAINT evidence_organization_id_fkey
                           FOREIGN KEY (organization_id) REFERENCES organizations(id)
                           ON DELETE RESTRICT;
                   END IF;
               END $$"""
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS evidence_organization_captured_idx "
            "ON evidence (organization_id, captured_at DESC, id DESC)"
        )


def _audit_event_organization_ownership(repository: object) -> None:
    """Assign durable audit records to their owning organization."""
    with repository.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS organization_id UUID")
        cursor.execute(
            f"""CREATE OR REPLACE FUNCTION threatlens_resolve_audit_organization(
                   event_resource_type TEXT, event_resource_id UUID, event_actor_id UUID
               ) RETURNS UUID
               LANGUAGE plpgsql STABLE AS $$
               DECLARE resolved UUID;
                       membership_count INTEGER;
               BEGIN
                   CASE event_resource_type
                     WHEN 'CAMPAIGN' THEN
                       SELECT organization_id INTO resolved FROM campaigns
                        WHERE id=event_resource_id;
                     WHEN 'CAMPAIGN_REPORT' THEN
                       SELECT organization_id INTO resolved FROM campaigns
                        WHERE id=event_resource_id;
                     WHEN 'SCAN' THEN
                       SELECT c.organization_id INTO resolved FROM scans s
                         JOIN campaigns c ON c.id=s.campaign_id
                        WHERE s.execution_id=event_resource_id;
                     WHEN 'FINDING' THEN
                       SELECT a.organization_id INTO resolved FROM findings f
                         JOIN assets a ON a.id=f.asset_id
                        WHERE f.id=event_resource_id;
                     WHEN 'EVIDENCE_VALIDATION' THEN
                       SELECT e.organization_id INTO resolved FROM evidence_validations v
                         JOIN evidence e ON e.id=v.evidence_id
                        WHERE v.id=event_resource_id;
                     WHEN 'ATTACK_PATH_RELATION' THEN
                       SELECT a.organization_id INTO resolved
                         FROM attack_path_relations r JOIN assets a ON a.id=r.source_asset_id
                        WHERE r.id=event_resource_id;
                     ELSE
                       resolved := NULL;
                   END CASE;
                   IF resolved IS NULL AND event_actor_id IS NOT NULL THEN
                       SELECT count(*) INTO membership_count
                         FROM organization_memberships
                        WHERE user_id=event_actor_id AND active=TRUE;
                       IF membership_count = 1 THEN
                           SELECT organization_id INTO resolved
                             FROM organization_memberships
                            WHERE user_id=event_actor_id AND active=TRUE;
                       END IF;
                   END IF;
                   RETURN COALESCE(resolved, '{_LEGACY_DEFAULT_ORGANIZATION_ID}'::UUID);
               END;
               $$"""
        )
        # The append-only trigger blocks ordinary UPDATE statements. Temporarily
        # remove it inside this transactional migration while legacy rows are tagged.
        cursor.execute("DROP TRIGGER IF EXISTS audit_events_append_only ON audit_events")
        cursor.execute(
            """UPDATE audit_events AS audit_row
               SET organization_id=threatlens_resolve_audit_organization(
                   audit_row.resource_type, audit_row.resource_id, audit_row.actor_user_id
               )
               WHERE organization_id IS NULL"""
        )
        cursor.execute(
            """CREATE TRIGGER audit_events_append_only
               BEFORE UPDATE OR DELETE ON audit_events
               FOR EACH ROW EXECUTE FUNCTION threatlens_reject_audit_mutation()"""
        )
        cursor.execute("ALTER TABLE audit_events ALTER COLUMN organization_id SET NOT NULL")
        cursor.execute(
            """DO $$ BEGIN
                   IF NOT EXISTS (
                       SELECT 1 FROM pg_constraint
                       WHERE conname='audit_events_organization_id_fkey'
                         AND conrelid='audit_events'::regclass
                   ) THEN
                       ALTER TABLE audit_events
                           ADD CONSTRAINT audit_events_organization_id_fkey
                           FOREIGN KEY (organization_id) REFERENCES organizations(id)
                           ON DELETE RESTRICT;
                   END IF;
               END $$"""
        )
        cursor.execute(
            """CREATE OR REPLACE FUNCTION threatlens_assign_audit_organization()
               RETURNS trigger LANGUAGE plpgsql AS $$
               BEGIN
                   NEW.organization_id := threatlens_resolve_audit_organization(
                       NEW.resource_type, NEW.resource_id, NEW.actor_user_id
                   );
                   RETURN NEW;
               END;
               $$"""
        )
        cursor.execute("DROP TRIGGER IF EXISTS audit_events_organization_insert ON audit_events")
        cursor.execute(
            """CREATE TRIGGER audit_events_organization_insert
               BEFORE INSERT ON audit_events
               FOR EACH ROW EXECUTE FUNCTION threatlens_assign_audit_organization()"""
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS audit_events_organization_created_idx "
            "ON audit_events (organization_id, created_at DESC, id DESC)"
        )


def _single_user_workspace(repository: object) -> None:
    """Remove organization isolation while preserving all personal assessment records."""
    with repository.connection.cursor() as cursor:
        cursor.execute("DROP TRIGGER IF EXISTS audit_events_organization_insert ON audit_events")
        cursor.execute("DROP FUNCTION IF EXISTS threatlens_assign_audit_organization()")
        cursor.execute("DROP FUNCTION IF EXISTS threatlens_resolve_audit_organization(TEXT, UUID, UUID)")

        # The per-organization unique index replaced canonical_id's original global
        # uniqueness. Restore that invariant before dropping the tenant index/column.
        cursor.execute(
            """DO $$ BEGIN
                   IF EXISTS (
                       SELECT 1 FROM assets GROUP BY canonical_id HAVING count(*) > 1
                   ) THEN
                       RAISE EXCEPTION 'duplicate asset canonical IDs prevent single-user migration';
                   END IF;
               END $$"""
        )
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS assets_canonical_id_single_user_uq "
            "ON assets (canonical_id)"
        )
        cursor.execute("DROP INDEX IF EXISTS assets_organization_canonical_uq")

        for table in ("campaigns", "assets", "evidence", "audit_events"):
            cursor.execute(f"ALTER TABLE {table} DROP COLUMN IF EXISTS organization_id CASCADE")

        cursor.execute("DROP TABLE IF EXISTS organization_memberships")
        cursor.execute("DROP TABLE IF EXISTS organizations")


def _service_product_fingerprint(repository: object) -> None:
    """Persist detected software products separately from network service names."""
    with repository.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE services ADD COLUMN IF NOT EXISTS product TEXT")


def _vulnerability_intelligence(repository: object) -> None:
    """Create a single-user store for normalized trusted CVE feed records."""
    with repository.connection.cursor() as cursor:
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS vulnerability_intelligence (
                vulnerability_id TEXT NOT NULL,
                product TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL CHECK (
                    severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')
                ),
                cve TEXT,
                cwe TEXT,
                affected_versions JSONB NOT NULL,
                fixed_version TEXT,
                cvss DOUBLE PRECISION CHECK (cvss IS NULL OR (cvss >= 0 AND cvss <= 10)),
                confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
                references_json JSONB NOT NULL,
                source TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (vulnerability_id, product)
            )"""
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS vulnerability_intelligence_cve_idx "
            "ON vulnerability_intelligence (cve)"
        )


def _vendor_aware_intelligence(repository: object) -> None:
    """Persist CPE vendors and permit distinct vendors for one CVE/product."""
    with repository.connection.cursor() as cursor:
        cursor.execute("ALTER TABLE services ADD COLUMN IF NOT EXISTS vendor TEXT")
        cursor.execute(
            "ALTER TABLE vulnerability_intelligence "
            "ADD COLUMN IF NOT EXISTS vendor TEXT NOT NULL DEFAULT ''"
        )


def _ioc_indicators(repository: object) -> None:
    """Create a personal store for passive, normalized IOC values."""
    with repository.connection.cursor() as cursor:
        cursor.execute(
            """CREATE TABLE IF NOT EXISTS ioc_indicators (
                id UUID PRIMARY KEY,
                indicator_type TEXT NOT NULL CHECK (
                    indicator_type IN ('ipv4','ipv6','domain','md5','sha1','sha256')
                ),
                value TEXT NOT NULL CHECK (length(value) <= 512),
                source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 128),
                confidence DOUBLE PRECISION NOT NULL CHECK (
                    confidence >= 0 AND confidence <= 1
                ),
                tags JSONB NOT NULL,
                description TEXT CHECK (description IS NULL OR length(description) <= 512),
                first_seen_at TIMESTAMPTZ NOT NULL,
                last_seen_at TIMESTAMPTZ NOT NULL,
                UNIQUE (indicator_type, value)
            )"""
        )
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS ioc_indicators_type_seen_idx "
            "ON ioc_indicators (indicator_type, last_seen_at DESC)"
        )


def _vendor_aware_intelligence_identity(repository: object) -> None:
    """Allow one CVE/product to retain separate CPE vendors."""
    with repository.connection.cursor() as cursor:
        cursor.execute(
            "ALTER TABLE vulnerability_intelligence "
            "DROP CONSTRAINT IF EXISTS vulnerability_intelligence_pkey"
        )
        cursor.execute(
            "ALTER TABLE vulnerability_intelligence "
            "ADD CONSTRAINT vulnerability_intelligence_pkey "
            "PRIMARY KEY (vulnerability_id, vendor, product)"
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
    Migration(
        version=4,
        name="organization_membership_foundation",
        revision="default-organization-membership-backfill-v1",
        apply=_organizations_and_memberships,
    ),
    Migration(
        version=5,
        name="campaign_organization_ownership",
        revision="campaign-org-backfill-and-index-v1",
        apply=_campaign_organization_ownership,
    ),
    Migration(
        version=6,
        name="asset_organization_ownership",
        revision="asset-org-backfill-and-tenant-canonical-identity-v1",
        apply=_asset_organization_ownership,
    ),
    Migration(
        version=7,
        name="evidence_organization_ownership",
        revision="evidence-org-backfill-and-read-index-v1",
        apply=_evidence_organization_ownership,
    ),
    Migration(
        version=8,
        name="audit_event_organization_ownership",
        revision="audit-event-resource-org-assignment-and-read-index-v1",
        apply=_audit_event_organization_ownership,
    ),
    Migration(
        version=9,
        name="single_user_workspace",
        revision="remove-organization-isolation-preserve-personal-data-v1",
        apply=_single_user_workspace,
    ),
    Migration(
        version=10,
        name="service_product_fingerprint",
        revision="persist-service-product-for-intelligence-correlation-v1",
        apply=_service_product_fingerprint,
    ),
    Migration(
        version=11,
        name="single_user_schema_reconciliation",
        revision="reconcile-legacy-tenant-structures-after-single-user-cutover-v1",
        apply=_single_user_workspace,
    ),
    Migration(
        version=12,
        name="vulnerability_intelligence_store",
        revision="persist-normalized-trusted-cve-feed-records-v1",
        apply=_vulnerability_intelligence,
    ),
    Migration(
        version=13,
        name="vendor_aware_vulnerability_intelligence",
        revision="persist-cpe-vendor-and-use-vendor-aware-intelligence-identity-v1",
        apply=_vendor_aware_intelligence,
    ),
    Migration(
        version=14,
        name="personal_ioc_indicator_store",
        revision="persist-normalized-passive-personal-ioc-indicators-v1",
        apply=_ioc_indicators,
    ),
    Migration(
        version=15,
        name="vendor_aware_intelligence_identity",
        revision="key-vulnerability-intelligence-by-cve-vendor-and-product-v1",
        apply=_vendor_aware_intelligence_identity,
    ),
)



def _verify_audit_protection(repository: object) -> None:
    """Fail closed if the append-only audit protections drift after migration."""
    with repository.connection.cursor() as cursor:
        cursor.execute(
            """SELECT t.tgname, t.tgenabled, t.tgtype,
                      p.proname, p.prosrc, pg_get_functiondef(t.tgfoid)
               FROM pg_trigger t
               JOIN pg_class c ON c.oid = t.tgrelid
               JOIN pg_namespace n ON n.oid = c.relnamespace
               JOIN pg_proc p ON p.oid = t.tgfoid
               WHERE n.nspname = current_schema()
                 AND c.relname = 'audit_events'
                 AND NOT t.tgisinternal
                 AND t.tgname = ANY(%s)""",
            (["audit_events_append_only", "audit_events_no_truncate"],),
        )
        rows = {row[0]: row[1:] for row in cursor.fetchall()}
    # PostgreSQL encodes trigger timing, row/statement level, and event kinds
    # in tgtype. Validate those semantics rather than relying on event text order.
    before_bit = 2
    row_bit = 1
    delete_bit = 8
    update_bit = 16
    truncate_bit = 32
    expected = {
        "audit_events_append_only": {
            "required_bits": before_bit | row_bit | delete_bit | update_bit,
            "forbidden_bits": truncate_bit | 4,
        },
        "audit_events_no_truncate": {
            "required_bits": before_bit | truncate_bit,
            "forbidden_bits": row_bit | delete_bit | update_bit | 4,
        },
    }
    for name, requirements in expected.items():
        row = rows.get(name)
        if row is None:
            raise RuntimeError(f"required audit protection trigger is missing: {name}")
        enabled, trigger_type, function_name, function_source, function_definition = row
        if enabled not in ("O", "A"):
            raise RuntimeError(f"required audit protection trigger is disabled: {name}")
        if (
            trigger_type & requirements["required_bits"]
        ) != requirements["required_bits"] or trigger_type & requirements["forbidden_bits"]:
            raise RuntimeError(f"required audit protection trigger definition drifted: {name}")
        if function_name != "threatlens_reject_audit_mutation":
            raise RuntimeError(f"required audit protection function drifted: {name}")
        normalized_source = " ".join(function_source.lower().split())
        expected_source = (
            "begin raise exception 'audit_events is append-only' "
            "using errcode = '55000'; end;"
        )
        if normalized_source != expected_source:
            raise RuntimeError(f"required audit protection function drifted: {name}")
        normalized_definition = " ".join(function_definition.lower().split())
        if "returns trigger language plpgsql" not in normalized_definition:
            raise RuntimeError(f"required audit protection function drifted: {name}")


def _verify_single_user_schema(repository: object) -> None:
    """Fail startup if removed organization tables or ownership columns reappear."""
    with repository.connection.cursor() as cursor:
        cursor.execute(
            """SELECT to_regclass('organizations'), to_regclass('organization_memberships'),
                      EXISTS (
                          SELECT 1 FROM information_schema.columns
                          WHERE table_schema=current_schema()
                            AND table_name=ANY(%s)
                            AND column_name='organization_id'
                      )""",
            (["campaigns", "assets", "evidence", "audit_events"],),
        )
        organizations, memberships, ownership_columns = cursor.fetchone()
    if organizations is not None or memberships is not None or ownership_columns:
        raise RuntimeError("database schema is not a single-user workspace")


def verify_schema_ready(repository: object) -> None:
    """Verify deployed schema and audit protections without requiring DDL privileges."""
    connection = repository.connection
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                f"SELECT version, name, checksum FROM {REGISTRY_TABLE} ORDER BY version"
            )
            rows = cursor.fetchall()
        expected = [
            (migration.version, migration.name, migration.checksum)
            for migration in MIGRATIONS
        ]
        if rows != expected:
            raise RuntimeError(
                "database schema is not ready for this application; run the controlled "
                "schema migration command with the migration database identity"
            )
        _verify_single_user_schema(repository)
        _verify_audit_protection(repository)
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()
        repository.schema_migrations_managed = True



def verify_runtime_privileges(repository: object) -> None:
    """Reject a runtime identity with effective schema/audit/migration DDL authority."""
    connection = repository.connection
    try:
        with connection.cursor() as cursor:
            cursor.execute(
                """SELECT current_user, session_user,
                          effective_role.rolsuper, login_role.rolsuper,
                          d.datdba, n.nspowner, audit.relowner, registry.relowner,
                          audit_fn.proowner,
                          has_database_privilege(current_user, d.datname, 'CREATE')
                            OR has_database_privilege(session_user, d.datname, 'CREATE'),
                          has_schema_privilege(current_user, n.oid, 'CREATE')
                            OR has_schema_privilege(session_user, n.oid, 'CREATE'),
                          has_table_privilege(current_user, audit.oid, 'UPDATE')
                            OR has_table_privilege(session_user, audit.oid, 'UPDATE'),
                          has_table_privilege(current_user, audit.oid, 'DELETE')
                            OR has_table_privilege(session_user, audit.oid, 'DELETE'),
                          has_table_privilege(current_user, audit.oid, 'TRUNCATE')
                            OR has_table_privilege(session_user, audit.oid, 'TRUNCATE'),
                          has_table_privilege(current_user, audit.oid, 'TRIGGER')
                            OR has_table_privilege(session_user, audit.oid, 'TRIGGER'),
                          has_table_privilege(current_user, registry.oid, 'INSERT')
                            OR has_table_privilege(session_user, registry.oid, 'INSERT'),
                          has_table_privilege(current_user, registry.oid, 'UPDATE')
                            OR has_table_privilege(session_user, registry.oid, 'UPDATE'),
                          has_table_privilege(current_user, registry.oid, 'DELETE')
                            OR has_table_privilege(session_user, registry.oid, 'DELETE'),
                          has_table_privilege(current_user, registry.oid, 'TRUNCATE')
                            OR has_table_privilege(session_user, registry.oid, 'TRUNCATE'),
                          has_table_privilege(current_user, registry.oid, 'TRIGGER')
                            OR has_table_privilege(session_user, registry.oid, 'TRIGGER'),
                          has_table_privilege(current_user, users.oid, 'INSERT')
                            OR has_table_privilege(session_user, users.oid, 'INSERT')
                            OR has_any_column_privilege(current_user, users.oid, 'INSERT')
                            OR has_any_column_privilege(session_user, users.oid, 'INSERT'),
                          has_table_privilege(current_user, users.oid, 'UPDATE')
                            OR has_table_privilege(session_user, users.oid, 'UPDATE')
                            OR has_any_column_privilege(current_user, users.oid, 'UPDATE')
                            OR has_any_column_privilege(session_user, users.oid, 'UPDATE'),
                          has_table_privilege(current_user, users.oid, 'DELETE')
                            OR has_table_privilege(session_user, users.oid, 'DELETE'),
                          current_user::regrole::oid = d.datdba
                            OR session_user::regrole::oid = d.datdba
                            OR pg_has_role(current_user, d.datdba, 'MEMBER')
                            OR pg_has_role(session_user, d.datdba, 'MEMBER'),
                          current_user::regrole::oid = n.nspowner
                            OR session_user::regrole::oid = n.nspowner
                            OR pg_has_role(current_user, n.nspowner, 'MEMBER')
                            OR pg_has_role(session_user, n.nspowner, 'MEMBER'),
                          current_user::regrole::oid = audit.relowner
                            OR session_user::regrole::oid = audit.relowner
                            OR pg_has_role(current_user, audit.relowner, 'MEMBER')
                            OR pg_has_role(session_user, audit.relowner, 'MEMBER'),
                          current_user::regrole::oid = registry.relowner
                            OR session_user::regrole::oid = registry.relowner
                            OR pg_has_role(current_user, registry.relowner, 'MEMBER')
                            OR pg_has_role(session_user, registry.relowner, 'MEMBER'),
                          current_user::regrole::oid = audit_fn.proowner
                            OR session_user::regrole::oid = audit_fn.proowner
                            OR pg_has_role(current_user, audit_fn.proowner, 'MEMBER')
                            OR pg_has_role(session_user, audit_fn.proowner, 'MEMBER'),
                          EXISTS (
                            SELECT 1 FROM pg_class owned_relation
                            WHERE owned_relation.relnamespace = n.oid
                              AND (
                                current_user::regrole::oid = owned_relation.relowner
                                OR session_user::regrole::oid = owned_relation.relowner
                                OR pg_has_role(current_user, owned_relation.relowner, 'MEMBER')
                                OR pg_has_role(session_user, owned_relation.relowner, 'MEMBER')
                              )
                          ),
                          EXISTS (
                            SELECT 1 FROM pg_class privileged_relation
                            WHERE privileged_relation.relnamespace = n.oid
                              AND privileged_relation.relkind IN ('r', 'p')
                              AND (
                                has_table_privilege(
                                    current_user, privileged_relation.oid, 'TRUNCATE'
                                )
                                OR has_table_privilege(
                                    session_user, privileged_relation.oid, 'TRUNCATE'
                                )
                                OR has_table_privilege(
                                    current_user, privileged_relation.oid, 'TRIGGER'
                                )
                                OR has_table_privilege(
                                    session_user, privileged_relation.oid, 'TRIGGER'
                                )
                                OR has_table_privilege(
                                    current_user, privileged_relation.oid, 'REFERENCES'
                                )
                                OR has_table_privilege(
                                    session_user, privileged_relation.oid, 'REFERENCES'
                                )
                              )
                          ),
                          EXISTS (
                            SELECT 1 FROM pg_class privileged_sequence
                            WHERE privileged_sequence.relnamespace = n.oid
                              AND privileged_sequence.relkind = 'S'
                              AND (
                                has_sequence_privilege(
                                    current_user, privileged_sequence.oid, 'SELECT'
                                )
                                OR has_sequence_privilege(
                                    session_user, privileged_sequence.oid, 'SELECT'
                                )
                                OR has_sequence_privilege(
                                    current_user, privileged_sequence.oid, 'USAGE'
                                )
                                OR has_sequence_privilege(
                                    session_user, privileged_sequence.oid, 'USAGE'
                                )
                                OR has_sequence_privilege(
                                    current_user, privileged_sequence.oid, 'UPDATE'
                                )
                                OR has_sequence_privilege(
                                    session_user, privileged_sequence.oid, 'UPDATE'
                                )
                              )
                          ),
                          EXISTS (
                            SELECT 1 FROM pg_proc executable_security_definer
                            WHERE executable_security_definer.pronamespace = n.oid
                              AND executable_security_definer.prosecdef
                              AND (
                                has_function_privilege(
                                    current_user, executable_security_definer.oid, 'EXECUTE'
                                )
                                OR has_function_privilege(
                                    session_user, executable_security_definer.oid, 'EXECUTE'
                                )
                              )
                          ),
                          EXISTS (
                            SELECT 1 FROM pg_proc owned_routine
                            WHERE owned_routine.pronamespace = n.oid
                              AND (
                                current_user::regrole::oid = owned_routine.proowner
                                OR session_user::regrole::oid = owned_routine.proowner
                                OR pg_has_role(current_user, owned_routine.proowner, 'MEMBER')
                                OR pg_has_role(session_user, owned_routine.proowner, 'MEMBER')
                              )
                          ),
                          EXISTS (
                            SELECT 1 FROM pg_type owned_type
                            WHERE owned_type.typnamespace = n.oid
                              AND (
                                current_user::regrole::oid = owned_type.typowner
                                OR session_user::regrole::oid = owned_type.typowner
                                OR pg_has_role(current_user, owned_type.typowner, 'MEMBER')
                                OR pg_has_role(session_user, owned_type.typowner, 'MEMBER')
                              )
                          )
                   FROM pg_database d
                   JOIN pg_namespace n ON n.nspname = current_schema()
                   JOIN pg_class audit
                     ON audit.relnamespace = n.oid AND audit.relname = 'audit_events'
                   JOIN pg_class registry
                     ON registry.relnamespace = n.oid
                    AND registry.relname = 'threatlens_schema_migrations'
                   JOIN pg_class users
                     ON users.relnamespace = n.oid AND users.relname = 'users'
                   JOIN pg_proc audit_fn
                     ON audit_fn.pronamespace = n.oid
                    AND audit_fn.proname = 'threatlens_reject_audit_mutation'
                    AND audit_fn.pronargs = 0
                   JOIN pg_roles effective_role ON effective_role.rolname = current_user
                   JOIN pg_roles login_role ON login_role.rolname = session_user
                   WHERE d.datname = current_database()"""
            )
            row = cursor.fetchone()
        if row is None:
            raise RuntimeError(
                "runtime database privilege verification could not resolve required schema objects"
            )
        (
            _current_user,
            _session_user,
            current_superuser,
            session_superuser,
            _database_owner,
            _schema_owner,
            _audit_owner,
            _registry_owner,
            _function_owner,
            database_create,
            schema_create,
            audit_update,
            audit_delete,
            audit_truncate,
            audit_trigger,
            registry_insert,
            registry_update,
            registry_delete,
            registry_truncate,
            registry_trigger,
            users_insert,
            users_update,
            users_delete,
            database_owner_member,
            schema_owner_member,
            audit_owner_member,
            registry_owner_member,
            function_owner_member,
            owns_schema_relation,
            has_dangerous_relation_privilege,
            has_sequence_privilege,
            can_execute_security_definer_routine,
            owns_schema_routine,
            owns_schema_type,
        ) = row
        violations = []
        if current_superuser or session_superuser:
            violations.append("superuser identity")
        if database_create:
            violations.append("database CREATE privilege")
        if schema_create:
            violations.append("schema CREATE privilege")
        if any((audit_update, audit_delete, audit_truncate, audit_trigger)):
            violations.append("audit-table mutation or trigger privilege")
        if any(
            (registry_insert, registry_update, registry_delete, registry_truncate, registry_trigger)
        ):
            violations.append("migration-registry mutation privilege")
        if any((users_insert, users_update, users_delete)):
            violations.append("user-table mutation privilege")
        if any(
            (
                database_owner_member,
                schema_owner_member,
                audit_owner_member,
                registry_owner_member,
                function_owner_member,
            )
        ):
            violations.append("ownership or membership in an owning role")
        if any((owns_schema_relation, owns_schema_routine, owns_schema_type)):
            violations.append("ownership of application schema objects")
        if has_dangerous_relation_privilege:
            violations.append("TRUNCATE, TRIGGER, or REFERENCES privilege on application tables")
        if has_sequence_privilege:
            violations.append("sequence privilege on application sequences")
        if can_execute_security_definer_routine:
            violations.append("EXECUTE privilege on SECURITY DEFINER routines")
        if violations:
            raise RuntimeError(
                "unsafe PostgreSQL runtime identity: " + ", ".join(violations)
            )
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()

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
        try:
            _verify_audit_protection(repository)
        except BaseException:
            # Catalog verification runs after the migration lock is released and
            # starts a fresh implicit transaction. Roll it back on drift/errors
            # so failed startup never leaves the connection inside a transaction.
            connection.rollback()
            raise
        else:
            # psycopg starts a transaction for the verifier's SELECT queries.
            # Commit it explicitly so callers can safely begin their own outer
            # transaction without turning it into a savepoint and retaining locks.
            connection.commit()
        repository.schema_migrations_managed = True
