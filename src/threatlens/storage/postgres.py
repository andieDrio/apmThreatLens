"""PostgreSQL persistence adapter using the same repository contracts as SQLite."""

from __future__ import annotations

import json
from uuid import UUID

from threatlens.domain.models import Asset, Campaign, Evidence, Finding, Service
from threatlens.storage.auth import PostgresAuthMixin
from threatlens.storage.evidence_validation import PostgresEvidenceValidationMixin
from threatlens.storage.finding_correlation import PostgresFindingCorrelationMixin

SCHEMA = """
CREATE TABLE IF NOT EXISTS campaigns (
    id UUID PRIMARY KEY, name TEXT NOT NULL, authorized BOOLEAN NOT NULL,
    state TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS scopes (
    campaign_id UUID PRIMARY KEY REFERENCES campaigns(id) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS scope_entries (
    campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    value TEXT NOT NULL, included BOOLEAN NOT NULL,
    PRIMARY KEY (campaign_id, value, included)
);
CREATE TABLE IF NOT EXISTS assets (
    id UUID PRIMARY KEY, canonical_id TEXT NOT NULL UNIQUE, asset_type TEXT NOT NULL,
    value TEXT NOT NULL, first_seen_at TIMESTAMPTZ NOT NULL, last_seen_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS services (
    id UUID PRIMARY KEY, asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL, port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    service_name TEXT, version TEXT, UNIQUE(asset_id, protocol, port)
);
CREATE TABLE IF NOT EXISTS evidence (
    id UUID PRIMARY KEY, kind TEXT NOT NULL, content TEXT NOT NULL, source TEXT NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL, sha256 TEXT, metadata_json JSONB NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY, title TEXT NOT NULL, asset_id UUID NOT NULL REFERENCES assets(id),
    state TEXT NOT NULL, severity TEXT NOT NULL, vulnerability_id TEXT, cwe TEXT, cve TEXT,
    cvss DOUBLE PRECISION CHECK (cvss IS NULL OR (cvss >= 0 AND cvss <= 10)),
    confidence DOUBLE PRECISION NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    source TEXT NOT NULL, detected_at TIMESTAMPTZ NOT NULL
);
CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id UUID NOT NULL REFERENCES evidence(id), PRIMARY KEY (finding_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS scans (
    execution_id UUID PRIMARY KEY, campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    provider_name TEXT NOT NULL, state TEXT NOT NULL, queued_at TIMESTAMPTZ NOT NULL,
    started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ, error TEXT
);
"""


class PostgresRepository(PostgresAuthMixin, PostgresFindingCorrelationMixin, PostgresEvidenceValidationMixin):
    """PostgreSQL implementation of the current persistence boundary."""

    def __init__(self, dsn: str) -> None:
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise RuntimeError("PostgreSQL support requires the psycopg dependency") from exc
        self.connection = psycopg.connect(dsn)

    def close(self) -> None:
        self.connection.close()

    def initialize(self) -> None:
        with self.connection.cursor() as cursor:
            cursor.execute(SCHEMA)
        self.connection.commit()
        self.initialize_finding_correlation()
        self.initialize_evidence_validation()
        self.initialize_auth()

    def save_campaign(self, campaign: Campaign) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO campaigns (id,name,authorized,state,created_at) VALUES (%s,%s,%s,%s,%s)",
                    (campaign.id, campaign.name, campaign.authorized, campaign.state.value, campaign.created_at),
                )
                cursor.execute("INSERT INTO scopes (campaign_id) VALUES (%s)", (campaign.id,))
                cursor.executemany(
                    "INSERT INTO scope_entries (campaign_id,value,included) VALUES (%s,%s,%s)",
                    [(campaign.id, value, True) for value in campaign.scope.include]
                    + [(campaign.id, value, False) for value in campaign.scope.exclude],
                )

    def save_asset(self, asset: Asset) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO assets (id,canonical_id,asset_type,value,first_seen_at,last_seen_at)
                       VALUES (%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (canonical_id) DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at""",
                    (asset.id, asset.canonical_id, asset.asset_type, asset.value, asset.first_seen_at, asset.last_seen_at),
                )

    def save_service(self, service: Service) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO services (id,asset_id,protocol,port,service_name,version)
                       VALUES (%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (asset_id,protocol,port) DO UPDATE SET
                         service_name=EXCLUDED.service_name, version=EXCLUDED.version""",
                    (service.id, service.asset_id, service.protocol, service.port, service.service_name, service.version),
                )

    def save_evidence(self, evidence: Evidence) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO evidence (id,kind,content,source,captured_at,sha256,metadata_json)
                       VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                    (evidence.id, evidence.kind, evidence.content, evidence.source,
                     evidence.captured_at, evidence.sha256, json.dumps(dict(evidence.metadata), sort_keys=True)),
                )

    def save_finding(self, finding: Finding) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO findings
                       (id,title,asset_id,state,severity,vulnerability_id,cwe,cve,cvss,confidence,source,detected_at)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (finding.id, finding.title, finding.asset_id, finding.state.value, finding.severity.value,
                     finding.vulnerability_id, finding.cwe, finding.cve, finding.cvss, finding.confidence,
                     finding.source, finding.detected_at),
                )
                cursor.executemany(
                    "INSERT INTO finding_evidence (finding_id,evidence_id) VALUES (%s,%s)",
                    [(finding.id, evidence_id) for evidence_id in finding.evidence_ids],
                )

    def count(self, table: str) -> int:
        allowed = {"campaigns", "assets", "services", "evidence", "findings", "finding_evidence", "scans", "finding_correlations", "evidence_validations", "users", "auth_sessions", "audit_events"}
        if table not in allowed:
            raise ValueError("unsupported table")
        with self.connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            return int(cursor.fetchone()[0])

    def asset_id(self, canonical_id: str) -> UUID:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT id FROM assets WHERE canonical_id=%s", (canonical_id,))
            row = cursor.fetchone()
        if row is None:
            raise KeyError(canonical_id)
        return row[0]
