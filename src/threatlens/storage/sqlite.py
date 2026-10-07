"""SQLite persistence for the foundational ThreatLens domain."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from uuid import UUID

from threatlens.storage.auth import SQLiteAuthMixin
from threatlens.storage.evidence_validation import SQLiteEvidenceValidationMixin
from threatlens.storage.finding_correlation import SQLiteFindingCorrelationMixin

from threatlens.domain.models import (
    Asset,
    AuditEvent,
    Campaign,
    Evidence,
    Finding,
    LifecycleState,
    Scan,
    Service,
    validate_lifecycle_transition,
)

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    authorized INTEGER NOT NULL CHECK (authorized IN (0, 1)),
    state TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scopes (
    campaign_id TEXT PRIMARY KEY REFERENCES campaigns(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scope_entries (
    campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    value TEXT NOT NULL,
    included INTEGER NOT NULL CHECK (included IN (0, 1)),
    PRIMARY KEY (campaign_id, value, included)
);

CREATE TABLE IF NOT EXISTS scans (
    execution_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
    provider_name TEXT NOT NULL,
    state TEXT NOT NULL,
    queued_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    error TEXT,
    heartbeat_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_campaign_id ON scans(campaign_id);

CREATE TABLE IF NOT EXISTS assets (
    id TEXT PRIMARY KEY,
    canonical_id TEXT NOT NULL UNIQUE,
    asset_type TEXT NOT NULL,
    value TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS services (
    id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    service_name TEXT,
    version TEXT,
    UNIQUE(asset_id, protocol, port)
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    content TEXT NOT NULL,
    source TEXT NOT NULL,
    captured_at TEXT NOT NULL,
    sha256 TEXT,
    metadata_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    asset_id TEXT NOT NULL REFERENCES assets(id),
    state TEXT NOT NULL,
    severity TEXT NOT NULL,
    vulnerability_id TEXT,
    cwe TEXT,
    cve TEXT,
    cvss REAL CHECK (cvss IS NULL OR (cvss >= 0 AND cvss <= 10)),
    confidence REAL NOT NULL CHECK (confidence >= 0 AND confidence <= 1),
    source TEXT NOT NULL,
    detected_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_evidence (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    PRIMARY KEY (finding_id, evidence_id)
);
"""


class SQLiteRepository(SQLiteAuthMixin, SQLiteFindingCorrelationMixin, SQLiteEvidenceValidationMixin):
    """Transactional repository for domain persistence."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._transaction_lock = RLock()
        self.connection = sqlite3.connect(self.path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA journal_mode = WAL")
        self._ensure_scan_heartbeat_column()

    def _ensure_scan_heartbeat_column(self) -> None:
        columns = {row[1] for row in self.connection.execute("PRAGMA table_info(scans)").fetchall()}
        if "heartbeat_at" not in columns:
            self.connection.execute("ALTER TABLE scans ADD COLUMN heartbeat_at TEXT")
            self.connection.commit()

    def close(self) -> None:
        self.connection.close()

    def initialize(self) -> None:
        self.connection.executescript(SCHEMA)
        self.connection.commit()
        self.initialize_finding_correlation()
        self.initialize_evidence_validation()
        self.initialize_auth()

    def save_campaign(self, campaign: Campaign) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO campaigns (id,name,authorized,state,created_at) VALUES (?,?,?,?,?)",
                (
                    str(campaign.id), campaign.name, int(campaign.authorized),
                    campaign.state.value, campaign.created_at.isoformat(),
                ),
            )
            self.connection.execute("INSERT INTO scopes (campaign_id) VALUES (?)", (str(campaign.id),))
            self.connection.executemany(
                "INSERT INTO scope_entries (campaign_id,value,included) VALUES (?,?,?)",
                [(str(campaign.id), value, 1) for value in campaign.scope.include]
                + [(str(campaign.id), value, 0) for value in campaign.scope.exclude],
            )

    def save_scan(self, scan: Scan) -> None:
        with self.connection:
            self.connection.execute(
                """INSERT INTO scans
                   (execution_id,campaign_id,provider_name,state,queued_at,started_at,finished_at,error,heartbeat_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    str(scan.execution_id), str(scan.campaign_id), scan.provider_name,
                    scan.state.value, scan.queued_at.isoformat(),
                    scan.started_at.isoformat() if scan.started_at else None,
                    scan.finished_at.isoformat() if scan.finished_at else None,
                    scan.error, scan.heartbeat_at.isoformat() if scan.heartbeat_at else None,
                ),
            )


    def save_scan_with_audit(self, scan: Scan, event: AuditEvent) -> None:
        with self._transaction_lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                self.connection.execute(
                    """INSERT INTO scans
                       (execution_id,campaign_id,provider_name,state,queued_at,started_at,finished_at,error)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (str(scan.execution_id), str(scan.campaign_id), scan.provider_name, scan.state.value,
                     scan.queued_at.isoformat(), scan.started_at.isoformat() if scan.started_at else None,
                     scan.finished_at.isoformat() if scan.finished_at else None, scan.error),
                )
                self.connection.execute(
                    "INSERT INTO audit_events (id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (str(event.id), str(event.actor_user_id) if event.actor_user_id else None,
                     event.action, event.resource_type, str(event.resource_id) if event.resource_id else None,
                     event.outcome, event.detail, event.created_at.isoformat()),
                )
                self.connection.commit()
            except BaseException:
                self.connection.rollback()
                raise

    def update_scan_state(
        self,
        execution_id: UUID,
        target: LifecycleState,
        error: str | None = None,
    ) -> None:
        with self._transaction_lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                row = self.connection.execute(
                    "SELECT state FROM scans WHERE execution_id = ?", (str(execution_id),)
                ).fetchone()
                if row is None:
                    raise KeyError(str(execution_id))
                current = LifecycleState(row[0])
                validate_lifecycle_transition(current, target)

                now = datetime.now(timezone.utc).isoformat()
                started_at = now if target is LifecycleState.RUNNING else None
                finished_at = now if target in {
                    LifecycleState.COMPLETED,
                    LifecycleState.FAILED,
                    LifecycleState.CANCELLED,
                    LifecycleState.PARTIAL,
                } else None
                self.connection.execute(
                    """UPDATE scans
                       SET state = ?, started_at = COALESCE(?, started_at),
                           finished_at = COALESCE(?, finished_at), error = ?
                       WHERE execution_id = ?""",
                    (target.value, started_at, finished_at, error, str(execution_id)),
                )
                self.connection.commit()
            except BaseException:
                self.connection.rollback()
                raise

    def heartbeat_scan(self, execution_id: UUID) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._transaction_lock:
            cursor = self.connection.execute(
                "UPDATE scans SET heartbeat_at=? WHERE execution_id=? AND state=?",
                (now, str(execution_id), LifecycleState.RUNNING.value),
            )
            self.connection.commit()
            return cursor.rowcount == 1

    def recover_stale_scan(self, execution_id: UUID, stale_after_seconds: float, event: AuditEvent) -> bool:
        cutoff = datetime.now(timezone.utc).timestamp() - stale_after_seconds
        with self._transaction_lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                row = self.connection.execute("SELECT state, heartbeat_at, started_at FROM scans WHERE execution_id=?", (str(execution_id),)).fetchone()
                if row is None:
                    raise KeyError(str(execution_id))
                heartbeat = row["heartbeat_at"] or row["started_at"]
                if row["state"] != LifecycleState.RUNNING.value or not heartbeat or datetime.fromisoformat(heartbeat).timestamp() > cutoff:
                    self.connection.rollback()
                    return False
                now = datetime.now(timezone.utc).isoformat()
                self.connection.execute("UPDATE scans SET state=?, finished_at=?, error=? WHERE execution_id=? AND state=?", (LifecycleState.FAILED.value, now, "execution lease expired; provider execution could not be confirmed alive", str(execution_id), LifecycleState.RUNNING.value))
                self.connection.execute("INSERT INTO audit_events (id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) VALUES (?,?,?,?,?,?,?,?)", (str(event.id), str(event.actor_user_id) if event.actor_user_id else None, event.action, event.resource_type, str(event.resource_id) if event.resource_id else None, event.outcome, event.detail, event.created_at.isoformat()))
                self.connection.commit()
                return True
            except BaseException:
                self.connection.rollback()
                raise

    def scan_state(self, execution_id: UUID) -> LifecycleState:
        with self._transaction_lock:
            row = self.connection.execute(
                "SELECT state FROM scans WHERE execution_id = ?", (str(execution_id),)
            ).fetchone()
        if row is None:
            raise KeyError(str(execution_id))
        return LifecycleState(row[0])

    
    def update_scan_state_if_current(
        self, execution_id: UUID, expected: LifecycleState, target: LifecycleState, error: str | None = None
    ) -> bool:
        validate_lifecycle_transition(expected, target)
        now = datetime.now(timezone.utc).isoformat()
        started_at = now if target is LifecycleState.RUNNING else None
        finished_at = now if target in {LifecycleState.COMPLETED, LifecycleState.FAILED, LifecycleState.CANCELLED, LifecycleState.PARTIAL} else None
        with self._transaction_lock:
            with self.connection:
                cursor = self.connection.execute(
                    """UPDATE scans SET state=?, started_at=COALESCE(?,started_at),
                       finished_at=COALESCE(?,finished_at), error=?
                       WHERE execution_id=? AND state=?""",
                (target.value, started_at, finished_at, error, str(execution_id), expected.value),
            )
            return cursor.rowcount == 1

    def cancel_scan(self, execution_id: UUID) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._transaction_lock:
            with self.connection:
                cursor = self.connection.execute(
                    """UPDATE scans SET state=?, finished_at=?
                       WHERE execution_id=? AND state IN (?,?)""",
                (LifecycleState.CANCELLED.value, now, str(execution_id),
                 LifecycleState.QUEUED.value, LifecycleState.RUNNING.value),
            )
            return cursor.rowcount == 1


    def update_scan_state_if_current_with_audit(
        self, execution_id: UUID, expected: LifecycleState, target: LifecycleState,
        event: AuditEvent, error: str | None = None
    ) -> bool:
        validate_lifecycle_transition(expected, target)
        now = datetime.now(timezone.utc).isoformat()
        started_at = now if target is LifecycleState.RUNNING else None
        finished_at = now if target in {LifecycleState.COMPLETED, LifecycleState.FAILED, LifecycleState.CANCELLED, LifecycleState.PARTIAL} else None
        with self._transaction_lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = self.connection.execute(
                    """UPDATE scans SET state=?, started_at=COALESCE(?,started_at),
                       finished_at=COALESCE(?,finished_at), error=?
                       WHERE execution_id=? AND state=?""",
                    (target.value, started_at, finished_at, error, str(execution_id), expected.value),
                )
                if cursor.rowcount != 1:
                    self.connection.rollback()
                    return False
                self.connection.execute(
                    "INSERT INTO audit_events (id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (str(event.id), str(event.actor_user_id) if event.actor_user_id else None,
                     event.action, event.resource_type, str(event.resource_id) if event.resource_id else None,
                     event.outcome, event.detail, event.created_at.isoformat()),
                )
                self.connection.commit()
                return True
            except BaseException:
                self.connection.rollback()
                raise

    def cancel_scan_with_audit(self, execution_id: UUID, success_event: AuditEvent, noop_event: AuditEvent) -> bool:
        now = datetime.now(timezone.utc).isoformat()
        with self._transaction_lock:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = self.connection.execute(
                    """UPDATE scans SET state=?, finished_at=?
                       WHERE execution_id=? AND state IN (?,?)""",
                    (LifecycleState.CANCELLED.value, now, str(execution_id),
                     LifecycleState.QUEUED.value, LifecycleState.RUNNING.value),
                )
                event = success_event if cursor.rowcount == 1 else noop_event
                self.connection.execute(
                    "INSERT INTO audit_events (id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (str(event.id), str(event.actor_user_id) if event.actor_user_id else None,
                     event.action, event.resource_type, str(event.resource_id) if event.resource_id else None,
                     event.outcome, event.detail, event.created_at.isoformat()),
                )
                self.connection.commit()
                return cursor.rowcount == 1
            except BaseException:
                self.connection.rollback()
                raise

    def save_asset(self, asset: Asset) -> None:
        with self.connection:
            self.connection.execute(
                """INSERT INTO assets (id,canonical_id,asset_type,value,first_seen_at,last_seen_at)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(canonical_id) DO UPDATE SET last_seen_at=excluded.last_seen_at""",
                (
                    str(asset.id), asset.canonical_id, asset.asset_type, asset.value,
                    asset.first_seen_at.isoformat(), asset.last_seen_at.isoformat(),
                ),
            )

    def save_service(self, service: Service) -> None:
        with self.connection:
            self.connection.execute(
                """INSERT INTO services (id,asset_id,protocol,port,service_name,version)
                   VALUES (?,?,?,?,?,?)
                   ON CONFLICT(asset_id,protocol,port) DO UPDATE SET
                     service_name=excluded.service_name, version=excluded.version""",
                (
                    str(service.id), str(service.asset_id), service.protocol, service.port,
                    service.service_name, service.version,
                ),
            )

    def save_evidence(self, evidence: Evidence) -> None:
        with self.connection:
            self.connection.execute(
                """INSERT INTO evidence (id,kind,content,source,captured_at,sha256,metadata_json)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    str(evidence.id), evidence.kind, evidence.content, evidence.source,
                    evidence.captured_at.isoformat(), evidence.sha256,
                    json.dumps(dict(evidence.metadata), sort_keys=True),
                ),
            )

    def save_finding(self, finding: Finding) -> None:
        with self.connection:
            self.connection.execute(
                """INSERT INTO findings
                   (id,title,asset_id,state,severity,vulnerability_id,cwe,cve,cvss,confidence,source,detected_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(finding.id), finding.title, str(finding.asset_id), finding.state.value,
                    finding.severity.value, finding.vulnerability_id, finding.cwe, finding.cve,
                    finding.cvss, finding.confidence, finding.source, finding.detected_at.isoformat(),
                ),
            )
            self.connection.executemany(
                "INSERT INTO finding_evidence (finding_id,evidence_id) VALUES (?,?)",
                [(str(finding.id), str(evidence_id)) for evidence_id in finding.evidence_ids],
            )

    def count(self, table: str) -> int:
        allowed = {"campaigns", "scans", "assets", "services", "evidence", "findings", "finding_evidence", "finding_correlations", "evidence_validations", "users", "auth_sessions", "audit_events"}
        if table not in allowed:
            raise ValueError("unsupported table")
        return int(self.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def asset_id(self, canonical_id: str) -> UUID:
        row = self.connection.execute("SELECT id FROM assets WHERE canonical_id=?", (canonical_id,)).fetchone()
        if row is None:
            raise KeyError(canonical_id)
        return UUID(row[0])
