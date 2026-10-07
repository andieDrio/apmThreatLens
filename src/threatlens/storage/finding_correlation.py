"""Durable finding correlation for SQLite and PostgreSQL persistence boundaries."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Protocol
from uuid import UUID

from threatlens.domain.models import Finding, FindingState, Severity
from threatlens.providers.correlation import correlation_key, correlate_findings


class CorrelationPersistence(Protocol):
    def persist(self, finding: Finding) -> Finding: ...


class DurableFindingCorrelator:
    """Persist one logical finding per deterministic correlation key.

    The correlator owns only correlation persistence. Raw evidence remains
    immutable and is never rewritten here.
    """

    def __init__(self, repository) -> None:
        self.repository = repository
        self._initialize()

    def persist(self, finding: Finding) -> Finding:
        key = correlation_key(finding)
        existing = self.repository.find_correlated_finding(key)
        if existing is None:
            self.repository.save_finding(finding)
            self.repository.save_correlation(key, finding.id)
            return finding

        merged = correlate_findings((existing, finding))[0]
        self.repository.update_correlated_finding(existing.id, merged)
        self.repository.add_finding_evidence(existing.id, merged.evidence_ids)
        return merged

    def _initialize(self) -> None:
        self.repository.initialize_finding_correlation()


class SQLiteFindingCorrelationMixin:
    """Persistence primitives used by DurableFindingCorrelator."""

    def initialize_finding_correlation(self) -> None:
        with self.connection:
            self.connection.execute(
                """CREATE TABLE IF NOT EXISTS finding_correlations (
                    correlation_key TEXT PRIMARY KEY,
                    finding_id TEXT NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL
                )"""
            )

    def find_correlated_finding(self, correlation_key_value: str) -> Finding | None:
        row = self.connection.execute(
            """SELECT f.id,f.title,f.asset_id,f.state,f.severity,f.vulnerability_id,
                      f.cwe,f.cve,f.cvss,f.confidence,f.source,f.detected_at
               FROM findings f
               JOIN finding_correlations c ON c.finding_id=f.id
               WHERE c.correlation_key=?""",
            (correlation_key_value,),
        ).fetchone()
        if row is None:
            return None
        evidence_rows = self.connection.execute(
            "SELECT evidence_id FROM finding_evidence WHERE finding_id=? ORDER BY evidence_id",
            (row["id"],),
        ).fetchall()
        return Finding(
            id=UUID(row["id"]),
            title=row["title"],
            asset_id=UUID(row["asset_id"]),
            evidence_ids=tuple(UUID(item["evidence_id"]) for item in evidence_rows),
            state=FindingState(row["state"]),
            severity=Severity(row["severity"]),
            vulnerability_id=row["vulnerability_id"],
            cwe=row["cwe"],
            cve=row["cve"],
            cvss=row["cvss"],
            confidence=row["confidence"],
            source=row["source"],
            detected_at=datetime.fromisoformat(row["detected_at"]),
        )

    def save_correlation(self, key: str, finding_id: UUID) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO finding_correlations (correlation_key,finding_id,created_at) VALUES (?,?,?)",
                (key, str(finding_id), datetime.now(timezone.utc).isoformat()),
            )

    def update_correlated_finding(self, finding_id: UUID, finding: Finding) -> None:
        with self.connection:
            self.connection.execute(
                """UPDATE findings SET title=?,state=?,severity=?,vulnerability_id=?,cwe=?,cve=?,
                   cvss=?,confidence=?,source=?,detected_at=? WHERE id=?""",
                (
                    finding.title, finding.state.value, finding.severity.value,
                    finding.vulnerability_id, finding.cwe, finding.cve, finding.cvss,
                    finding.confidence, finding.source, finding.detected_at.isoformat(),
                    str(finding_id),
                ),
            )

    def add_finding_evidence(self, finding_id: UUID, evidence_ids: tuple[UUID, ...]) -> None:
        with self.connection:
            self.connection.executemany(
                "INSERT OR IGNORE INTO finding_evidence (finding_id,evidence_id) VALUES (?,?)",
                [(str(finding_id), str(evidence_id)) for evidence_id in evidence_ids],
            )


class PostgresFindingCorrelationMixin:
    """PostgreSQL equivalents of the durable correlation primitives."""

    def initialize_finding_correlation(self) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS finding_correlations (
                        correlation_key TEXT PRIMARY KEY,
                        finding_id UUID NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
                        created_at TIMESTAMPTZ NOT NULL
                    )"""
                )

    def find_correlated_finding(self, correlation_key_value: str) -> Finding | None:
        with self.connection.cursor() as cursor:
            cursor.execute(
                """SELECT f.id,f.title,f.asset_id,f.state,f.severity,f.vulnerability_id,
                          f.cwe,f.cve,f.cvss,f.confidence,f.source,f.detected_at
                   FROM findings f
                   JOIN finding_correlations c ON c.finding_id=f.id
                   WHERE c.correlation_key=%s""",
                (correlation_key_value,),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            cursor.execute(
                "SELECT evidence_id FROM finding_evidence WHERE finding_id=%s ORDER BY evidence_id",
                (row[0],),
            )
            evidence_rows = cursor.fetchall()
        return Finding(
            id=row[0], title=row[1], asset_id=row[2],
            evidence_ids=tuple(item[0] for item in evidence_rows),
            state=FindingState(row[3]), severity=Severity(row[4]),
            vulnerability_id=row[5], cwe=row[6], cve=row[7], cvss=row[8],
            confidence=row[9], source=row[10], detected_at=row[11],
        )

    def save_correlation(self, key: str, finding_id: UUID) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO finding_correlations (correlation_key,finding_id,created_at) VALUES (%s,%s,%s)",
                    (key, finding_id, datetime.now(timezone.utc)),
                )

    def update_correlated_finding(self, finding_id: UUID, finding: Finding) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """UPDATE findings SET title=%s,state=%s,severity=%s,vulnerability_id=%s,cwe=%s,cve=%s,
                       cvss=%s,confidence=%s,source=%s,detected_at=%s WHERE id=%s""",
                    (
                        finding.title, finding.state.value, finding.severity.value,
                        finding.vulnerability_id, finding.cwe, finding.cve, finding.cvss,
                        finding.confidence, finding.source, finding.detected_at, finding_id,
                    ),
                )

    def add_finding_evidence(self, finding_id: UUID, evidence_ids: tuple[UUID, ...]) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.executemany(
                    "INSERT INTO finding_evidence (finding_id,evidence_id) VALUES (%s,%s) ON CONFLICT DO NOTHING",
                    [(finding_id, evidence_id) for evidence_id in evidence_ids],
                )
