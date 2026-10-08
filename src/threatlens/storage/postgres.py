"""PostgreSQL persistence adapter using the same repository contracts as SQLite."""

from __future__ import annotations

import json
from threading import RLock
from uuid import UUID, uuid4

from threatlens.attack_paths.engine import AttackPathRelation
from threatlens.domain.models import (
    Asset,
    AuditEvent,
    Campaign,
    Evidence,
    Finding,
    FindingState,
    Service,
    validate_finding_remediation_transition,
)
from threatlens.storage.auth import PostgresAuthMixin
from threatlens.storage.evidence_validation import PostgresEvidenceValidationMixin
from threatlens.storage.finding_correlation import PostgresFindingCorrelationMixin
from datetime import UTC

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
    source TEXT NOT NULL, detected_at TIMESTAMPTZ NOT NULL,
    service_id UUID REFERENCES services(id), endpoint TEXT, parameter TEXT, location TEXT
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
CREATE TABLE IF NOT EXISTS attack_path_relations (
    id UUID PRIMARY KEY,
    source_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    target_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    relationship_type TEXT NOT NULL,
    validated BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL,
    validated_at TIMESTAMPTZ,
    validated_by UUID REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS attack_path_relation_evidence (
    relation_id UUID NOT NULL REFERENCES attack_path_relations(id) ON DELETE CASCADE,
    evidence_id UUID NOT NULL REFERENCES evidence(id),
    PRIMARY KEY (relation_id, evidence_id)
);
CREATE TABLE IF NOT EXISTS risk_assessments (
    id UUID PRIMARY KEY,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    level TEXT NOT NULL,
    score DOUBLE PRECISION NOT NULL CHECK (score >= 0 AND score <= 1),
    context_json JSONB NOT NULL,
    factors_json JSONB NOT NULL,
    explanation_json JSONB NOT NULL,
    inputs_used_json JSONB NOT NULL,
    missing_inputs_json JSONB NOT NULL,
    context_source TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
"""


class PostgresRepository(
    PostgresAuthMixin, PostgresFindingCorrelationMixin, PostgresEvidenceValidationMixin
):
    """PostgreSQL implementation of the current persistence boundary."""

    def __init__(self, dsn: str) -> None:
        self._transaction_lock = RLock()
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
        with self.connection.cursor() as cursor:
            cursor.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS heartbeat_at TIMESTAMPTZ")
            cursor.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS service_id UUID REFERENCES services(id)")
            cursor.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS endpoint TEXT")
            cursor.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS parameter TEXT")
            cursor.execute("ALTER TABLE findings ADD COLUMN IF NOT EXISTS location TEXT")
        self.connection.commit()
        self.initialize_finding_correlation()
        self.initialize_evidence_validation()
        self.initialize_auth()

    def save_attack_path_relation_with_audit(
        self, relation: AttackPathRelation, actor_user_id: UUID
    ) -> None:
        """Persist an explicit, initially unvalidated attack-path relationship atomically."""
        if relation.validated:
            raise ValueError("new attack-path relationships must start unvalidated")
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT 1 FROM assets WHERE id=%s OR id=%s",
                        (relation.source_asset_id, relation.target_asset_id),
                    )
                    if cursor.fetchone() is None:
                        raise KeyError("attack-path relation references missing asset")
                    cursor.execute(
                        "SELECT id, content, sha256 FROM evidence WHERE id = ANY(%s)",
                        ([str(item) for item in relation.evidence_ids],),
                    )
                    rows = cursor.fetchall()
                    if len(rows) != len(relation.evidence_ids):
                        raise KeyError("attack-path relation references missing evidence")
                    for _, content, sealed_hash in rows:
                        if not sealed_hash or sealed_hash != __import__("hashlib").sha256(
                            content.encode("utf-8")
                        ).hexdigest():
                            raise ValueError("attack-path relation references unsealed or invalid evidence")
                    cursor.execute(
                        """INSERT INTO attack_path_relations
                           (id,source_asset_id,target_asset_id,relationship_type,validated,created_at)
                           VALUES (%s,%s,%s,%s,FALSE,NOW())""",
                        (
                            relation.id,
                            relation.source_asset_id,
                            relation.target_asset_id,
                            relation.relationship_type.value,
                        ),
                    )
                    cursor.executemany(
                        """INSERT INTO attack_path_relation_evidence (relation_id,evidence_id)
                           VALUES (%s,%s)""",
                        [(relation.id, evidence_id) for evidence_id in relation.evidence_ids],
                    )
                    event = AuditEvent(
                        actor_user_id=actor_user_id,
                        action="ATTACK_PATH_RELATION_CREATED",
                        resource_type="ATTACK_PATH_RELATION",
                        resource_id=relation.id,
                        outcome="SUCCESS",
                        detail=f"validated=false;evidence_count={len(relation.evidence_ids)}",
                    )
                    self._insert_audit_event(cursor, event)

    def validate_attack_path_relation_with_audit(
        self, relation_id: UUID, actor_user_id: UUID
    ) -> bool:
        """Validate a relation only when every referenced evidence item is currently VALIDATED."""
        from hashlib import sha256
        from datetime import datetime, UTC

        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        """SELECT validated FROM attack_path_relations
                           WHERE id=%s FOR UPDATE""",
                        (relation_id,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise KeyError(str(relation_id))
                    if row[0]:
                        event = AuditEvent(
                            actor_user_id=actor_user_id,
                            action="ATTACK_PATH_RELATION_VALIDATED",
                            resource_type="ATTACK_PATH_RELATION",
                            resource_id=relation_id,
                            outcome="NOOP",
                            detail="already validated",
                        )
                        self._insert_audit_event(cursor, event)
                        return False
                    cursor.execute(
                        """SELECT e.id, e.content, e.sha256
                           FROM attack_path_relation_evidence re
                           JOIN evidence e ON e.id = re.evidence_id
                           WHERE re.relation_id=%s
                           ORDER BY e.id""",
                        (relation_id,),
                    )
                    evidence_rows = cursor.fetchall()
                    if not evidence_rows:
                        raise ValueError("attack-path relation must reference evidence")
                    for _, content, sealed_hash in evidence_rows:
                        if not sealed_hash or sealed_hash != sha256(content.encode("utf-8")).hexdigest():
                            raise ValueError("attack-path relation references invalid evidence")
                    evidence_ids = [row[0] for row in evidence_rows]
                    cursor.execute(
                        """SELECT COUNT(*)
                           FROM evidence_validations ev
                           WHERE ev.evidence_id = ANY(%s)
                             AND ev.state = 'VALIDATED'
                             AND NOT EXISTS (
                                 SELECT 1 FROM evidence_validations newer
                                 WHERE newer.supersedes_id = ev.id
                             )""",
                        (evidence_ids,),
                    )
                    if cursor.fetchone()[0] != len(evidence_ids):
                        raise ValueError("all attack-path evidence must have a current VALIDATED decision")
                    validated_at = datetime.now(UTC)
                    cursor.execute(
                        """UPDATE attack_path_relations
                           SET validated=TRUE, validated_at=%s, validated_by=%s
                           WHERE id=%s AND validated=FALSE""",
                        (validated_at, actor_user_id, relation_id),
                    )
                    changed = cursor.rowcount == 1
                    event = AuditEvent(
                        actor_user_id=actor_user_id,
                        action="ATTACK_PATH_RELATION_VALIDATED",
                        resource_type="ATTACK_PATH_RELATION",
                        resource_id=relation_id,
                        outcome="SUCCESS" if changed else "NOOP",
                        detail=f"evidence_count={len(evidence_ids)}",
                    )
                    self._insert_audit_event(cursor, event)
                    return changed

    def save_campaign(self, campaign: Campaign) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO campaigns (id,name,authorized,state,created_at) VALUES (%s,%s,%s,%s,%s)",
                    (
                        campaign.id,
                        campaign.name,
                        campaign.authorized,
                        campaign.state.value,
                        campaign.created_at,
                    ),
                )
                cursor.execute("INSERT INTO scopes (campaign_id) VALUES (%s)", (campaign.id,))
                cursor.executemany(
                    "INSERT INTO scope_entries (campaign_id,value,included) VALUES (%s,%s,%s)",
                    [(campaign.id, value, True) for value in campaign.scope.include]
                    + [(campaign.id, value, False) for value in campaign.scope.exclude],
                )

    def campaign_by_id(self, campaign_id: UUID) -> Campaign:
        from threatlens.domain.models import LifecycleState, Scope

        with self.connection.cursor() as cursor:
            cursor.execute(
                """SELECT c.id, c.name, c.authorized, c.state, c.created_at,
                          COALESCE(
                              array_agg(se.value ORDER BY se.included DESC, se.value)
                              FILTER (WHERE se.included),
                              ARRAY[]::TEXT[]
                          ),
                          COALESCE(
                              array_agg(se.value ORDER BY se.value)
                              FILTER (WHERE NOT se.included),
                              ARRAY[]::TEXT[]
                          )
                   FROM campaigns c
                   LEFT JOIN scope_entries se ON se.campaign_id = c.id
                   WHERE c.id=%s
                   GROUP BY c.id, c.name, c.authorized, c.state, c.created_at""",
                (campaign_id,),
            )
            row = cursor.fetchone()
        if row is None:
            raise KeyError(str(campaign_id))
        return Campaign(
            id=row[0],
            name=row[1],
            authorized=row[2],
            state=LifecycleState(row[3]),
            created_at=row[4],
            scope=Scope(
                include=tuple(row[5] or ()),
                exclude=tuple(row[6] or ()),
            ),
        )

    def save_campaign_with_audit(self, campaign: Campaign, actor_user_id: UUID) -> None:
        from threatlens.domain.models import AuditEvent

        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO campaigns (id,name,authorized,state,created_at) VALUES (%s,%s,%s,%s,%s)",
                        (
                            campaign.id,
                            campaign.name,
                            campaign.authorized,
                            campaign.state.value,
                            campaign.created_at,
                        ),
                    )
                    cursor.execute("INSERT INTO scopes (campaign_id) VALUES (%s)", (campaign.id,))
                    cursor.executemany(
                        "INSERT INTO scope_entries (campaign_id,value,included) VALUES (%s,%s,%s)",
                        [(campaign.id, value, True) for value in campaign.scope.include]
                        + [(campaign.id, value, False) for value in campaign.scope.exclude],
                    )
                    event = AuditEvent(
                        actor_user_id=actor_user_id,
                        action="CAMPAIGN_CREATED",
                        resource_type="CAMPAIGN",
                        resource_id=campaign.id,
                        outcome="SUCCESS",
                        detail=f"authorized=true;include_count={len(campaign.scope.include)};exclude_count={len(campaign.scope.exclude)}",
                    )
                    cursor.execute(
                        "INSERT INTO audit_events (id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        (
                            event.id,
                            event.actor_user_id,
                            event.action,
                            event.resource_type,
                            event.resource_id,
                            event.outcome,
                            event.detail,
                            event.created_at,
                        ),
                    )

    def save_asset(self, asset: Asset) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO assets (id,canonical_id,asset_type,value,first_seen_at,last_seen_at)
                       VALUES (%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (canonical_id) DO UPDATE SET last_seen_at=EXCLUDED.last_seen_at""",
                    (
                        asset.id,
                        asset.canonical_id,
                        asset.asset_type,
                        asset.value,
                        asset.first_seen_at,
                        asset.last_seen_at,
                    ),
                )

    def save_service(self, service: Service) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO services (id,asset_id,protocol,port,service_name,version)
                       VALUES (%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (asset_id,protocol,port) DO UPDATE SET
                         service_name=EXCLUDED.service_name, version=EXCLUDED.version""",
                    (
                        service.id,
                        service.asset_id,
                        service.protocol,
                        service.port,
                        service.service_name,
                        service.version,
                    ),
                )

    def save_evidence(self, evidence: Evidence) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO evidence (id,kind,content,source,captured_at,sha256,metadata_json)
                       VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        evidence.id,
                        evidence.kind,
                        evidence.content,
                        evidence.source,
                        evidence.captured_at,
                        evidence.sha256,
                        json.dumps(dict(evidence.metadata), sort_keys=True),
                    ),
                )

    def save_finding(self, finding: Finding) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """INSERT INTO findings
                       (id,title,asset_id,state,severity,vulnerability_id,cwe,cve,cvss,confidence,source,detected_at,service_id,endpoint,parameter,location)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        finding.id,
                        finding.title,
                        finding.asset_id,
                        finding.state.value,
                        finding.severity.value,
                        finding.vulnerability_id,
                        finding.cwe,
                        finding.cve,
                        finding.cvss,
                        finding.confidence,
                        finding.source,
                        finding.detected_at,
                        finding.service_id,
                        finding.endpoint,
                        finding.parameter,
                        finding.location,
                    ),
                )
                cursor.executemany(
                    "INSERT INTO finding_evidence (finding_id,evidence_id) VALUES (%s,%s)",
                    [(finding.id, evidence_id) for evidence_id in finding.evidence_ids],
                )

    def transition_finding_remediation_with_audit(
        self,
        finding_id: UUID,
        target_state: FindingState,
        actor_user_id: UUID,
        rationale: str,
    ) -> tuple[bool, FindingState, bool]:
        """Atomically apply an authorized remediation state transition and audit it."""
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT state FROM findings WHERE id=%s FOR UPDATE",
                        (finding_id,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise KeyError(str(finding_id))

                    current_state = FindingState(row[0])
                    if current_state is target_state:
                        event = AuditEvent(
                            actor_user_id=actor_user_id,
                            action="FINDING_REMEDIATION",
                            resource_type="FINDING",
                            resource_id=finding_id,
                            outcome="NOOP",
                            detail=f"state={target_state.value};rationale={rationale}",
                        )
                        cursor.execute(
                            "INSERT INTO audit_events "
                            "(id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) "
                            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                            (
                                event.id,
                                event.actor_user_id,
                                event.action,
                                event.resource_type,
                                event.resource_id,
                                event.outcome,
                                event.detail,
                                event.created_at,
                            ),
                        )
                        return False, current_state, True

                    try:
                        validate_finding_remediation_transition(current_state, target_state)
                    except ValueError as exc:
                        event = AuditEvent(
                            actor_user_id=actor_user_id,
                            action="FINDING_REMEDIATION",
                            resource_type="FINDING",
                            resource_id=finding_id,
                            outcome="DENIED",
                            detail=f"current={current_state.value};target={target_state.value};reason={exc}",
                        )
                        cursor.execute(
                            "INSERT INTO audit_events "
                            "(id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) "
                            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                            (
                                event.id,
                                event.actor_user_id,
                                event.action,
                                event.resource_type,
                                event.resource_id,
                                event.outcome,
                                event.detail,
                                event.created_at,
                            ),
                        )
                        return False, current_state, False

                    cursor.execute(
                        "UPDATE findings SET state=%s WHERE id=%s AND state=%s",
                        (target_state.value, finding_id, current_state.value),
                    )
                    if cursor.rowcount != 1:
                        raise RuntimeError("finding remediation compare-and-set failed")

                    event = AuditEvent(
                        actor_user_id=actor_user_id,
                        action="FINDING_REMEDIATION",
                        resource_type="FINDING",
                        resource_id=finding_id,
                        outcome="SUCCESS",
                        detail=f"from={current_state.value};to={target_state.value};rationale={rationale}",
                    )
                    cursor.execute(
                        "INSERT INTO audit_events "
                        "(id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        (
                            event.id,
                            event.actor_user_id,
                            event.action,
                            event.resource_type,
                            event.resource_id,
                            event.outcome,
                            event.detail,
                            event.created_at,
                        ),
                    )
                    return True, target_state, True

    def finding_by_id(self, finding_id: UUID) -> Finding:
        from threatlens.domain.models import FindingState, Severity

        with self.connection.cursor() as cursor:
            cursor.execute(
                """SELECT f.id, f.title, f.asset_id, f.state, f.severity,
                          f.vulnerability_id, f.cwe, f.cve, f.cvss, f.confidence,
                          f.source, f.detected_at, f.service_id, f.endpoint,
                          f.parameter, f.location
                   FROM findings f
                   WHERE f.id=%s""",
                (finding_id,),
            )
            row = cursor.fetchone()
            if row is None:
                raise KeyError(str(finding_id))
            cursor.execute(
                "SELECT evidence_id FROM finding_evidence WHERE finding_id=%s ORDER BY evidence_id",
                (finding_id,),
            )
            evidence_ids = tuple(item[0] for item in cursor.fetchall())

        return Finding(
            id=row[0],
            title=row[1],
            asset_id=row[2],
            evidence_ids=evidence_ids,
            state=FindingState(row[3]),
            severity=Severity(row[4]),
            vulnerability_id=row[5],
            cwe=row[6],
            cve=row[7],
            cvss=row[8],
            confidence=row[9],
            source=row[10],
            detected_at=row[11],
            service_id=row[12],
            endpoint=row[13],
            parameter=row[14],
            location=row[15],
        )

    def save_risk_assessment_with_audit(
        self, assessment, context: dict[str, object], actor_user_id: UUID
    ) -> UUID:
        from datetime import datetime
        from threatlens.domain.models import AuditEvent

        assessment_id = uuid4()
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        """INSERT INTO risk_assessments
                           (id,finding_id,level,score,context_json,factors_json,
                            explanation_json,inputs_used_json,missing_inputs_json,
                            context_source,created_at)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (
                            assessment_id,
                            UUID(assessment.finding_id),
                            assessment.level.value,
                            assessment.score,
                            json.dumps(context, sort_keys=True),
                            json.dumps(
                                [
                                    {
                                        "name": factor.name,
                                        "score": factor.score,
                                        "weight": factor.weight,
                                        "rationale": factor.rationale,
                                        "source": factor.source,
                                    }
                                    for factor in assessment.factors
                                ],
                                sort_keys=True,
                            ),
                            json.dumps(list(assessment.explanation)),
                            json.dumps(list(assessment.inputs_used)),
                            json.dumps(list(assessment.missing_inputs)),
                            assessment.context_source,
                            datetime.now(UTC),
                        ),
                    )
                    event = AuditEvent(
                        actor_user_id=actor_user_id,
                        action="RISK_ASSESSMENT_CREATED",
                        resource_type="FINDING",
                        resource_id=UUID(assessment.finding_id),
                        outcome="SUCCESS",
                        detail=(
                            f"risk_level={assessment.level.value};score={assessment.score:.4f};"
                            f"context_source={assessment.context_source or 'none'}"
                        ),
                    )
                    cursor.execute(
                        "INSERT INTO audit_events "
                        "(id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        (
                            event.id,
                            event.actor_user_id,
                            event.action,
                            event.resource_type,
                            event.resource_id,
                            event.outcome,
                            event.detail,
                            event.created_at,
                        ),
                    )
                    return assessment_id



    def risk_assessments_read_model(
        self, finding_id: UUID, limit: int = 50, offset: int = 0
    ) -> dict[str, object]:
        """Return bounded persisted risk assessments for one canonical finding."""
        if not 1 <= limit <= 100:
            raise ValueError("limit must be within 1..100")
        if offset < 0:
            raise ValueError("offset cannot be negative")
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM risk_assessments WHERE finding_id=%s",
                (finding_id,),
            )
            total = int(cursor.fetchone()[0])
            cursor.execute(
                """SELECT id, finding_id, level, score, context_json, factors_json,
                          explanation_json, inputs_used_json, missing_inputs_json,
                          context_source, created_at
                   FROM risk_assessments
                   WHERE finding_id=%s
                   ORDER BY created_at DESC, id DESC
                   LIMIT %s OFFSET %s""",
                (finding_id, limit, offset),
            )
            rows = cursor.fetchall()
        items = []
        for row in rows:
            factors = []
            for factor in list(row[5] or []):
                normalized = dict(factor)
                normalized["contribution"] = round(
                    float(normalized["score"]) * float(normalized["weight"]), 4
                )
                factors.append(normalized)
            items.append(
                {
                    "assessment_id": str(row[0]),
                    "finding_id": str(row[1]),
                    "level": str(row[2]),
                    "score": float(row[3]),
                    "context": dict(row[4] or {}),
                    "factors": factors,
                    "explanation": list(row[6] or []),
                    "inputs_used": list(row[7] or []),
                    "missing_inputs": list(row[8] or []),
                    "context_source": row[9],
                    "created_at": row[10],
                }
            )
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": items,
        }

    def count(self, table: str) -> int:
        allowed = {
            "campaigns",
            "assets",
            "services",
            "evidence",
            "findings",
            "finding_evidence",
            "scans",
            "finding_correlations",
            "evidence_validations",
            "users",
            "auth_sessions",
            "audit_events",
            "risk_assessments",
        }
        if table not in allowed:
            raise ValueError("unsupported table")
        with self.connection.cursor() as cursor:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            return int(cursor.fetchone()[0])

    def heartbeat_scan(self, execution_id: UUID) -> bool:
        from datetime import datetime

        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE scans SET heartbeat_at=%s WHERE execution_id=%s AND state=%s",
                        (datetime.now(UTC), execution_id, "RUNNING"),
                    )
                    return cursor.rowcount == 1

    def recover_stale_scan(
        self, execution_id: UUID, stale_after_seconds: float, event: AuditEvent
    ) -> bool:
        from datetime import datetime, timedelta

        cutoff = datetime.now(UTC) - timedelta(seconds=stale_after_seconds)
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT state, COALESCE(heartbeat_at, started_at) FROM scans WHERE execution_id=%s FOR UPDATE",
                        (execution_id,),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise KeyError(str(execution_id))
                    if row[0] != "RUNNING" or row[1] is None or row[1] > cutoff:
                        return False
                    cursor.execute(
                        "UPDATE scans SET state=%s, finished_at=%s, error=%s WHERE execution_id=%s AND state=%s",
                        (
                            "FAILED",
                            datetime.now(UTC),
                            "execution lease expired; provider execution could not be confirmed alive",
                            execution_id,
                            "RUNNING",
                        ),
                    )
                    cursor.execute(
                        "INSERT INTO audit_events (id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        (
                            event.id,
                            event.actor_user_id,
                            event.action,
                            event.resource_type,
                            event.resource_id,
                            event.outcome,
                            event.detail,
                            event.created_at,
                        ),
                    )
                    return True

    def scan_state(self, execution_id: UUID):
        from threatlens.domain.models import LifecycleState

        with self._transaction_lock:
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT state FROM scans WHERE execution_id=%s", (execution_id,))
                row = cursor.fetchone()
        if row is None:
            raise KeyError(str(execution_id))
        return LifecycleState(row[0])

    def save_scan_with_audit(self, scan, event: AuditEvent) -> None:
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        """INSERT INTO scans
                           (execution_id,campaign_id,provider_name,state,queued_at,started_at,finished_at,error,heartbeat_at)
                           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (
                            scan.execution_id,
                            scan.campaign_id,
                            scan.provider_name,
                            scan.state.value,
                            scan.queued_at,
                            scan.started_at,
                            scan.finished_at,
                            scan.error,
                            scan.heartbeat_at,
                        ),
                    )
                    cursor.execute(
                        "INSERT INTO audit_events (id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        (
                            event.id,
                            event.actor_user_id,
                            event.action,
                            event.resource_type,
                            event.resource_id,
                            event.outcome,
                            event.detail,
                            event.created_at,
                        ),
                    )

    def update_scan_state(self, execution_id: UUID, target, error: str | None = None) -> None:
        from datetime import datetime
        from threatlens.domain.models import LifecycleState, validate_lifecycle_transition

        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT state FROM scans WHERE execution_id=%s FOR UPDATE", (execution_id,)
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise KeyError(str(execution_id))
                    current = LifecycleState(row[0])
                    validate_lifecycle_transition(current, target)
                    now = datetime.now(UTC)
                    started_at = now if target is LifecycleState.RUNNING else None
                    finished_at = (
                        now
                        if target
                        in {
                            LifecycleState.COMPLETED,
                            LifecycleState.FAILED,
                            LifecycleState.CANCELLED,
                            LifecycleState.PARTIAL,
                        }
                        else None
                    )
                    cursor.execute(
                        """UPDATE scans SET state=%s, started_at=COALESCE(%s,started_at),
                           finished_at=COALESCE(%s,finished_at), error=%s WHERE execution_id=%s""",
                        (target.value, started_at, finished_at, error, execution_id),
                    )

    def update_scan_state_if_current(
        self, execution_id: UUID, expected, target, error: str | None = None
    ) -> bool:
        from datetime import datetime
        from threatlens.domain.models import LifecycleState, validate_lifecycle_transition

        validate_lifecycle_transition(expected, target)
        now = datetime.now(UTC)
        started_at = now if target is LifecycleState.RUNNING else None
        finished_at = (
            now
            if target
            in {
                LifecycleState.COMPLETED,
                LifecycleState.FAILED,
                LifecycleState.CANCELLED,
                LifecycleState.PARTIAL,
            }
            else None
        )
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        """UPDATE scans SET state=%s, started_at=COALESCE(%s,started_at),
                           finished_at=COALESCE(%s,finished_at), error=%s
                           WHERE execution_id=%s AND state=%s""",
                        (
                            target.value,
                            started_at,
                            finished_at,
                            error,
                            execution_id,
                            expected.value,
                        ),
                    )
                    return cursor.rowcount == 1

    def cancel_scan(self, execution_id: UUID) -> bool:
        from datetime import datetime
        from threatlens.domain.models import LifecycleState

        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        """UPDATE scans SET state=%s, finished_at=%s
                           WHERE execution_id=%s AND state IN (%s,%s)""",
                        (
                            LifecycleState.CANCELLED.value,
                            datetime.now(UTC),
                            execution_id,
                            LifecycleState.QUEUED.value,
                            LifecycleState.RUNNING.value,
                        ),
                    )
                    return cursor.rowcount == 1

    def update_scan_state_if_current_with_audit(
        self, execution_id, expected, target, event: AuditEvent, error: str | None = None
    ) -> bool:
        from datetime import datetime
        from threatlens.domain.models import LifecycleState, validate_lifecycle_transition

        validate_lifecycle_transition(expected, target)
        now = datetime.now(UTC)
        started_at = now if target is LifecycleState.RUNNING else None
        finished_at = (
            now
            if target
            in {
                LifecycleState.COMPLETED,
                LifecycleState.FAILED,
                LifecycleState.CANCELLED,
                LifecycleState.PARTIAL,
            }
            else None
        )
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        """UPDATE scans SET state=%s, started_at=COALESCE(%s,started_at),
                           finished_at=COALESCE(%s,finished_at), error=%s
                           WHERE execution_id=%s AND state=%s""",
                        (
                            target.value,
                            started_at,
                            finished_at,
                            error,
                            execution_id,
                            expected.value,
                        ),
                    )
                    if cursor.rowcount != 1:
                        return False
                    cursor.execute(
                        "INSERT INTO audit_events (id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        (
                            event.id,
                            event.actor_user_id,
                            event.action,
                            event.resource_type,
                            event.resource_id,
                            event.outcome,
                            event.detail,
                            event.created_at,
                        ),
                    )
                    return True

    def cancel_scan_with_audit(
        self, execution_id, success_event: AuditEvent, noop_event: AuditEvent
    ) -> bool:
        from datetime import datetime
        from threatlens.domain.models import LifecycleState

        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        """UPDATE scans SET state=%s, finished_at=%s
                           WHERE execution_id=%s AND state IN (%s,%s)""",
                        (
                            LifecycleState.CANCELLED.value,
                            datetime.now(UTC),
                            execution_id,
                            LifecycleState.QUEUED.value,
                            LifecycleState.RUNNING.value,
                        ),
                    )
                    changed = cursor.rowcount == 1
                    event = success_event if changed else noop_event
                    cursor.execute(
                        "INSERT INTO audit_events (id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        (
                            event.id,
                            event.actor_user_id,
                            event.action,
                            event.resource_type,
                            event.resource_id,
                            event.outcome,
                            event.detail,
                            event.created_at,
                        ),
                    )
                    return changed

    def dashboard_summary(self) -> dict[str, object]:
        """Return bounded read-only aggregate data for the authenticated dashboard."""
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM campaigns")
            campaigns = int(cursor.fetchone()[0])
            cursor.execute("SELECT COUNT(*) FROM assets")
            assets = int(cursor.fetchone()[0])
            cursor.execute("SELECT COUNT(*) FROM services")
            services = int(cursor.fetchone()[0])
            cursor.execute("SELECT COUNT(*) FROM findings")
            findings = int(cursor.fetchone()[0])
            cursor.execute(
                "SELECT severity, COUNT(*) FROM findings GROUP BY severity ORDER BY severity"
            )
            findings_by_severity = {
                str(row[0]): int(row[1]) for row in cursor.fetchall()
            }
            cursor.execute(
                "SELECT state, COUNT(*) FROM scans GROUP BY state ORDER BY state"
            )
            scans_by_state = {str(row[0]): int(row[1]) for row in cursor.fetchall()}
        return {
            "campaigns": campaigns,
            "assets": assets,
            "services": services,
            "findings": findings,
            "findings_by_severity": findings_by_severity,
            "scans_by_state": scans_by_state,
        }

    def campaigns_read_model(self, limit: int = 50, offset: int = 0) -> dict[str, object]:
        """Return bounded authorized campaign metadata and explicit scope entries."""
        if not 1 <= limit <= 100:
            raise ValueError("limit must be within 1..100")
        if offset < 0:
            raise ValueError("offset cannot be negative")
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM campaigns")
            total = int(cursor.fetchone()[0])
            cursor.execute(
                """SELECT c.id, c.name, c.authorized, c.state, c.created_at,
                          COALESCE(
                              array_agg(se.value ORDER BY se.included DESC, se.value)
                              FILTER (WHERE se.included),
                              ARRAY[]::TEXT[]
                          ),
                          COALESCE(
                              array_agg(se.value ORDER BY se.value)
                              FILTER (WHERE NOT se.included),
                              ARRAY[]::TEXT[]
                          )
                   FROM campaigns c
                   LEFT JOIN scope_entries se ON se.campaign_id = c.id
                   GROUP BY c.id, c.name, c.authorized, c.state, c.created_at
                   ORDER BY c.created_at DESC, c.id DESC
                   LIMIT %s OFFSET %s""",
                (limit, offset),
            )
            rows = cursor.fetchall()
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "id": str(row[0]),
                    "name": row[1],
                    "authorized": row[2],
                    "state": str(row[3]),
                    "created_at": row[4],
                    "include": list(row[5] or []),
                    "exclude": list(row[6] or []),
                }
                for row in rows
            ],
        }

    def scans_read_model(self, limit: int = 50, offset: int = 0) -> dict[str, object]:
        """Return bounded scan execution state for the authenticated application layer."""
        if not 1 <= limit <= 100:
            raise ValueError("limit must be within 1..100")
        if offset < 0:
            raise ValueError("offset cannot be negative")
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM scans")
            total = int(cursor.fetchone()[0])
            cursor.execute(
                """SELECT s.execution_id, s.campaign_id, c.name, s.provider_name, s.state,
                          s.queued_at, s.started_at, s.finished_at, s.heartbeat_at,
                          LEFT(s.error, 2048)
                   FROM scans s
                   JOIN campaigns c ON c.id = s.campaign_id
                   ORDER BY s.queued_at DESC, s.execution_id DESC
                   LIMIT %s OFFSET %s""",
                (limit, offset),
            )
            rows = cursor.fetchall()
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "execution_id": str(row[0]),
                    "campaign_id": str(row[1]),
                    "campaign_name": row[2],
                    "provider_name": row[3],
                    "state": str(row[4]),
                    "queued_at": row[5],
                    "started_at": row[6],
                    "finished_at": row[7],
                    "heartbeat_at": row[8],
                    "error": row[9],
                }
                for row in rows
            ],
        }

    def evidence_read_model(self, limit: int = 50, offset: int = 0) -> dict[str, object]:
        """Return bounded immutable evidence metadata without exposing raw payloads."""
        if not 1 <= limit <= 100:
            raise ValueError("limit must be within 1..100")
        if offset < 0:
            raise ValueError("offset cannot be negative")
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM evidence")
            total = int(cursor.fetchone()[0])
            cursor.execute(
                """SELECT id, kind, source, captured_at, sha256, metadata_json
                   FROM evidence
                   ORDER BY captured_at DESC, id DESC
                   LIMIT %s OFFSET %s""",
                (limit, offset),
            )
            rows = cursor.fetchall()
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "id": str(row[0]),
                    "kind": row[1],
                    "source": row[2],
                    "captured_at": row[3],
                    "sha256": row[4],
                    "metadata": dict(row[5] or {}),
                }
                for row in rows
            ],
        }

    def findings_read_model(self, limit: int = 50, offset: int = 0) -> dict[str, object]:
        """Return a bounded finding list without exposing raw evidence or arbitrary SQL."""
        if not 1 <= limit <= 100:
            raise ValueError("limit must be within 1..100")
        if offset < 0:
            raise ValueError("offset cannot be negative")
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM findings")
            total = int(cursor.fetchone()[0])
            cursor.execute(
                """SELECT f.id, f.title, f.asset_id, a.canonical_id, f.state, f.severity,
                          f.vulnerability_id, f.cwe, f.cve, f.cvss, f.confidence, f.source,
                          f.detected_at, f.service_id, s.protocol, s.port, s.service_name,
                          s.version, f.endpoint, f.parameter, f.location
                   FROM findings f
                   JOIN assets a ON a.id = f.asset_id
                   LEFT JOIN services s ON s.id = f.service_id
                   ORDER BY f.detected_at DESC, f.id DESC
                   LIMIT %s OFFSET %s""",
                (limit, offset),
            )
            rows = cursor.fetchall()
        items = [
            {
                "id": str(row[0]),
                "title": row[1],
                "asset_id": str(row[2]),
                "asset_canonical_id": row[3],
                "state": str(row[4]),
                "severity": str(row[5]),
                "vulnerability_id": row[6],
                "cwe": row[7],
                "cve": row[8],
                "cvss": row[9],
                "confidence": row[10],
                "source": row[11],
                "detected_at": row[12],
                "service_id": str(row[13]) if row[13] is not None else None,
                "service_protocol": row[14],
                "service_port": row[15],
                "service_name": row[16],
                "service_version": row[17],
                "endpoint": row[18],
                "parameter": row[19],
                "location": row[20],
            }
            for row in rows
        ]
        return {"total": total, "limit": limit, "offset": offset, "items": items}

    def assets_read_model(self, limit: int = 50, offset: int = 0) -> dict[str, object]:
        """Return bounded asset inventory with its observed services."""
        if not 1 <= limit <= 100:
            raise ValueError("limit must be within 1..100")
        if offset < 0:
            raise ValueError("offset cannot be negative")
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM assets")
            total = int(cursor.fetchone()[0])
            cursor.execute(
                """SELECT a.id, a.canonical_id, a.asset_type, a.value,
                          a.first_seen_at, a.last_seen_at,
                          s.id, s.protocol, s.port, s.service_name, s.version
                   FROM (
                       SELECT id, canonical_id, asset_type, value, first_seen_at, last_seen_at
                       FROM assets
                       ORDER BY last_seen_at DESC, id
                       LIMIT %s OFFSET %s
                   ) a
                   LEFT JOIN services s ON s.asset_id = a.id
                   ORDER BY a.last_seen_at DESC, a.id, s.port NULLS LAST, s.id NULLS LAST""",
                (limit, offset),
            )
            rows = cursor.fetchall()
        grouped: dict[UUID, dict[str, object]] = {}
        for row in rows:
            asset_id = row[0]
            item = grouped.setdefault(
                asset_id,
                {
                    "id": str(asset_id),
                    "canonical_id": row[1],
                    "asset_type": row[2],
                    "value": row[3],
                    "first_seen_at": row[4],
                    "last_seen_at": row[5],
                    "services": [],
                },
            )
            if row[6] is not None:
                item["services"].append(
                    {
                        "id": str(row[6]),
                        "protocol": row[7],
                        "port": row[8],
                        "service_name": row[9],
                        "version": row[10],
                    }
                )
        return {
            "total": total,
            "limit": limit,
            "offset": offset,
            "items": list(grouped.values()),
        }

    def asset_id(self, canonical_id: str) -> UUID:
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT id FROM assets WHERE canonical_id=%s", (canonical_id,))
            row = cursor.fetchone()
        if row is None:
            raise KeyError(canonical_id)
        return row[0]
