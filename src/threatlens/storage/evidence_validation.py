"""Durable evidence-validation persistence for SQLite and PostgreSQL."""

from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Protocol
from uuid import UUID

from threatlens.evidence.validation import EvidenceValidation, EvidenceValidationState, validate_evidence_transition


class EvidenceValidationPersistence(Protocol):
    def save_evidence_validation(self, validation: EvidenceValidation) -> None: ...

    def transition_evidence_validation(self, previous_id: UUID, replacement: EvidenceValidation) -> None: ...


class SQLiteEvidenceValidationMixin:
    """Append-only evidence validation records with foreign-key traceability."""

    def initialize_evidence_validation(self) -> None:
        with self.connection:
            self.connection.execute(
                """CREATE TABLE IF NOT EXISTS evidence_validations (
                    id TEXT PRIMARY KEY,
                    evidence_id TEXT NOT NULL REFERENCES evidence(id),
                    state TEXT NOT NULL,
                    validator TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    validated_at TEXT NOT NULL,
                    supporting_evidence_ids_json TEXT NOT NULL,
                    supersedes_id TEXT UNIQUE REFERENCES evidence_validations(id)
                )"""
            )

    def save_evidence_validation(self, validation: EvidenceValidation) -> None:
        import json

        evidence_row = self.connection.execute(
            "SELECT content,sha256 FROM evidence WHERE id=?", (str(validation.evidence_id),)
        ).fetchone()
        if evidence_row is None:
            raise KeyError(str(validation.evidence_id))
        if not evidence_row["sha256"] or evidence_row["sha256"] != sha256(evidence_row["content"].encode("utf-8")).hexdigest():
            raise ValueError("target evidence failed integrity validation")
        if validation.state is EvidenceValidationState.SUPERSEDED:
            raise ValueError("superseded validation records must be created by supersede_evidence_validation")
        supporting = [(str(item_id),) for item_id in validation.supporting_evidence_ids]
        if supporting:
            rows = self.connection.execute(
                f"SELECT id FROM evidence WHERE id IN ({','.join('?' for _ in supporting)})",
                [item[0] for item in supporting],
            ).fetchall()
            if len(rows) != len(supporting):
                raise KeyError("validation references missing supporting evidence")
        with self.connection:
            self.connection.execute(
                """INSERT INTO evidence_validations
                   (id,evidence_id,state,validator,rationale,validated_at,supporting_evidence_ids_json,supersedes_id)
                   VALUES (?,?,?,?,?,?,?,NULL)""",
                (str(validation.id), str(validation.evidence_id), validation.state.value,
                 validation.validator, validation.rationale, validation.validated_at.isoformat(),
                 json.dumps([str(item) for item in validation.supporting_evidence_ids], sort_keys=True)),
            )

    def transition_evidence_validation(self, previous_id: UUID, replacement: EvidenceValidation) -> None:
        """Append a new lifecycle state and supersede the previous record atomically."""
        if replacement.state is EvidenceValidationState.SUPERSEDED:
            raise ValueError("use supersede_evidence_validation for SUPERSEDED records")
        row = self.connection.execute(
            "SELECT evidence_id,state FROM evidence_validations WHERE id=?", (str(previous_id),)
        ).fetchone()
        if row is None:
            raise KeyError(str(previous_id))
        current = EvidenceValidationState(row["state"])
        validate_evidence_transition(current, replacement.state)
        if replacement.evidence_id != UUID(row["evidence_id"]):
            raise ValueError("validation transition cannot change evidence identity")
        if replacement.supporting_evidence_ids:
            rows = self.connection.execute(
                "SELECT id FROM evidence WHERE id IN (" + ",".join("?" for _ in replacement.supporting_evidence_ids) + ")",
                [str(item) for item in replacement.supporting_evidence_ids],
            ).fetchall()
            if len(rows) != len(replacement.supporting_evidence_ids):
                raise KeyError("validation references missing supporting evidence")
        import json
        with self.connection:
            self.connection.execute("UPDATE evidence_validations SET state=? WHERE id=?", (replacement.state.value, str(previous_id)))
            self.connection.execute(
                """INSERT INTO evidence_validations
                   (id,evidence_id,state,validator,rationale,validated_at,supporting_evidence_ids_json,supersedes_id)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (str(replacement.id), str(replacement.evidence_id), replacement.state.value,
                 replacement.validator, replacement.rationale, replacement.validated_at.isoformat(),
                 json.dumps([str(item) for item in replacement.supporting_evidence_ids], sort_keys=True), str(previous_id)),
            )

    def supersede_evidence_validation(self, previous_id: UUID, replacement: EvidenceValidation) -> None:
        if replacement.state is not EvidenceValidationState.SUPERSEDED:
            raise ValueError("replacement validation must be SUPERSEDED")
        row = self.connection.execute(
            "SELECT state FROM evidence_validations WHERE id=?", (str(previous_id),)
        ).fetchone()
        if row is None:
            raise KeyError(str(previous_id))
        validate_evidence_transition(EvidenceValidationState(row[0]), EvidenceValidationState.SUPERSEDED)
        with self.connection:
            self.connection.execute(
                "UPDATE evidence_validations SET state=? WHERE id=?",
                (EvidenceValidationState.SUPERSEDED.value, str(previous_id)),
            )
            self.connection.execute(
                """INSERT INTO evidence_validations
                   (id,evidence_id,state,validator,rationale,validated_at,supporting_evidence_ids_json,supersedes_id)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (str(replacement.id), str(replacement.evidence_id), replacement.state.value,
                 replacement.validator, replacement.rationale, replacement.validated_at.isoformat(),
                 json.dumps([str(item) for item in replacement.supporting_evidence_ids], sort_keys=True),
                 str(previous_id)),
            )


class PostgresEvidenceValidationMixin:
    """PostgreSQL equivalent of the append-only validation boundary."""

    def initialize_evidence_validation(self) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    """CREATE TABLE IF NOT EXISTS evidence_validations (
                        id UUID PRIMARY KEY,
                        evidence_id UUID NOT NULL REFERENCES evidence(id),
                        state TEXT NOT NULL,
                        validator TEXT NOT NULL,
                        rationale TEXT NOT NULL,
                        validated_at TIMESTAMPTZ NOT NULL,
                        supporting_evidence_ids_json JSONB NOT NULL,
                        supersedes_id UUID UNIQUE REFERENCES evidence_validations(id)
                    )"""
                )

    def save_evidence_validation(self, validation: EvidenceValidation) -> None:
        import json

        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT 1 FROM evidence WHERE id=%s", (validation.evidence_id,))
                if cursor.fetchone() is None:
                    raise KeyError(str(validation.evidence_id))
                if validation.state is EvidenceValidationState.SUPERSEDED:
                    raise ValueError("superseded validation records must be created by supersede_evidence_validation")
                if validation.supporting_evidence_ids:
                    cursor.execute(
                        "SELECT COUNT(*) FROM evidence WHERE id = ANY(%s)",
                        ([str(item) for item in validation.supporting_evidence_ids],),
                    )
                    if cursor.fetchone()[0] != len(validation.supporting_evidence_ids):
                        raise KeyError("validation references missing supporting evidence")
                cursor.execute(
                    """INSERT INTO evidence_validations
                       (id,evidence_id,state,validator,rationale,validated_at,supporting_evidence_ids_json,supersedes_id)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,NULL)""",
                    (validation.id, validation.evidence_id, validation.state.value, validation.validator,
                     validation.rationale, validation.validated_at,
                     json.dumps([str(item) for item in validation.supporting_evidence_ids], sort_keys=True)),
                )

    def transition_evidence_validation(self, previous_id: UUID, replacement: EvidenceValidation) -> None:
        import json

        if replacement.state is EvidenceValidationState.SUPERSEDED:
            raise ValueError("use supersede_evidence_validation for SUPERSEDED records")
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT state,evidence_id FROM evidence_validations WHERE id=%s", (previous_id,))
                row = cursor.fetchone()
                if row is None:
                    raise KeyError(str(previous_id))
                current = EvidenceValidationState(row[0])
                validate_evidence_transition(current, replacement.state)
                if replacement.evidence_id != row[1]:
                    raise ValueError("validation transition cannot change evidence identity")
                cursor.execute("SELECT content,sha256 FROM evidence WHERE id=%s", (row[1],))
                target = cursor.fetchone()
                if target is None or not target[1] or target[1] != sha256(target[0].encode("utf-8")).hexdigest():
                    raise ValueError("target evidence failed integrity validation")
                if replacement.supporting_evidence_ids:
                    cursor.execute("SELECT id FROM evidence WHERE id = ANY(%s)", ([str(item) for item in replacement.supporting_evidence_ids],))
                    rows = cursor.fetchall()
                    if len(rows) != len(replacement.supporting_evidence_ids):
                        raise KeyError("validation references missing supporting evidence")
                cursor.execute("UPDATE evidence_validations SET state=%s WHERE id=%s", (replacement.state.value, previous_id))
                cursor.execute(
                    """INSERT INTO evidence_validations
                       (id,evidence_id,state,validator,rationale,validated_at,supporting_evidence_ids_json,supersedes_id)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (replacement.id, replacement.evidence_id, replacement.state.value, replacement.validator,
                     replacement.rationale, replacement.validated_at,
                     json.dumps([str(item) for item in replacement.supporting_evidence_ids], sort_keys=True), previous_id),
                )

    def supersede_evidence_validation(self, previous_id: UUID, replacement: EvidenceValidation) -> None:
        import json

        if replacement.state is not EvidenceValidationState.SUPERSEDED:
            raise ValueError("replacement validation must be SUPERSEDED")
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute("SELECT state FROM evidence_validations WHERE id=%s", (previous_id,))
                row = cursor.fetchone()
                if row is None:
                    raise KeyError(str(previous_id))
                validate_evidence_transition(EvidenceValidationState(row[0]), EvidenceValidationState.SUPERSEDED)
                cursor.execute(
                    "UPDATE evidence_validations SET state=%s WHERE id=%s",
                    (EvidenceValidationState.SUPERSEDED.value, previous_id),
                )
                cursor.execute(
                    """INSERT INTO evidence_validations
                       (id,evidence_id,state,validator,rationale,validated_at,supporting_evidence_ids_json,supersedes_id)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (replacement.id, replacement.evidence_id, replacement.state.value, replacement.validator,
                     replacement.rationale, replacement.validated_at,
                     json.dumps([str(item) for item in replacement.supporting_evidence_ids], sort_keys=True),
                     previous_id),
                )
