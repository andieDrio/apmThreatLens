"""Durable authentication, session, and audit persistence."""

from __future__ import annotations

from datetime import datetime, UTC
import uuid
from uuid import UUID

from threatlens.domain.models import AuditEvent, User


class SQLiteAuthMixin:
    def initialize_auth(self) -> None:
        with self.connection:
            self.connection.execute("""CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
                role TEXT NOT NULL, active INTEGER NOT NULL CHECK (active IN (0,1)),
                created_at TEXT NOT NULL
            )""")
            self.connection.execute("""CREATE TABLE IF NOT EXISTS auth_sessions (
                id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL CHECK (revoked IN (0,1)), created_at TEXT NOT NULL
            )""")
            self.connection.execute("""CREATE TABLE IF NOT EXISTS audit_events (
                id TEXT PRIMARY KEY, actor_user_id TEXT REFERENCES users(id),
                action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT,
                outcome TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL
            )""")

    def save_user(self, user: User) -> None:
        with self.connection:
            self.connection.execute(
                "INSERT INTO users (id,username,password_hash,role,active,created_at) VALUES (?,?,?,?,?,?)",
                (
                    str(user.id),
                    user.username,
                    user.password_hash,
                    user.role,
                    int(user.active),
                    user.created_at.isoformat(),
                ),
            )

    def save_user_with_audit(self, user: User, event: AuditEvent) -> None:
        """Atomically persist a provisioned user and its success audit event."""
        lock = getattr(self, "_transaction_lock", None)

        def persist() -> None:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO users (id,username,password_hash,role,active,created_at) VALUES (?,?,?,?,?,?)",
                    (
                        str(user.id),
                        user.username,
                        user.password_hash,
                        user.role,
                        int(user.active),
                        user.created_at.isoformat(),
                    ),
                )
                self.connection.execute(
                    "INSERT INTO audit_events "
                    "(id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (
                        str(event.id),
                        str(event.actor_user_id) if event.actor_user_id else None,
                        event.action,
                        event.resource_type,
                        str(event.resource_id) if event.resource_id else None,
                        event.outcome,
                        event.detail,
                        event.created_at.isoformat(),
                    ),
                )

        if lock is None:
            persist()
        else:
            with lock:
                persist()

    def user_by_username(self, username: str):
        row = self.connection.execute(
            "SELECT id,username,password_hash,role,active,created_at FROM users WHERE username=?",
            (username,),
        ).fetchone()
        return (
            None
            if row is None
            else User(
                id=UUID(row["id"]),
                username=row["username"],
                password_hash=row["password_hash"],
                role=row["role"],
                active=bool(row["active"]),
                created_at=datetime.fromisoformat(row["created_at"]),
            )
        )

    def user_by_id(self, user_id: UUID):
        row = self.connection.execute(
            "SELECT id,username,password_hash,role,active,created_at FROM users WHERE id=?",
            (str(user_id),),
        ).fetchone()
        return (
            None
            if row is None
            else User(
                id=UUID(row["id"]),
                username=row["username"],
                password_hash=row["password_hash"],
                role=row["role"],
                active=bool(row["active"]),
                created_at=datetime.fromisoformat(row["created_at"]),
            )
        )

    def create_session(self, user_id: UUID, token_hash: str, expires_at: datetime) -> UUID:
        session_id = uuid.uuid4()
        with self.connection:
            self.connection.execute(
                "INSERT INTO auth_sessions (id,user_id,token_hash,expires_at,revoked,created_at) VALUES (?,?,?,?,?,?)",
                (
                    str(session_id),
                    str(user_id),
                    token_hash,
                    expires_at.isoformat(),
                    0,
                    datetime.now(UTC).isoformat(),
                ),
            )
        return session_id

    def create_session_with_audit(
        self, user_id: UUID, token_hash: str, expires_at: datetime, event: AuditEvent
    ) -> UUID:
        """Atomically persist a login session and its success audit event."""
        session_id = uuid.uuid4()

        def persist() -> None:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO auth_sessions (id,user_id,token_hash,expires_at,revoked,created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (str(session_id), str(user_id), token_hash, expires_at.isoformat(), 0, datetime.now(UTC).isoformat()),
                )
                self.connection.execute(
                    "INSERT INTO audit_events "
                    "(id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (str(event.id), str(event.actor_user_id) if event.actor_user_id else None,
                     event.action, event.resource_type, str(event.resource_id) if event.resource_id else None,
                     event.outcome, event.detail, event.created_at.isoformat()),
                )

        lock = getattr(self, "_transaction_lock", None)
        if lock is None:
            persist()
        else:
            with lock:
                persist()
        return session_id

    def session_by_token_hash(self, token_hash: str):
        row = self.connection.execute(
            "SELECT id,user_id,expires_at,revoked FROM auth_sessions WHERE token_hash=?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "user_id": row["user_id"],
            "expires_at": datetime.fromisoformat(row["expires_at"]),
            "revoked": bool(row["revoked"]),
        }

    def revoke_session(self, session_id: UUID) -> None:
        with self.connection:
            self.connection.execute(
                "UPDATE auth_sessions SET revoked=1 WHERE id=?", (str(session_id),)
            )

    def revoke_session_with_audit(self, session_id: UUID, event: AuditEvent) -> None:
        """Atomically revoke a session and append its successful logout audit event."""

        def persist() -> None:
            with self.connection:
                self.connection.execute(
                    "UPDATE auth_sessions SET revoked=1 WHERE id=?", (str(session_id),)
                )
                self.connection.execute(
                    "INSERT INTO audit_events "
                    "(id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (
                        str(event.id),
                        str(event.actor_user_id) if event.actor_user_id else None,
                        event.action,
                        event.resource_type,
                        str(event.resource_id) if event.resource_id else None,
                        event.outcome,
                        event.detail,
                        event.created_at.isoformat(),
                    ),
                )

        lock = getattr(self, "_transaction_lock", None)
        if lock is None:
            persist()
        else:
            with lock:
                persist()

    def save_audit_event(self, event: AuditEvent) -> None:
        lock = getattr(self, "_transaction_lock", None)
        if lock is None:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO audit_events (id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        str(event.id),
                        str(event.actor_user_id) if event.actor_user_id else None,
                        event.action,
                        event.resource_type,
                        str(event.resource_id) if event.resource_id else None,
                        event.outcome,
                        event.detail,
                        event.created_at.isoformat(),
                    ),
                )
            return
        with lock:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO audit_events (id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (
                        str(event.id),
                        str(event.actor_user_id) if event.actor_user_id else None,
                        event.action,
                        event.resource_type,
                        str(event.resource_id) if event.resource_id else None,
                        event.outcome,
                        event.detail,
                        event.created_at.isoformat(),
                    ),
                )


class PostgresAuthMixin:
    def initialize_auth(self) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute("""CREATE TABLE IF NOT EXISTS users (
                    id UUID PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
                    role TEXT NOT NULL, active BOOLEAN NOT NULL, created_at TIMESTAMPTZ NOT NULL
                )""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS auth_sessions (
                    id UUID PRIMARY KEY, user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL UNIQUE, expires_at TIMESTAMPTZ NOT NULL,
                    revoked BOOLEAN NOT NULL, created_at TIMESTAMPTZ NOT NULL
                )""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS audit_events (
                    id UUID PRIMARY KEY, actor_user_id UUID REFERENCES users(id),
                    action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id UUID,
                    outcome TEXT NOT NULL, detail TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL
                )""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS scan_command_idempotency (
                    actor_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    idempotency_key TEXT NOT NULL
                        CHECK (length(idempotency_key) BETWEEN 16 AND 128),
                    request_hash CHAR(64) NOT NULL,
                    execution_id UUID NOT NULL UNIQUE
                        REFERENCES scans(execution_id) ON DELETE CASCADE,
                    created_at TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (actor_user_id, idempotency_key)
                )""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS auth_login_rate_limits (
                    bucket_key TEXT PRIMARY KEY,
                    window_started_at TIMESTAMPTZ NOT NULL,
                    attempts INTEGER NOT NULL CHECK (attempts > 0)
                )""")
                cursor.execute("""CREATE TABLE IF NOT EXISTS scan_lifecycle_command_idempotency (
                    actor_user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    idempotency_key TEXT NOT NULL
                        CHECK (length(idempotency_key) BETWEEN 16 AND 128),
                    action TEXT NOT NULL CHECK (action IN ('CANCEL', 'RECOVER_STALE')),
                    request_hash CHAR(64) NOT NULL,
                    execution_id UUID NOT NULL REFERENCES scans(execution_id) ON DELETE CASCADE,
                    changed BOOLEAN NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL,
                    PRIMARY KEY (actor_user_id, idempotency_key)
                )""")
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_audit_events_created_id "
                    "ON audit_events (created_at DESC, id DESC)"
                )
                cursor.execute(
                    "CREATE INDEX IF NOT EXISTS idx_auth_login_rate_limits_window "
                    "ON auth_login_rate_limits (window_started_at)"
                )

    def record_login_attempts(
        self,
        bucket_keys: tuple[str, ...],
        now: datetime,
        window_seconds: int = 60,
        audit_limits: dict[str, tuple[int, str]] | None = None,
    ) -> dict[str, tuple[int, datetime]]:
        """Atomically increment login buckets and audit threshold crossings."""
        if not bucket_keys or len(bucket_keys) > 4:
            raise ValueError("one to four login rate-limit buckets are required")
        if not 30 <= window_seconds <= 300:
            raise ValueError("login rate-limit window must be within 30..300 seconds")
        if any(not key or len(key) > 128 or any(ch.isspace() for ch in key) for key in bucket_keys):
            raise ValueError("invalid login rate-limit bucket key")
        if audit_limits is not None:
            if not set(audit_limits).issubset(set(bucket_keys)):
                raise ValueError("audit thresholds must reference configured login buckets")
            if any(limit < 1 or not detail for limit, detail in audit_limits.values()):
                raise ValueError("login audit thresholds require positive limits and details")
        result: dict[str, tuple[int, datetime]] = {}
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "DELETE FROM auth_login_rate_limits "
                        "WHERE window_started_at < %s - INTERVAL '10 minutes'",
                        (now,),
                    )
                    for bucket_key in sorted(set(bucket_keys)):
                        cursor.execute(
                            """INSERT INTO auth_login_rate_limits
                                   (bucket_key, window_started_at, attempts)
                               VALUES (%s, %s, 1)
                               ON CONFLICT (bucket_key) DO UPDATE SET
                                   attempts = CASE
                                       WHEN auth_login_rate_limits.window_started_at
                                            + (%s * INTERVAL '1 second')
                                            <= EXCLUDED.window_started_at
                                       THEN 1
                                       ELSE auth_login_rate_limits.attempts + 1
                                   END,
                                   window_started_at = CASE
                                       WHEN auth_login_rate_limits.window_started_at
                                            + (%s * INTERVAL '1 second')
                                            <= EXCLUDED.window_started_at
                                       THEN EXCLUDED.window_started_at
                                       ELSE auth_login_rate_limits.window_started_at
                                   END
                               RETURNING attempts, window_started_at""",
                            (bucket_key, now, window_seconds, window_seconds),
                        )
                        attempts, window_started_at = cursor.fetchone()
                        attempts = int(attempts)
                        result[bucket_key] = (attempts, window_started_at)
                        threshold = (audit_limits or {}).get(bucket_key)
                        if threshold is not None and attempts == threshold[0] + 1:
                            event = AuditEvent(
                                actor_user_id=None,
                                action="LOGIN_RATE_LIMITED",
                                resource_type="AUTH",
                                outcome="DENIED",
                                detail=threshold[1],
                                created_at=now,
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
        return result

    def save_user(self, user: User) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO users (id,username,password_hash,role,active,created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                    (
                        user.id,
                        user.username,
                        user.password_hash,
                        user.role,
                        user.active,
                        user.created_at,
                    ),
                )

    def save_user_with_audit(self, user: User, event: AuditEvent) -> None:
        """Atomically persist a provisioned user and its success audit event."""
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO users (id,username,password_hash,role,active,created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                        (
                            user.id,
                            user.username,
                            user.password_hash,
                            user.role,
                            user.active,
                            user.created_at,
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

    def user_by_username(self, username: str):
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT id,username,password_hash,role,active,created_at "
                        "FROM users WHERE username=%s",
                        (username,),
                    )
                    row = cursor.fetchone()

        return (
            None
            if row is None
            else User(
                id=row[0],
                username=row[1],
                password_hash=row[2],
                role=row[3],
                active=row[4],
                created_at=row[5],
            )
        )

    def user_by_id(self, user_id: UUID):
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT id,username,password_hash,role,active,created_at "
                        "FROM users WHERE id=%s",
                        (user_id,),
                    )
                    row = cursor.fetchone()

        return (
            None
            if row is None
            else User(
                id=row[0],
                username=row[1],
                password_hash=row[2],
                role=row[3],
                active=row[4],
                created_at=row[5],
            )
        )

    def create_session(self, user_id: UUID, token_hash: str, expires_at: datetime) -> UUID:
        session_id = uuid.uuid4()
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    "INSERT INTO auth_sessions (id,user_id,token_hash,expires_at,revoked,created_at) VALUES (%s,%s,%s,%s,%s,%s)",
                    (session_id, user_id, token_hash, expires_at, False, datetime.now(UTC)),
                )
        return session_id

    def create_session_with_audit(
        self, user_id: UUID, token_hash: str, expires_at: datetime, event: AuditEvent
    ) -> UUID:
        """Atomically persist a login session and its success audit event."""
        session_id = uuid.uuid4()
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO auth_sessions "
                        "(id,user_id,token_hash,expires_at,revoked,created_at) "
                        "VALUES (%s,%s,%s,%s,%s,%s)",
                        (session_id, user_id, token_hash, expires_at, False, datetime.now(UTC)),
                    )
                    cursor.execute(
                        "INSERT INTO audit_events "
                        "(id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) "
                        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        (event.id, event.actor_user_id, event.action, event.resource_type,
                         event.resource_id, event.outcome, event.detail, event.created_at),
                    )
        return session_id

    def session_by_token_hash(self, token_hash: str):
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "SELECT id,user_id,expires_at,revoked "
                        "FROM auth_sessions WHERE token_hash=%s",
                        (token_hash,),
                    )
                    row = cursor.fetchone()

        return (
            None
            if row is None
            else {
                "id": str(row[0]),
                "user_id": str(row[1]),
                "expires_at": row[2],
                "revoked": row[3],
            }
        )

    def revoke_session(self, session_id: UUID) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute("UPDATE auth_sessions SET revoked=TRUE WHERE id=%s", (session_id,))

    def revoke_session_with_audit(self, session_id: UUID, event: AuditEvent) -> None:
        """Atomically revoke a session and append its successful logout audit event."""
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "UPDATE auth_sessions SET revoked=TRUE WHERE id=%s", (session_id,)
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

    def save_audit_event(self, event: AuditEvent) -> None:
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
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

    def audit_events_read_model(self, limit: int = 50, offset: int = 0) -> dict[str, object]:
        """Return bounded audit metadata without exposing free-text event details."""
        if not 1 <= limit <= 100:
            raise ValueError("limit must be within 1..100")
        if offset < 0:
            raise ValueError("offset cannot be negative")
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute("SELECT COUNT(*) FROM audit_events")
                    total = int(cursor.fetchone()[0])
                    cursor.execute(
                        """SELECT id, actor_user_id, LEFT(action, 128),
                                  LEFT(resource_type, 128), resource_id, LEFT(outcome, 32),
                                  created_at
                           FROM audit_events
                           ORDER BY created_at DESC, id DESC
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
                    "actor_user_id": str(row[1]) if row[1] else None,
                    "action": row[2],
                    "resource_type": row[3],
                    "resource_id": str(row[4]) if row[4] else None,
                    "outcome": row[5],
                    "created_at": row[6],
                }
                for row in rows
            ],
        }
