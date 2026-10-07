"""Durable authentication, session, and audit persistence."""

from __future__ import annotations

from datetime import datetime, timezone
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
                (
                    "INSERT INTO users (id,username,password_hash,role,active,created_at) "
                    "VALUES (?,?,?,?,?,?)"
                ),
                (str(user.id), user.username, user.password_hash, user.role, int(user.active), user.created_at.isoformat()),
            )

    def user_by_username(self, username: str):
        row = self.connection.execute(
            "SELECT id,username,password_hash,role,active,created_at FROM users WHERE username=?", (username,)
        ).fetchone()
        return None if row is None else User(
            id=UUID(row["id"]), username=row["username"], password_hash=row["password_hash"],
            role=row["role"], active=bool(row["active"]), created_at=datetime.fromisoformat(row["created_at"])
        )

    def user_by_id(self, user_id: UUID):
        row = self.connection.execute(
            "SELECT id,username,password_hash,role,active,created_at FROM users WHERE id=?", (str(user_id),)
        ).fetchone()
        return None if row is None else User(
            id=UUID(row["id"]), username=row["username"], password_hash=row["password_hash"],
            role=row["role"], active=bool(row["active"]), created_at=datetime.fromisoformat(row["created_at"])
        )

    def create_session(self, user_id: UUID, token_hash: str, expires_at: datetime) -> UUID:
        session_id = uuid.uuid4()
        with self.connection:
            self.connection.execute(
                (
                    "INSERT INTO auth_sessions "
                    "(id,user_id,token_hash,expires_at,revoked,created_at) "
                    "VALUES (?,?,?,?,?,?)"
                ),
                (str(session_id), str(user_id), token_hash, expires_at.isoformat(), 0, datetime.now(timezone.utc).isoformat()),
            )
        return session_id

    def session_by_token_hash(self, token_hash: str):
        row = self.connection.execute(
            "SELECT id,user_id,expires_at,revoked FROM auth_sessions WHERE token_hash=?", (token_hash,)
        ).fetchone()
        if row is None:
            return None
        return {"id": row["id"], "user_id": row["user_id"],
                "expires_at": datetime.fromisoformat(row["expires_at"]), "revoked": bool(row["revoked"])}

    def revoke_session(self, session_id: UUID) -> None:
        with self.connection:
            self.connection.execute("UPDATE auth_sessions SET revoked=1 WHERE id=?", (str(session_id),))

    def save_audit_event(self, event: AuditEvent) -> None:
        lock = getattr(self, "_transaction_lock", None)
        if lock is None:
            with self.connection:
                self.connection.execute(
                    (
                        "INSERT INTO audit_events "
                        "(id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) "
                        "VALUES (?,?,?,?,?,?,?,?)"
                    ),
                    (str(event.id), str(event.actor_user_id) if event.actor_user_id else None, event.action,
                     event.resource_type, str(event.resource_id) if event.resource_id else None,
                     event.outcome, event.detail, event.created_at.isoformat()),
                )
            return
        with lock:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO audit_events (id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (str(event.id), str(event.actor_user_id) if event.actor_user_id else None, event.action,
                     event.resource_type, str(event.resource_id) if event.resource_id else None,
                     event.outcome, event.detail, event.created_at.isoformat()),
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

    def save_user(self, user: User) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    (
                    "INSERT INTO users (id,username,password_hash,role,active,created_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s)"
                ),
                    (user.id, user.username, user.password_hash, user.role, user.active, user.created_at),
                )

    def user_by_username(self, username: str):
        with self.connection.cursor() as cursor:
            cursor.execute((
                "SELECT id,username,password_hash,role,active,created_at "
                "FROM users WHERE username=%s"
            ), (username,))
            row = cursor.fetchone()
        return None if row is None else User(id=row[0], username=row[1], password_hash=row[2],
                                             role=row[3], active=row[4], created_at=row[5])

    def user_by_id(self, user_id: UUID):
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT id,username,password_hash,role,active,created_at FROM users WHERE id=%s", (user_id,))
            row = cursor.fetchone()
        return None if row is None else User(id=row[0], username=row[1], password_hash=row[2],
                                             role=row[3], active=row[4], created_at=row[5])

    def create_session(self, user_id: UUID, token_hash: str, expires_at: datetime) -> UUID:
        session_id = uuid.uuid4()
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute(
                    (
                    "INSERT INTO auth_sessions "
                    "(id,user_id,token_hash,expires_at,revoked,created_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s)"
                ),
                    (session_id, user_id, token_hash, expires_at, False, datetime.now(timezone.utc)),
                )
        return session_id

    def session_by_token_hash(self, token_hash: str):
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT id,user_id,expires_at,revoked FROM auth_sessions WHERE token_hash=%s", (token_hash,))
            row = cursor.fetchone()
        return None if row is None else {"id": str(row[0]), "user_id": str(row[1]),
                                         "expires_at": row[2], "revoked": row[3]}

    def revoke_session(self, session_id: UUID) -> None:
        with self.connection.transaction():
            with self.connection.cursor() as cursor:
                cursor.execute("UPDATE auth_sessions SET revoked=TRUE WHERE id=%s", (session_id,))

    def save_audit_event(self, event: AuditEvent) -> None:
        with self._transaction_lock:
            with self.connection.transaction():
                with self.connection.cursor() as cursor:
                    cursor.execute(
                        "INSERT INTO audit_events "
                    "(id,actor_user_id,action,resource_type,resource_id,outcome,detail,created_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s,%s,%s)",
                        (event.id, event.actor_user_id, event.action, event.resource_type, event.resource_id,
                         event.outcome, event.detail, event.created_at),
                    )
