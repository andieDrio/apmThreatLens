"""Fail-closed authentication, session, and role-based authorization."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import hashlib
import hmac
import secrets
from uuid import UUID

from threatlens.domain.models import User, AuditEvent


class Role(StrEnum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


class Permission(StrEnum):
    READ = "READ"
    ASSESS = "ASSESS"
    VALIDATE = "VALIDATE"
    REMEDIATE = "REMEDIATE"
    ADMIN = "ADMIN"


_ROLE_PERMISSIONS = {
    Role.ADMIN: frozenset(Permission),
    Role.ANALYST: frozenset({Permission.READ, Permission.ASSESS, Permission.VALIDATE, Permission.REMEDIATE}),
    Role.VIEWER: frozenset({Permission.READ}),
}


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    user_id: UUID
    username: str
    role: Role
    session_id: UUID


class AuthenticationService:
    def __init__(self, repository, session_ttl_seconds: int = 1800) -> None:
        if session_ttl_seconds < 60:
            raise ValueError("session_ttl_seconds must be at least 60")
        self.repository = repository
        self.session_ttl = timedelta(seconds=session_ttl_seconds)

    @staticmethod
    def _hash_password(password: str, salt: bytes, iterations: int = 600_000) -> str:
        if not password:
            raise ValueError("password cannot be blank")
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
        return f"pbkdf2_sha256${iterations}${salt.hex()}${digest.hex()}"

    @classmethod
    def create_password_hash(cls, password: str) -> str:
        return cls._hash_password(password, secrets.token_bytes(16))

    @staticmethod
    def _verify_password(password: str, encoded: str) -> bool:
        try:
            scheme, iteration_text, salt_hex, digest_hex = encoded.split("$")
            if scheme != "pbkdf2_sha256":
                return False
            expected = AuthenticationService._hash_password(password, bytes.fromhex(salt_hex), int(iteration_text))
            return hmac.compare_digest(expected, encoded)
        except (ValueError, TypeError):
            return False

    def create_user(self, username: str, password: str, role: Role = Role.VIEWER) -> User:
        username = username.strip()
        if not username:
            raise ValueError("username cannot be blank")
        if len(password) < 12:
            raise ValueError("password must be at least 12 characters")
        user = User(username=username, password_hash=self.create_password_hash(password), role=role.value)
        self.repository.save_user(user)
        self.repository.save_audit_event(
            AuditEvent(actor_user_id=user.id, action="USER_CREATED", resource_type="USER",
                       resource_id=user.id, outcome="SUCCESS", detail=f"role={role.value}")
        )
        return user

    def authenticate(self, username: str, password: str) -> tuple[AuthenticatedPrincipal, str]:
        user = self.repository.user_by_username(username.strip())
        if user is None or not user.active or not self._verify_password(password, user.password_hash):
            self.repository.save_audit_event(
                AuditEvent(actor_user_id=None, action="LOGIN", resource_type="AUTH",
                           resource_id=None, outcome="DENIED", detail="invalid credentials")
            )
            raise PermissionError("authentication failed")
        role = Role(user.role)
        raw_token = secrets.token_urlsafe(32)
        session_id = self.repository.create_session(
            user.id, hashlib.sha256(raw_token.encode("utf-8")).hexdigest(),
            datetime.now(timezone.utc) + self.session_ttl,
        )
        self.repository.save_audit_event(
            AuditEvent(actor_user_id=user.id, action="LOGIN", resource_type="AUTH",
                       resource_id=user.id, outcome="SUCCESS", detail="session created")
        )
        return AuthenticatedPrincipal(user.id, user.username, role, session_id), raw_token

    def authenticate_session(self, raw_token: str) -> AuthenticatedPrincipal:
        if not raw_token:
            raise PermissionError("authentication required")
        session = self.repository.session_by_token_hash(hashlib.sha256(raw_token.encode("utf-8")).hexdigest())
        now = datetime.now(timezone.utc)
        if session is None or session["revoked"] or session["expires_at"] <= now:
            raise PermissionError("session is invalid or expired")
        user = self.repository.user_by_id(UUID(session["user_id"]))
        if user is None or not user.active:
            raise PermissionError("user is inactive")
        return AuthenticatedPrincipal(user.id, user.username, Role(user.role), UUID(session["id"]))

    def logout(self, principal: AuthenticatedPrincipal) -> None:
        self.repository.revoke_session(principal.session_id)
        self.repository.save_audit_event(
            AuditEvent(actor_user_id=principal.user_id, action="LOGOUT", resource_type="AUTH",
                       resource_id=principal.user_id, outcome="SUCCESS", detail="session revoked")
        )

    def authorize(self, principal: AuthenticatedPrincipal | None, permission: Permission) -> None:
        if principal is None:
            raise PermissionError("authentication required")
        if permission not in _ROLE_PERMISSIONS[principal.role]:
            self.repository.save_audit_event(
                AuditEvent(actor_user_id=principal.user_id, action="AUTHZ_DENIED",
                           resource_type="PERMISSION", resource_id=None, outcome="DENIED",
                           detail=f"permission={permission.value}")
            )
            raise PermissionError("insufficient permission")
