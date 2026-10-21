from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from threatlens.api.app import create_app
from threatlens.auth.service import AuthenticationService, Role
from threatlens.domain.models import AuditEvent, Evidence, User


class FakeRepository:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.audit_events = []
        self.login_attempts = {}
        self.evidence = [
            Evidence(
                kind="banner",
                content="HTTP/1.1 200 OK",
                source="unit-test",
                captured_at=datetime(2026, 1, 2, tzinfo=UTC),
                sha256="a" * 64,
                metadata={
                    "execution_id": str(uuid4()),
                    "provider": "test",
                    "url": (
                        "https://user:url-secret@example.test/api/items?api_key=top-secret"
                        "&region=ap-southeast-1#fragment-secret"
                    ),
                    "redirect_location": "/next?access_token=redirect-secret",
                    "authorization": "Bearer header-secret",
                },
            )
        ]

    def record_login_attempts(
        self, bucket_keys, now, window_seconds=60, audit_limits=None
    ):
        result = {}
        for key in sorted(set(bucket_keys)):
            started, count = self.login_attempts.get(key, (now, 0))
            if (now - started).total_seconds() >= window_seconds:
                started, count = now, 0
            count += 1
            self.login_attempts[key] = (started, count)
            result[key] = (count, started)
        return result

    def save_user(self, user: User):
        self.users[user.username] = user

    def save_user_with_audit(self, user: User, event: AuditEvent):
        previous_user = self.users.get(user.username)
        audit_count = len(self.audit_events)
        self.users[user.username] = user
        try:
            self.save_audit_event(event)
        except Exception:
            if previous_user is None:
                self.users.pop(user.username, None)
            else:
                self.users[user.username] = previous_user
            del self.audit_events[audit_count:]
            raise

    def user_by_username(self, username):
        return self.users.get(username)

    def user_by_id(self, user_id):
        return next((user for user in self.users.values() if user.id == user_id), None)

    def create_session(self, user_id, token_hash, expires_at):
        session_id = uuid4()
        self.sessions[token_hash] = {
            "id": str(session_id),
            "user_id": str(user_id),
            "expires_at": expires_at,
            "revoked": False,
        }
        return session_id

    def create_session_with_audit(self, user_id, token_hash, expires_at, event: AuditEvent):
        session_id = self.create_session(user_id, token_hash, expires_at)
        try:
            self.save_audit_event(event)
        except Exception:
            self.sessions.pop(token_hash, None)
            raise
        return session_id

    def session_by_token_hash(self, token_hash):
        return self.sessions.get(token_hash)

    def revoke_session(self, session_id):
        for session in self.sessions.values():
            if session["id"] == str(session_id):
                session["revoked"] = True

    def save_audit_event(self, event: AuditEvent):
        self.audit_events.append(event)

    def evidence_read_model(self, limit=50, offset=0):
        return {
            "total": len(self.evidence),
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "id": str(item.id),
                    "kind": item.kind,
                    "source": item.source,
                    "captured_at": item.captured_at,
                    "sha256": item.sha256,
                    "metadata": dict(item.metadata),
                }
                for item in self.evidence[offset : offset + limit]
            ],
        }


async def make_client(role=Role.ANALYST):
    repository = FakeRepository()
    auth = AuthenticationService(repository)
    auth.create_user("operator", "correct-horse-battery-123", role)
    app = create_app(repository=repository, auth_service=auth)
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    )


async def login(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "correct-horse-battery-123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.mark.anyio
async def test_evidence_requires_authentication():
    client = await make_client()
    async with client:
        response = await client.get("/api/v1/evidence")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_evidence_allows_read_permission():
    client = await make_client(Role.VIEWER)
    async with client:
        token = await login(client)
        response = await client.get(
            "/api/v1/evidence",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200


@pytest.mark.anyio
async def test_evidence_read_model_exposes_integrity_metadata_not_raw_content():
    client = await make_client()
    async with client:
        token = await login(client)
        response = await client.get(
            "/api/v1/evidence",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["kind"] == "banner"
    assert payload["items"][0]["sha256"] == "a" * 64
    assert payload["items"][0]["metadata"]["provider"] == "test"
    assert payload["items"][0]["metadata"]["execution_id"]
    assert payload["items"][0]["metadata"]["url"] == (
        "https://example.test/api/items?[REDACTED]"
    )
    assert payload["items"][0]["metadata"]["redirect_location"] == "/next?[REDACTED]"
    assert payload["items"][0]["metadata"]["authorization"] == "[REDACTED]"
    assert "top-secret" not in response.text
    assert "redirect-secret" not in response.text
    assert "header-secret" not in response.text
    assert "url-secret" not in response.text
    assert "fragment-secret" not in response.text
    assert "content" not in payload["items"][0]


@pytest.mark.anyio
async def test_evidence_read_model_bounds_pagination():
    client = await make_client()
    async with client:
        token = await login(client)
        response = await client.get(
            "/api/v1/evidence?limit=101",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 422
