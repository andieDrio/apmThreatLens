from uuid import uuid4

import httpx
import pytest

from threatlens.api.app import create_app
from threatlens.auth.service import AuthenticationService, Role
from threatlens.domain.models import AuditEvent, User


class FakeRepository:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.audit_events = []
        self.login_attempts = {}
        self.campaigns = []

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

    def organization_for_user(self, user_id):
        user = self.user_by_id(user_id)
        if user is None:
            raise PermissionError("organization context unavailable")
        return {"organization_id": "00000000-0000-4000-8000-000000000001",
                "organization_name": "Default Organization", "role": user.role}

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

    def save_campaign_with_audit(self, campaign, actor_user_id):
        self.campaigns.append(campaign)
        self.audit_events.append(
            AuditEvent(
                actor_user_id=actor_user_id,
                action="CAMPAIGN_CREATED",
                resource_type="CAMPAIGN",
                resource_id=campaign.id,
                outcome="SUCCESS",
                detail="authorized=true",
            )
        )


def make_client(role=Role.ADMIN):
    repository = FakeRepository()
    auth = AuthenticationService(repository)
    auth.create_user("operator", "correct-horse-battery-123", role)
    app = create_app(repository=repository, auth_service=auth)
    return (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ),
        repository,
    )


async def login(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "correct-horse-battery-123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.mark.anyio
async def test_campaign_creation_requires_authentication():
    client, _ = make_client()
    async with client:
        response = await client.post(
            "/api/v1/campaigns",
            json={"name": "authorized", "include": ["10.0.0.10"], "authorized": True},
        )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_campaign_creation_requires_admin_permission():
    client, _ = make_client(Role.ANALYST)
    async with client:
        token = await login(client)
        response = await client.post(
            "/api/v1/campaigns",
            headers={"Authorization": f"Bearer {token}"},
            json={"name": "authorized", "include": ["10.0.0.10"], "authorized": True},
        )
    assert response.status_code == 403


@pytest.mark.anyio
async def test_campaign_creation_requires_explicit_authorization():
    client, repository = make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            "/api/v1/campaigns",
            headers={"Authorization": f"Bearer {token}"},
            json={"name": "unauthorized", "include": ["10.0.0.10"], "authorized": False},
        )
    assert response.status_code == 422
    assert repository.campaigns == []


@pytest.mark.anyio
async def test_campaign_creation_persists_scope_and_audit_actor():
    client, repository = make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            "/api/v1/campaigns",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "name": "authorized-campaign",
                "include": ["10.0.0.10", "https://example.test"],
                "exclude": ["10.0.0.11"],
                "authorized": True,
            },
        )
    assert response.status_code == 201
    body = response.json()
    assert body["name"] == "authorized-campaign"
    assert body["authorized"] is True
    assert body["state"] == "QUEUED"
    assert body["include"] == ["10.0.0.10", "https://example.test"]
    assert body["exclude"] == ["10.0.0.11"]
    assert len(repository.campaigns) == 1
    assert repository.audit_events[-1].action == "CAMPAIGN_CREATED"
    assert repository.audit_events[-1].actor_user_id == repository.users["operator"].id


@pytest.mark.anyio
async def test_campaign_creation_rejects_empty_scope():
    client, _ = make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            "/api/v1/campaigns",
            headers={"Authorization": f"Bearer {token}"},
            json={"name": "empty-scope", "include": [], "authorized": True},
        )
    assert response.status_code == 422
