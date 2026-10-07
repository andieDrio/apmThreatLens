from datetime import UTC, datetime
from uuid import UUID, uuid4

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

    def save_user(self, user: User):
        self.users[user.username] = user

    def user_by_username(self, username):
        return self.users.get(username)

    def user_by_id(self, user_id):
        return next((u for u in self.users.values() if u.id == user_id), None)

    def create_session(self, user_id, token_hash, expires_at):
        session_id = uuid4()
        self.sessions[token_hash] = {
            "id": str(session_id),
            "user_id": str(user_id),
            "expires_at": expires_at,
            "revoked": False,
        }
        return session_id

    def session_by_token_hash(self, token_hash):
        return self.sessions.get(token_hash)

    def revoke_session(self, session_id):
        for session in self.sessions.values():
            if session["id"] == str(session_id):
                session["revoked"] = True

    def save_audit_event(self, event: AuditEvent):
        self.audit_events.append(event)


@pytest.fixture
def client():
    repository = FakeRepository()
    auth = AuthenticationService(repository)
    auth.create_user("analyst", "correct-horse-battery-123", Role.ANALYST)
    app = create_app(repository=repository, auth_service=auth)
    return httpx.Client(transport=httpx.ASGITransport(app=app), base_url="http://test")


def test_health_is_public(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_me_requires_authentication(client):
    response = client.get("/api/v1/me")
    assert response.status_code == 401


def test_login_and_me_return_authenticated_principal(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert token

    response = client.get(
        "/api/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["username"] == "analyst"
    assert response.json()["role"] == "ANALYST"


def test_logout_revokes_session(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = response.json()["access_token"]

    response = client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 204

    response = client.get(
        "/api/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


def test_invalid_credentials_fail_closed(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "wrong-password"},
    )
    assert response.status_code == 401
