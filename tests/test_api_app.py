from datetime import UTC, datetime
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

    def assets_read_model(self, limit=50, offset=0):
        return {
            "total": 1,
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "id": "44444444-4444-4444-4444-444444444444",
                    "canonical_id": "fqdn:example.test",
                    "asset_type": "fqdn",
                    "value": "example.test",
                    "first_seen_at": datetime(2026, 10, 1, tzinfo=UTC),
                    "last_seen_at": datetime(2026, 10, 7, tzinfo=UTC),
                    "services": [
                        {
                            "id": "55555555-5555-5555-5555-555555555555",
                            "protocol": "tcp",
                            "port": 443,
                            "service_name": "https",
                            "version": "1.3",
                        }
                    ],
                }
            ],
        }

    def findings_read_model(self, limit=50, offset=0):
        return {
            "total": 2,
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "title": "Missing HSTS",
                    "asset_id": "22222222-2222-2222-2222-222222222222",
                    "asset_canonical_id": "fqdn:example.test",
                    "state": "SUSPECTED",
                    "severity": "LOW",
                    "vulnerability_id": None,
                    "cwe": None,
                    "cve": None,
                    "cvss": None,
                    "confidence": 0.9,
                    "source": "web-assessment",
                    "detected_at": datetime(2026, 10, 7, tzinfo=UTC),
                    "service_id": "33333333-3333-3333-3333-333333333333",
                    "service_protocol": "tcp",
                    "service_port": 443,
                    "service_name": "https",
                    "service_version": None,
                    "endpoint": "https://example.test/",
                    "parameter": None,
                    "location": "response-header",
                }
            ],
        }

    def campaigns_read_model(self, limit=50, offset=0):
        return {
            "total": 1,
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "id": "88888888-8888-8888-8888-888888888888",
                    "name": "authorized-test",
                    "authorized": True,
                    "state": "QUEUED",
                    "created_at": datetime(2026, 10, 7, 6, 0, tzinfo=UTC),
                    "include": ["fqdn:example.test", "10.10.10.0/24"],
                    "exclude": ["10.10.10.5"],
                }
            ],
        }

    def scans_read_model(self, limit=50, offset=0):
        return {
            "total": 2,
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "execution_id": "66666666-6666-6666-6666-666666666666",
                    "campaign_id": "77777777-7777-7777-7777-777777777777",
                    "campaign_name": "authorized-test",
                    "provider_name": "network-discovery",
                    "state": "RUNNING",
                    "queued_at": datetime(2026, 10, 7, 7, 0, tzinfo=UTC),
                    "started_at": datetime(2026, 10, 7, 7, 1, tzinfo=UTC),
                    "finished_at": None,
                    "heartbeat_at": datetime(2026, 10, 7, 7, 5, tzinfo=UTC),
                    "error": None,
                }
            ],
        }

    def dashboard_summary(self):
        return {
            "campaigns": 2,
            "assets": 4,
            "services": 7,
            "findings": 3,
            "findings_by_severity": {"HIGH": 2, "LOW": 1},
            "scans_by_state": {"COMPLETED": 1, "RUNNING": 1},
        }


@pytest.fixture
async def client():
    repository = FakeRepository()
    auth = AuthenticationService(repository)
    auth.create_user("analyst", "correct-horse-battery-123", Role.ANALYST)
    app = create_app(repository=repository, auth_service=auth)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client


@pytest.mark.anyio
async def test_health_is_public(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.anyio
async def test_me_requires_authentication(client):
    response = await client.get("/api/v1/me")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_login_and_me_return_authenticated_principal(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert token

    response = await client.get(
        "/api/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json()["username"] == "analyst"
    assert response.json()["role"] == "ANALYST"


@pytest.mark.anyio
async def test_logout_revokes_session(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = response.json()["access_token"]

    response = await client.post(
        "/api/v1/auth/logout",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 204

    response = await client.get(
        "/api/v1/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_invalid_credentials_fail_closed(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "wrong-password"},
    )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_dashboard_summary_requires_read_permission(client):
    response = await client.get("/api/v1/dashboard/summary")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_dashboard_summary_is_bounded_read_model(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    response = await client.get(
        "/api/v1/dashboard/summary",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.json() == {
        "campaigns": 2,
        "assets": 4,
        "services": 7,
        "findings": 3,
        "findings_by_severity": {"HIGH": 2, "LOW": 1},
        "scans_by_state": {"COMPLETED": 1, "RUNNING": 1},
    }


@pytest.mark.anyio
async def test_findings_read_model_requires_authentication(client):
    response = await client.get("/api/v1/findings")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_findings_read_model_is_bounded_and_contextual(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    response = await client.get(
        "/api/v1/findings?limit=1&offset=1",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    assert payload["limit"] == 1
    assert payload["offset"] == 1
    assert payload["items"][0]["asset_canonical_id"] == "fqdn:example.test"
    assert payload["items"][0]["service_port"] == 443
    assert payload["items"][0]["endpoint"] == "https://example.test/"
    assert "evidence" not in payload["items"][0]


@pytest.mark.anyio
async def test_findings_read_model_rejects_unbounded_limit(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    response = await client.get(
        "/api/v1/findings?limit=101",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_campaigns_read_model_requires_authentication(client):
    response = await client.get("/api/v1/campaigns")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_campaigns_read_model_exposes_explicit_scope(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    response = await client.get(
        "/api/v1/campaigns?limit=1&offset=0",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["authorized"] is True
    assert payload["items"][0]["include"] == ["fqdn:example.test", "10.10.10.0/24"]
    assert payload["items"][0]["exclude"] == ["10.10.10.5"]


@pytest.mark.anyio
async def test_campaigns_read_model_rejects_unbounded_limit(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    response = await client.get(
        "/api/v1/campaigns?limit=101",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_scans_read_model_requires_authentication(client):
    response = await client.get("/api/v1/scans")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_scans_read_model_returns_execution_state(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    response = await client.get(
        "/api/v1/scans?limit=1&offset=0",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 2
    assert payload["items"][0]["state"] == "RUNNING"
    assert payload["items"][0]["provider_name"] == "network-discovery"
    assert payload["items"][0]["heartbeat_at"] is not None
    assert "evidence" not in payload["items"][0]


@pytest.mark.anyio
async def test_scans_read_model_rejects_unbounded_limit(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    response = await client.get(
        "/api/v1/scans?limit=101",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_assets_read_model_requires_authentication(client):
    response = await client.get("/api/v1/assets")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_assets_read_model_returns_services(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    response = await client.get(
        "/api/v1/assets?limit=1&offset=0",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] == 1
    assert payload["items"][0]["canonical_id"] == "fqdn:example.test"
    assert payload["items"][0]["services"][0]["port"] == 443


@pytest.mark.anyio
async def test_assets_read_model_rejects_unbounded_limit(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    response = await client.get(
        "/api/v1/assets?limit=101",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422
