from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from threatlens.api.app import create_app
from threatlens.auth.service import AuthenticationService, Role
from threatlens.domain.models import AuditEvent, Finding, FindingState, Severity, User


class FakeRepository:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.audit_events = []
        self.finding = Finding(
            id=uuid4(),
            title="Risk read model finding",
            asset_id=uuid4(),
            evidence_ids=(uuid4(),),
            state=FindingState.CONFIRMED,
            severity=Severity.HIGH,
            cvss=8.0,
            confidence=0.9,
            source="test",
        )

    def save_user(self, user: User):
        self.users[user.username] = user

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

    def session_by_token_hash(self, token_hash):
        return self.sessions.get(token_hash)

    def revoke_session(self, session_id):
        for session in self.sessions.values():
            if session["id"] == str(session_id):
                session["revoked"] = True

    def save_audit_event(self, event: AuditEvent):
        self.audit_events.append(event)

    def finding_by_id(self, finding_id):
        if finding_id != self.finding.id:
            raise KeyError(str(finding_id))
        return self.finding

    def risk_assessments_read_model(self, finding_id, limit=50, offset=0):
        if finding_id != self.finding.id:
            raise KeyError(str(finding_id))
        return {
            "total": 1,
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "assessment_id": str(uuid4()),
                    "finding_id": str(self.finding.id),
                    "level": "HIGH",
                    "score": 0.7425,
                    "context": {"exposure": 0.8, "source": "assessment-context"},
                    "factors": [
                        {
                            "name": "technical_severity",
                            "score": 0.75,
                            "weight": 0.2,
                            "rationale": "Finding severity is HIGH.",
                            "source": "Finding.severity",
                            "contribution": 0.15,
                        }
                    ],
                    "explanation": ["Finding severity is HIGH."],
                    "inputs_used": ["Finding.severity"],
                    "missing_inputs": ["asset_criticality"],
                    "context_source": "assessment-context",
                    "created_at": datetime.now(UTC),
                }
            ],
        }


def make_client(role=Role.ANALYST):
    repository = FakeRepository()
    auth = AuthenticationService(repository)
    auth.create_user("operator", "correct-horse-battery-123", role)
    app = create_app(repository=repository, auth_service=auth)
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    ), repository


async def login(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "correct-horse-battery-123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.mark.anyio
async def test_risk_assessment_read_model_requires_authentication():
    client, repository = make_client()
    async with client:
        response = await client.get(
            f"/api/v1/findings/{repository.finding.id}/risk-assessments"
        )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_risk_assessment_read_model_allows_viewer_read_permission():
    client, repository = make_client(Role.VIEWER)
    async with client:
        token = await login(client)
        response = await client.get(
            f"/api/v1/findings/{repository.finding.id}/risk-assessments",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200


@pytest.mark.anyio
async def test_risk_assessment_read_model_returns_bounded_assessments():
    client, repository = make_client()
    async with client:
        token = await login(client)
        response = await client.get(
            f"/api/v1/findings/{repository.finding.id}/risk-assessments",
            headers={"Authorization": f"Bearer {token}"},
            params={"limit": 10, "offset": 0},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["limit"] == 10
    assert body["offset"] == 0
    assert body["items"][0]["finding_id"] == str(repository.finding.id)
    assert body["items"][0]["level"] == "HIGH"
    assert body["items"][0]["score"] == 0.7425
    assert body["items"][0]["context_source"] == "assessment-context"
    assert body["items"][0]["factors"][0]["contribution"] == 0.15


@pytest.mark.anyio
async def test_risk_assessment_read_model_returns_not_found_for_unknown_finding():
    client, repository = make_client()
    async with client:
        token = await login(client)
        response = await client.get(
            f"/api/v1/findings/{uuid4()}/risk-assessments",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 404
