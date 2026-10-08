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
        self.asset_id = uuid4()
        self.evidence_id = uuid4()
        self.finding = Finding(
            id=uuid4(),
            title="Confirmed risk finding",
            asset_id=self.asset_id,
            evidence_ids=(self.evidence_id,),
            state=FindingState.CONFIRMED,
            severity=Severity.HIGH,
            cvss=8.0,
            confidence=0.9,
            source="test",
        )
        self.saved_assessments = []

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

    def save_risk_assessment_with_audit(self, assessment, context, actor_user_id):
        assessment_id = uuid4()
        self.saved_assessments.append((assessment_id, assessment, context))
        self.audit_events.append(
            AuditEvent(
                actor_user_id=actor_user_id,
                action="RISK_ASSESSMENT_CREATED",
                resource_type="FINDING",
                resource_id=self.finding.id,
                outcome="SUCCESS",
                detail=f"risk_level={assessment.level.value};score={assessment.score:.4f}",
            )
        )
        return assessment_id


def make_client(role=Role.ANALYST):
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
async def test_risk_assessment_requires_authentication():
    client, repository = make_client()
    async with client:
        response = await client.post(
            f"/api/v1/findings/{repository.finding.id}/risk-assessments",
            json={"source": "assessment-context", "exposure": 0.8},
        )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_risk_assessment_requires_assess_permission():
    client, repository = make_client(Role.VIEWER)
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/findings/{repository.finding.id}/risk-assessments",
            headers={"Authorization": f"Bearer {token}"},
            json={"source": "assessment-context", "exposure": 0.8},
        )
    assert response.status_code == 403


@pytest.mark.anyio
async def test_risk_assessment_requires_context_source_when_context_is_supplied():
    client, repository = make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/findings/{repository.finding.id}/risk-assessments",
            headers={"Authorization": f"Bearer {token}"},
            json={"exposure": 0.8},
        )
    assert response.status_code == 422
    assert repository.saved_assessments == []


@pytest.mark.anyio
async def test_risk_assessment_is_deterministic_and_audited():
    client, repository = make_client()
    payload = {
        "source": "assessment-context",
        "exploitability": 0.9,
        "exposure": 0.8,
        "asset_criticality": 0.7,
        "business_impact": 0.6,
        "threat_relevance": 0.5,
        "control_coverage": 0.2,
    }
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/findings/{repository.finding.id}/risk-assessments",
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
        )
    assert response.status_code == 201
    body = response.json()
    assert body["finding_id"] == str(repository.finding.id)
    assert body["level"] == "HIGH"
    assert body["context_source"] == "assessment-context"
    assert body["missing_inputs"] == []
    assert body["assessment_id"]
    assert len(repository.saved_assessments) == 1
    assert repository.audit_events[-1].action == "RISK_ASSESSMENT_CREATED"
    assert repository.audit_events[-1].actor_user_id == repository.users["operator"].id


@pytest.mark.anyio
async def test_risk_assessment_returns_not_found_for_unknown_finding():
    client, repository = make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/findings/{uuid4()}/risk-assessments",
            headers={"Authorization": f"Bearer {token}"},
            json={"source": "assessment-context"},
        )
    assert response.status_code == 404
    assert repository.saved_assessments == []
