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
        self.created = []
        self.transitions = []

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

    def save_evidence_validation(self, validation, audit_event=None):
        self.created.append((validation, audit_event))

    def transition_evidence_validation(self, previous_id, replacement, audit_event=None):
        self.transitions.append((previous_id, replacement, audit_event))

    def supersede_evidence_validation(self, previous_id, replacement, audit_event=None):
        self.transitions.append((previous_id, replacement, audit_event))


async def make_client(role=Role.ANALYST):
    repository = FakeRepository()
    auth = AuthenticationService(repository)
    auth.create_user("operator", "correct-horse-battery-123", role)
    app = create_app(repository=repository, auth_service=auth)
    return repository, httpx.AsyncClient(
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
async def test_evidence_validation_requires_validate_permission():
    repository, client = await make_client(Role.VIEWER)
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/evidence/{uuid4()}/validations",
            json={"state": "PENDING", "rationale": "Initial analyst review."},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 403
    assert repository.created == []


@pytest.mark.anyio
async def test_evidence_validation_binds_validator_and_audit_actor_to_authenticated_principal():
    repository, client = await make_client()
    evidence_id = uuid4()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/evidence/{evidence_id}/validations",
            json={"state": "PENDING", "rationale": "Initial analyst review."},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 201
    validation, audit = repository.created[0]
    operator = repository.users["operator"]
    assert validation.evidence_id == evidence_id
    assert validation.validator == "operator"
    assert audit.actor_user_id == operator.id
    assert audit.action == "EVIDENCE_VALIDATION_CREATED"
    assert response.json()["validator"] == "operator"


@pytest.mark.anyio
async def test_evidence_validation_transition_cannot_accept_client_validator():
    repository, client = await make_client()
    previous_id = uuid4()
    evidence_id = uuid4()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/evidence/validations/{previous_id}/transition",
            json={
                "evidence_id": str(evidence_id),
                "state": "VALIDATED",
                "rationale": "Evidence supports the finding.",
                "supporting_evidence_ids": [str(uuid4())],
                "validator": "attacker-controlled-name",
            },
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 201
    _, replacement, audit = repository.transitions[0]
    assert replacement.validator == "operator"
    assert audit.actor_user_id == repository.users["operator"].id
    assert "validator" not in response.json() or response.json()["validator"] == "operator"


@pytest.mark.anyio
async def test_evidence_validation_rejects_superseded_on_create():
    _, client = await make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/evidence/{uuid4()}/validations",
            json={"state": "SUPERSEDED", "rationale": "Invalid direct transition."},
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 422
