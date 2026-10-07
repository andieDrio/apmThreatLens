from datetime import UTC
from uuid import UUID, uuid4

import httpx
import pytest

from threatlens.api.app import create_app
from threatlens.auth.service import AuthenticationService, Role
from threatlens.domain.models import AuditEvent, LifecycleState, User


EXECUTION_ID = UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")


class FakeRepository:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.audit_events = []
        self.states = {EXECUTION_ID: LifecycleState.QUEUED}

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

    def scan_state(self, execution_id):
        if execution_id not in self.states:
            raise KeyError(str(execution_id))
        return self.states[execution_id]


class FakeOrchestrator:
    def __init__(self, repository):
        self.repository = repository
        self.cancel_principals = []
        self.recover_principals = []

    def cancel(self, execution_id, principal=None):
        if execution_id not in self.repository.states:
            raise KeyError(str(execution_id))
        self.cancel_principals.append(principal)
        if self.repository.states[execution_id] is not LifecycleState.COMPLETED:
            self.repository.states[execution_id] = LifecycleState.CANCELLED

    def recover_stale(self, execution_id, principal=None):
        if execution_id not in self.repository.states:
            raise KeyError(str(execution_id))
        self.recover_principals.append(principal)
        if self.repository.states[execution_id] is LifecycleState.RUNNING:
            self.repository.states[execution_id] = LifecycleState.FAILED
            return True
        return False


async def make_client(role=Role.ANALYST):
    repository = FakeRepository()
    auth = AuthenticationService(repository)
    auth.create_user("operator", "correct-horse-battery-123", role)
    orchestrator = FakeOrchestrator(repository)
    app = create_app(repository=repository, auth_service=auth, orchestrator=orchestrator)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://test",
    )
    return client, repository, orchestrator


async def login(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "correct-horse-battery-123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.mark.anyio
async def test_cancel_requires_assess_permission():
    client, _, _ = await make_client(Role.VIEWER)
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/scans/{EXECUTION_ID}/cancel",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 403


@pytest.mark.anyio
async def test_cancel_routes_through_orchestrator_and_returns_persisted_state():
    client, repository, orchestrator = await make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/scans/{EXECUTION_ID}/cancel",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200
    assert response.json() == {
        "execution_id": str(EXECUTION_ID),
        "action": "CANCEL",
        "state": "CANCELLED",
        "changed": True,
    }
    assert orchestrator.cancel_principals[0].username == "operator"
    assert repository.scan_state(EXECUTION_ID) is LifecycleState.CANCELLED


@pytest.mark.anyio
async def test_cancel_terminal_scan_is_idempotent_control_operation():
    client, repository, orchestrator = await make_client()
    repository.states[EXECUTION_ID] = LifecycleState.COMPLETED
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/scans/{EXECUTION_ID}/cancel",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200
    assert response.json()["changed"] is False
    assert response.json()["state"] == "COMPLETED"
    assert orchestrator.cancel_principals


@pytest.mark.anyio
async def test_recover_stale_requires_assess_permission():
    client, _, _ = await make_client(Role.VIEWER)
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/scans/{EXECUTION_ID}/recover-stale",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 403


@pytest.mark.anyio
async def test_recover_stale_transitions_running_scan_and_returns_changed():
    client, repository, orchestrator = await make_client()
    repository.states[EXECUTION_ID] = LifecycleState.RUNNING
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/scans/{EXECUTION_ID}/recover-stale",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200
    assert response.json()["changed"] is True
    assert response.json()["state"] == "FAILED"
    assert orchestrator.recover_principals[0].username == "operator"


@pytest.mark.anyio
async def test_control_returns_not_found_for_unknown_scan():
    unknown = UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    client, _, _ = await make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/scans/{unknown}/cancel",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 404


@pytest.mark.anyio
async def test_control_rejects_malformed_execution_id():
    client, _, _ = await make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            "/api/v1/scans/not-a-uuid/cancel",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 422
