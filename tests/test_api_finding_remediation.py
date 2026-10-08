from uuid import UUID, uuid4

import httpx
import pytest

from threatlens.api.app import create_app
from threatlens.auth.service import AuthenticationService, Role
from threatlens.domain.models import AuditEvent, FindingState, User


class FakeRepository:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.audit_events = []
        self.finding_states = {uuid4(): FindingState.CONFIRMED}

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

    def transition_finding_remediation_with_audit(
        self, finding_id, target_state, actor_user_id, rationale
    ):
        if finding_id not in self.finding_states:
            raise KeyError(str(finding_id))
        current_state = self.finding_states[finding_id]
        if current_state is target_state:
            self.audit_events.append(
                AuditEvent(
                    actor_user_id=actor_user_id,
                    action="FINDING_REMEDIATION",
                    resource_type="FINDING",
                    resource_id=finding_id,
                    outcome="NOOP",
                    detail=f"state={target_state.value};rationale={rationale}",
                )
            )
            return False, current_state, True
        if current_state is not FindingState.CONFIRMED or target_state not in {
            FindingState.MITIGATED,
            FindingState.ACCEPTED_RISK,
        }:
            self.audit_events.append(
                AuditEvent(
                    actor_user_id=actor_user_id,
                    action="FINDING_REMEDIATION",
                    resource_type="FINDING",
                    resource_id=finding_id,
                    outcome="DENIED",
                    detail=f"current={current_state.value};target={target_state.value}",
                )
            )
            return False, current_state, False
        self.finding_states[finding_id] = target_state
        self.audit_events.append(
            AuditEvent(
                actor_user_id=actor_user_id,
                action="FINDING_REMEDIATION",
                resource_type="FINDING",
                resource_id=finding_id,
                outcome="SUCCESS",
                detail=f"from={current_state.value};to={target_state.value};rationale={rationale}",
            )
        )
        return True, target_state, True


def make_client(role=Role.ANALYST):
    repository = FakeRepository()
    finding_id = next(iter(repository.finding_states))
    auth = AuthenticationService(repository)
    auth.create_user("operator", "correct-horse-battery-123", role)
    app = create_app(repository=repository, auth_service=auth)
    return (
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://test",
        ),
        repository,
        finding_id,
    )


async def login(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "correct-horse-battery-123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.mark.anyio
async def test_finding_remediation_requires_authentication():
    client, _, finding_id = make_client()
    async with client:
        response = await client.post(
            f"/api/v1/findings/{finding_id}/remediation",
            json={"state": "MITIGATED", "rationale": "fix verified"},
        )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_finding_remediation_requires_permission():
    client, _, finding_id = make_client(Role.VIEWER)
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/findings/{finding_id}/remediation",
            headers={"Authorization": f"Bearer {token}"},
            json={"state": "MITIGATED", "rationale": "fix verified"},
        )
    assert response.status_code == 403


@pytest.mark.anyio
async def test_finding_remediation_transitions_and_audits_actor():
    client, repository, finding_id = make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/findings/{finding_id}/remediation",
            headers={"Authorization": f"Bearer {token}"},
            json={"state": "MITIGATED", "rationale": "remediation verified"},
        )
    assert response.status_code == 200
    assert response.json() == {
        "finding_id": str(finding_id),
        "action": "REMEDIATE",
        "state": "MITIGATED",
        "changed": True,
    }
    assert repository.finding_states[finding_id] is FindingState.MITIGATED
    event = repository.audit_events[-1]
    assert event.action == "FINDING_REMEDIATION"
    assert event.outcome == "SUCCESS"
    assert event.actor_user_id == repository.users["operator"].id


@pytest.mark.anyio
async def test_finding_remediation_rejects_invalid_transition_and_audits_denial():
    client, repository, finding_id = make_client()
    repository.finding_states[finding_id] = FindingState.SUSPECTED
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/findings/{finding_id}/remediation",
            headers={"Authorization": f"Bearer {token}"},
            json={"state": "MITIGATED", "rationale": "fix verified"},
        )
    assert response.status_code == 409
    assert repository.finding_states[finding_id] is FindingState.SUSPECTED
    event = repository.audit_events[-1]
    assert event.action == "FINDING_REMEDIATION"
    assert event.outcome == "DENIED"
    assert event.actor_user_id == repository.users["operator"].id


@pytest.mark.anyio
async def test_finding_remediation_is_idempotent_for_terminal_target():
    client, repository, finding_id = make_client()
    repository.finding_states[finding_id] = FindingState.MITIGATED
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/findings/{finding_id}/remediation",
            headers={"Authorization": f"Bearer {token}"},
            json={"state": "MITIGATED", "rationale": "already verified"},
        )
    assert response.status_code == 200
    assert response.json()["changed"] is False
    assert response.json()["state"] == "MITIGATED"
    assert repository.audit_events[-1].outcome == "NOOP"


@pytest.mark.anyio
async def test_finding_remediation_returns_not_found():
    client, _, _ = make_client()
    missing_id = uuid4()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/findings/{missing_id}/remediation",
            headers={"Authorization": f"Bearer {token}"},
            json={"state": "MITIGATED", "rationale": "fix verified"},
        )
    assert response.status_code == 404
