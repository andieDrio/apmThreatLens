from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from threatlens.api.app import create_app
from threatlens.auth.service import AuthenticationService, Role
from threatlens.domain.models import AuditEvent, Campaign, LifecycleState, Scope, Scan, User
from threatlens.providers.runtime import ProviderMetadata, ProviderRegistry, ProviderCapability


CAMPAIGN_ID = uuid4()


class FakeProvider:
    name = "test-provider"

    def execute(self, campaign, execution_id, cancel_event):
        raise AssertionError("queue control must not execute providers")


class FakeRepository:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.audit_events = []
        self.campaigns = {
            CAMPAIGN_ID: Campaign(
                id=CAMPAIGN_ID,
                name="authorized-campaign",
                scope=Scope(include=("10.0.0.10",)),
                authorized=True,
            )
        }
        self.queued = []

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

    def campaign_by_id(self, campaign_id):
        if campaign_id not in self.campaigns:
            raise KeyError(str(campaign_id))
        return self.campaigns[campaign_id]

    def save_scan_with_audit(self, scan: Scan, event: AuditEvent):
        self.queued.append(scan)
        self.audit_events.append(event)


class FakeOrchestrator:
    def __init__(self, repository):
        self.repository = repository
        self.calls = []

    def queue(self, campaign, provider, principal=None):
        self.calls.append((campaign, provider, principal))
        scan = Scan(campaign_id=campaign.id, provider_name=provider.name)
        self.repository.save_scan_with_audit(
            scan,
            AuditEvent(
                actor_user_id=principal.user_id,
                action="SCAN_QUEUED",
                resource_type="SCAN",
                resource_id=scan.execution_id,
                outcome="SUCCESS",
                detail=f"provider={provider.name}",
            ),
        )
        return scan


def make_client(role=Role.ANALYST):
    repository = FakeRepository()
    auth = AuthenticationService(repository)
    auth.create_user("operator", "correct-horse-battery-123", role)
    orchestrator = FakeOrchestrator(repository)
    registry = ProviderRegistry()
    registry.register(
        ProviderMetadata(
            name="test-provider",
            version="1",
            capabilities=frozenset({ProviderCapability.DISCOVERY}),
        ),
        FakeProvider(),
    )
    app = create_app(
        repository=repository,
        auth_service=auth,
        orchestrator=orchestrator,
        provider_registry=registry,
    )
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
async def test_queue_requires_authentication():
    client, _, _ = make_client()
    async with client:
        response = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            json={"provider_name": "test-provider"},
        )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_queue_requires_assess_permission():
    client, _, _ = make_client(Role.VIEWER)
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers={"Authorization": f"Bearer {token}"},
            json={"provider_name": "test-provider"},
        )
    assert response.status_code == 403


@pytest.mark.anyio
async def test_queue_routes_through_orchestrator_with_authenticated_principal():
    client, repository, orchestrator = make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers={"Authorization": f"Bearer {token}"},
            json={"provider_name": "test-provider"},
        )
    assert response.status_code == 201
    body = response.json()
    assert body["campaign_id"] == str(CAMPAIGN_ID)
    assert body["provider_name"] == "test-provider"
    assert body["state"] == "QUEUED"
    assert len(orchestrator.calls) == 1
    assert orchestrator.calls[0][2].username == "operator"
    assert len(repository.queued) == 1
    assert repository.audit_events[-1].action == "SCAN_QUEUED"


@pytest.mark.anyio
async def test_queue_rejects_unknown_campaign():
    client, _, _ = make_client()
    unknown = uuid4()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/campaigns/{unknown}/scans",
            headers={"Authorization": f"Bearer {token}"},
            json={"provider_name": "test-provider"},
        )
    assert response.status_code == 404


@pytest.mark.anyio
async def test_queue_rejects_unknown_provider():
    client, _, _ = make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers={"Authorization": f"Bearer {token}"},
            json={"provider_name": "not-registered"},
        )
    assert response.status_code == 404


@pytest.mark.anyio
async def test_queue_rejects_malformed_campaign_id():
    client, _, _ = make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            "/api/v1/campaigns/not-a-uuid/scans",
            headers={"Authorization": f"Bearer {token}"},
            json={"provider_name": "test-provider"},
        )
    assert response.status_code == 422


@pytest.mark.anyio
async def test_queue_does_not_execute_provider():
    client, _, orchestrator = make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers={"Authorization": f"Bearer {token}"},
            json={"provider_name": "test-provider"},
        )
    assert response.status_code == 201
    assert orchestrator.calls[0][1].name == "test-provider"
