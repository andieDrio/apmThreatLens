from hashlib import sha256
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
        self.login_attempts = {}
        self.campaigns = {
            CAMPAIGN_ID: Campaign(
                id=CAMPAIGN_ID,
                name="authorized-campaign",
                scope=Scope(include=("10.0.0.10",)),
                authorized=True,
            )
        }
        self.queued = []
        self.idempotency_records = {}
        self.scan_states = {}
        self.lifecycle_records = {}

    def record_login_attempts(self, bucket_keys, now, window_seconds=60):
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
        session_id = uuid4()
        self.sessions[token_hash] = {
            "id": str(session_id),
            "user_id": str(user_id),
            "expires_at": expires_at,
            "revoked": False,
        }
        try:
            self.audit_events.append(event)
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

    def campaign_by_id(self, campaign_id):
        if campaign_id not in self.campaigns:
            raise KeyError(str(campaign_id))
        return self.campaigns[campaign_id]

    def save_scan_with_audit(self, scan: Scan, event: AuditEvent):
        self.queued.append(scan)
        self.scan_states[scan.execution_id] = scan.state
        self.audit_events.append(event)

    def scan_state(self, execution_id):
        if execution_id not in self.scan_states:
            raise KeyError(str(execution_id))
        return self.scan_states[execution_id]

    def execute_scan_lifecycle_command(
        self,
        execution_id,
        action,
        actor_user_id,
        idempotency_key,
        request_hash,
        stale_after_seconds,
        success_event,
        noop_event,
    ):
        key = (actor_user_id, idempotency_key)
        existing = self.lifecycle_records.get(key)
        if existing is not None:
            if existing[:3] != (action, request_hash, execution_id):
                raise ValueError(
                    "Idempotency-Key was already used for a different lifecycle command"
                )
            return existing[3], False
        if execution_id not in self.scan_states:
            raise KeyError(str(execution_id))
        changed = False
        if action == "CANCEL":
            if self.scan_states[execution_id] in {LifecycleState.QUEUED, LifecycleState.RUNNING}:
                self.scan_states[execution_id] = LifecycleState.CANCELLED
                changed = True
            self.audit_events.append(success_event if changed else noop_event)
        self.lifecycle_records[key] = (action, request_hash, execution_id, changed)
        return changed, True

    def save_scan_with_audit_idempotent(
        self, scan, event, actor_user_id, idempotency_key, request_hash
    ):
        key = (actor_user_id, idempotency_key)
        existing = self.idempotency_records.get(key)
        if existing is not None:
            if existing[0] != request_hash:
                raise ValueError("Idempotency-Key was already used for a different scan request")
            return existing[1], False
        self.queued.append(scan)
        self.scan_states[scan.execution_id] = scan.state
        self.audit_events.append(event)
        self.idempotency_records[key] = (request_hash, scan)
        return scan, True


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

    def queue_idempotent(self, campaign, provider, idempotency_key, principal=None):
        self.calls.append((campaign, provider, principal))
        scan = Scan(campaign_id=campaign.id, provider_name=provider.name)
        event = AuditEvent(
            actor_user_id=principal.user_id,
            action="SCAN_QUEUED",
            resource_type="SCAN",
            resource_id=scan.execution_id,
            outcome="SUCCESS",
            detail=f"provider={provider.name}",
        )
        request_hash = sha256(f"{campaign.id}\n{provider.name}".encode()).hexdigest()
        return self.repository.save_scan_with_audit_idempotent(
            scan, event, principal.user_id, idempotency_key, request_hash
        )

    def cancel_idempotent(self, execution_id, idempotency_key, principal=None):
        request_hash = sha256(f"CANCEL\n{execution_id}".encode()).hexdigest()
        return self.repository.execute_scan_lifecycle_command(
            execution_id,
            "CANCEL",
            principal.user_id,
            idempotency_key,
            request_hash,
            300,
            AuditEvent(
                actor_user_id=principal.user_id,
                action="SCAN_CANCELLED",
                resource_type="SCAN",
                resource_id=execution_id,
                outcome="SUCCESS",
                detail="scan cancellation requested",
            ),
            AuditEvent(
                actor_user_id=principal.user_id,
                action="SCAN_CANCELLED",
                resource_type="SCAN",
                resource_id=execution_id,
                outcome="NOOP",
                detail="scan already terminal",
            ),
        )

    def recover_stale_idempotent(self, execution_id, idempotency_key, principal=None):
        request_hash = sha256(f"RECOVER_STALE\n{execution_id}\n300.0".encode()).hexdigest()
        return self.repository.execute_scan_lifecycle_command(
            execution_id,
            "RECOVER_STALE",
            principal.user_id,
            idempotency_key,
            request_hash,
            300,
            AuditEvent(
                actor_user_id=principal.user_id,
                action="SCAN_RECOVERED_STALE",
                resource_type="SCAN",
                resource_id=execution_id,
                outcome="SUCCESS",
                detail="execution heartbeat lease expired",
            ),
            AuditEvent(
                actor_user_id=principal.user_id,
                action="SCAN_RECOVERED_STALE",
                resource_type="SCAN",
                resource_id=execution_id,
                outcome="NOOP",
                detail="execution heartbeat lease has not expired",
            ),
        )


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
            headers={"Idempotency-Key": "queue-test-key-0001"},
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
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "queue-test-key-0001"},
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
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "queue-test-key-0001"},
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
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "queue-test-key-0001"},
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
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "queue-test-key-0001"},
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
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "queue-test-key-0001"},
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
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "queue-test-key-0001"},
            json={"provider_name": "test-provider"},
        )
    assert response.status_code == 201
    assert orchestrator.calls[0][1].name == "test-provider"


@pytest.mark.anyio
async def test_queue_replays_same_idempotency_key_without_duplicate_scan():
    client, repository, _ = make_client()
    async with client:
        token = await login(client)
        headers = {
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "queue-replay-key-0001",
        }
        first = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers=headers,
            json={"provider_name": "test-provider"},
        )
        replay = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers=headers,
            json={"provider_name": "test-provider"},
        )
    assert first.status_code == replay.status_code == 201
    assert first.json()["execution_id"] == replay.json()["execution_id"]
    assert first.headers["idempotency-replayed"] == "false"
    assert replay.headers["idempotency-replayed"] == "true"
    assert len(repository.queued) == 1
    assert sum(event.action == "SCAN_QUEUED" for event in repository.audit_events) == 1


@pytest.mark.anyio
async def test_queue_rejects_idempotency_key_reused_for_different_request():
    client, repository, _ = make_client()
    second_campaign_id = uuid4()
    repository.campaigns[second_campaign_id] = Campaign(
        id=second_campaign_id,
        name="another-authorized-campaign",
        scope=Scope(include=("10.0.0.11",)),
        authorized=True,
    )
    async with client:
        token = await login(client)
        headers = {
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "queue-conflict-key-0001",
        }
        first = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers=headers,
            json={"provider_name": "test-provider"},
        )
        conflict = await client.post(
            f"/api/v1/campaigns/{second_campaign_id}/scans",
            headers=headers,
            json={"provider_name": "test-provider"},
        )
    assert first.status_code == 201
    assert conflict.status_code == 409
    assert len(repository.queued) == 1


@pytest.mark.anyio
async def test_queue_requires_valid_idempotency_key():
    client, _, _ = make_client()
    async with client:
        token = await login(client)
        missing = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers={"Authorization": f"Bearer {token}"},
            json={"provider_name": "test-provider"},
        )
        malformed = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "bad key",
            },
            json={"provider_name": "test-provider"},
        )
    assert missing.status_code == 422
    assert malformed.status_code == 422


@pytest.mark.anyio
async def test_cancel_replays_lifecycle_command_without_duplicate_audit():
    client, repository, _ = make_client()
    async with client:
        token = await login(client)
        queued = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "queue-before-cancel-0001",
            },
            json={"provider_name": "test-provider"},
        )
        execution_id = queued.json()["execution_id"]
        headers = {
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "cancel-replay-command-0001",
        }
        first = await client.post(f"/api/v1/scans/{execution_id}/cancel", headers=headers)
        replay = await client.post(f"/api/v1/scans/{execution_id}/cancel", headers=headers)
    assert first.status_code == replay.status_code == 200
    assert first.json()["changed"] is replay.json()["changed"] is True
    assert first.headers["idempotency-replayed"] == "false"
    assert replay.headers["idempotency-replayed"] == "true"
    assert replay.json()["state"] == "CANCELLED"
    assert sum(event.action == "SCAN_CANCELLED" for event in repository.audit_events) == 1


@pytest.mark.anyio
async def test_lifecycle_idempotency_key_conflict_returns_409():
    client, _, _ = make_client()
    async with client:
        token = await login(client)
        queued = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "queue-before-conflict-0001",
            },
            json={"provider_name": "test-provider"},
        )
        execution_id = queued.json()["execution_id"]
        headers = {
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "lifecycle-conflict-key-0001",
        }
        first = await client.post(f"/api/v1/scans/{execution_id}/cancel", headers=headers)
        conflict = await client.post(f"/api/v1/scans/{execution_id}/recover-stale", headers=headers)
    assert first.status_code == 200
    assert conflict.status_code == 409


@pytest.mark.anyio
async def test_lifecycle_control_requires_valid_idempotency_key():
    client, _, _ = make_client()
    async with client:
        token = await login(client)
        queued = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "queue-before-missing-0001",
            },
            json={"provider_name": "test-provider"},
        )
        execution_id = queued.json()["execution_id"]
        missing = await client.post(
            f"/api/v1/scans/{execution_id}/cancel",
            headers={"Authorization": f"Bearer {token}"},
        )
        malformed = await client.post(
            f"/api/v1/scans/{execution_id}/cancel",
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": "bad key"},
        )
    assert missing.status_code == 422
    assert malformed.status_code == 422


@pytest.mark.anyio
async def test_stale_recovery_replays_noop_result_without_repeated_audit():
    client, repository, _ = make_client()
    async with client:
        token = await login(client)
        queued = await client.post(
            f"/api/v1/campaigns/{CAMPAIGN_ID}/scans",
            headers={
                "Authorization": f"Bearer {token}",
                "Idempotency-Key": "queue-before-recovery-0001",
            },
            json={"provider_name": "test-provider"},
        )
        execution_id = queued.json()["execution_id"]
        headers = {
            "Authorization": f"Bearer {token}",
            "Idempotency-Key": "recover-stale-replay-0001",
        }
        first = await client.post(f"/api/v1/scans/{execution_id}/recover-stale", headers=headers)
        replay = await client.post(f"/api/v1/scans/{execution_id}/recover-stale", headers=headers)
    assert first.status_code == replay.status_code == 200
    assert first.json()["changed"] is replay.json()["changed"] is False
    assert first.headers["idempotency-replayed"] == "false"
    assert replay.headers["idempotency-replayed"] == "true"
    assert not any(event.action == "SCAN_RECOVERED_STALE" for event in repository.audit_events)
