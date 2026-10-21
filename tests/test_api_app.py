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
        self.login_attempts = {}

    def record_login_attempts(
        self, bucket_keys, now, window_seconds=60, audit_limits=None
    ):
        result = {}
        updated_attempts = dict(self.login_attempts)
        pending_audits = []
        for key in sorted(set(bucket_keys)):
            started, count = updated_attempts.get(key, (now, 0))
            if (now - started).total_seconds() >= window_seconds:
                started, count = now, 0
            count += 1
            updated_attempts[key] = (started, count)
            result[key] = (count, started)
            threshold = (audit_limits or {}).get(key)
            if threshold is not None and count == threshold[0] + 1:
                pending_audits.append(
                    AuditEvent(
                        actor_user_id=None,
                        action="LOGIN_RATE_LIMITED",
                        resource_type="AUTH",
                        outcome="DENIED",
                        detail=threshold[1],
                        created_at=now,
                    )
                )
        previous_audit_count = len(self.audit_events)
        try:
            for event in pending_audits:
                self.save_audit_event(event)
        except Exception:
            del self.audit_events[previous_audit_count:]
            raise
        self.login_attempts = updated_attempts
        return result

    def save_user(self, user: User):
        self.users[user.username] = user

    def save_user_with_audit(self, user: User, event: AuditEvent):
        self.save_user(user)
        try:
            self.save_audit_event(event)
        except Exception:
            self.users.pop(user.username, None)
            raise

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

    def create_session_with_audit(self, user_id, token_hash, expires_at, event):
        session_id = uuid4()
        self.sessions[token_hash] = {
            "id": str(session_id), "user_id": str(user_id),
            "expires_at": expires_at, "revoked": False,
        }
        self.audit_events.append(event)
        return session_id

    def session_by_token_hash(self, token_hash):
        return self.sessions.get(token_hash)

    def revoke_session(self, session_id):
        for session in self.sessions.values():
            if session["id"] == str(session_id):
                session["revoked"] = True

    def revoke_session_with_audit(self, session_id, event: AuditEvent):
        previous = {
            token_hash: session["revoked"]
            for token_hash, session in self.sessions.items()
            if session["id"] == str(session_id)
        }
        self.revoke_session(session_id)
        try:
            self.save_audit_event(event)
        except Exception:
            for token_hash, revoked in previous.items():
                self.sessions[token_hash]["revoked"] = revoked
            raise

    def save_audit_event(self, event: AuditEvent):
        self.audit_events.append(event)

    def audit_events_read_model(self, limit=50, offset=0):
        ordered = sorted(
            self.audit_events, key=lambda event: (event.created_at, str(event.id)), reverse=True
        )
        return {
            "total": len(ordered),
            "limit": limit,
            "offset": offset,
            "items": [
                {
                    "id": str(event.id),
                    "actor_user_id": str(event.actor_user_id) if event.actor_user_id else None,
                    "action": event.action[:128],
                    "resource_type": event.resource_type[:128],
                    "resource_id": str(event.resource_id) if event.resource_id else None,
                    "outcome": event.outcome[:32],
                    "created_at": event.created_at,
                }
                for event in ordered[offset : offset + limit]
            ],
        }

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

    def campaign_report_read_model(self, campaign_id):
        if str(campaign_id) != "88888888-8888-8888-8888-888888888888":
            raise KeyError(str(campaign_id))
        return {
            "campaign": self.campaigns_read_model()["items"][0],
            "scan_summary": {"total": 1, "by_state": {"COMPLETED": 1}},
            "finding_summary": {
                "total": 1,
                "by_severity": {"HIGH": 1},
                "by_state": {"SUSPECTED": 1},
                "truncated": False,
            },
            "findings": [
                {
                    "id": "11111111-1111-1111-1111-111111111111",
                    "title": "Missing HSTS",
                    "asset_id": "22222222-2222-2222-2222-222222222222",
                    "asset_canonical_id": "fqdn:example.test",
                    "asset_value": "example.test",
                    "state": "SUSPECTED",
                    "severity": "HIGH",
                    "vulnerability_id": None,
                    "cwe": None,
                    "cve": None,
                    "cvss": None,
                    "confidence": 0.9,
                    "source": "web-assessment",
                    "detected_at": datetime(2026, 10, 7, 7, 0, tzinfo=UTC),
                    "endpoint": "https://example.test/",
                    "parameter": None,
                    "location": "response-header",
                    "latest_risk": None,
                    "evidence": [
                        {
                            "id": "33333333-3333-3333-3333-333333333333",
                            "kind": "http-response",
                            "source": "web-assessment",
                            "captured_at": datetime(2026, 10, 7, 7, 0, tzinfo=UTC).isoformat(),
                            "sha256": "a" * 64,
                        }
                    ],
                    "evidence_total": 1,
                    "evidence_truncated": False,
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
    auth.create_user("admin", "correct-horse-battery-123", Role.ADMIN)
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
async def test_login_rate_limit_blocks_before_password_verification(client):
    payload = {"username": "analyst", "password": "wrong-password"}
    for attempt in range(5):
        response = await client.post(
            "/api/v1/auth/login",
            json=payload,
            headers={"X-Forwarded-For": f"198.51.100.{attempt + 1}"},
        )
        assert response.status_code == 401

    blocked = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )

    assert blocked.status_code == 429
    assert blocked.headers["retry-after"].isdigit()
    assert blocked.json()["detail"] == "too many login attempts; retry later"

    blocked_again = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    assert blocked_again.status_code == 429
    threshold_events = [
        event for event in client._transport.app.state.context.repository.audit_events
        if event.action == "LOGIN_RATE_LIMITED"
    ]
    assert len(threshold_events) == 1
    assert threshold_events[0].detail == "scope=client_username"


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
async def test_campaign_report_requires_authentication(client):
    response = await client.get(
        "/api/v1/campaigns/88888888-8888-8888-8888-888888888888/report"
    )
    assert response.status_code == 401


@pytest.mark.anyio
async def test_campaign_report_download_contains_persisted_summary_and_evidence_refs(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    response = await client.get(
        "/api/v1/campaigns/88888888-8888-8888-8888-888888888888/report",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/json")
    assert "attachment;" in response.headers["content-disposition"]
    report = response.json()
    assert report["schema_version"] == "1"
    assert report["campaign"]["include"] == ["fqdn:example.test", "10.10.10.0/24"]
    assert report["scan_summary"]["by_state"] == {"COMPLETED": 1}
    assert report["finding_summary"]["by_severity"] == {"HIGH": 1}
    assert report["findings"][0]["evidence"][0]["sha256"] == "a" * 64
    assert "content" not in str(report["findings"][0]["evidence"])


@pytest.mark.anyio
async def test_campaign_report_returns_not_found_for_unknown_campaign(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    response = await client.get(
        "/api/v1/campaigns/99999999-9999-9999-9999-999999999999/report",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


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


@pytest.mark.anyio
async def test_audit_events_read_model_requires_authentication(client):
    response = await client.get("/api/v1/audit-events")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_audit_events_read_model_requires_admin_permission(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "analyst", "password": "correct-horse-battery-123"},
    )
    response = await client.get(
        "/api/v1/audit-events",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert response.status_code == 403


@pytest.mark.anyio
async def test_audit_events_read_model_is_bounded_and_excludes_free_text_details(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    response = await client.get(
        "/api/v1/audit-events?limit=1&offset=0",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total"] >= 2
    assert payload["limit"] == 1
    assert payload["offset"] == 0
    assert len(payload["items"]) == 1
    assert set(payload["items"][0]) == {
        "id", "actor_user_id", "action", "resource_type", "resource_id", "outcome", "created_at"
    }
    assert "detail" not in payload["items"][0]
    assert "password_hash" not in payload["items"][0]
    assert "token_hash" not in payload["items"][0]


@pytest.mark.anyio
async def test_audit_events_read_model_rejects_invalid_pagination(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "correct-horse-battery-123"},
    )
    token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert (await client.get("/api/v1/audit-events?limit=101", headers=headers)).status_code == 422
    assert (await client.get("/api/v1/audit-events?limit=0", headers=headers)).status_code == 422
    assert (await client.get("/api/v1/audit-events?offset=-1", headers=headers)).status_code == 422


@pytest.mark.anyio
async def test_audit_events_read_model_empty_page_is_stable(client):
    login = await client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": "correct-horse-battery-123"},
    )
    response = await client.get(
        "/api/v1/audit-events?limit=1&offset=1000",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert response.status_code == 200
    assert response.json()["items"] == []

def test_app_startup_verifies_schema_without_running_migrations(monkeypatch):
    repository = FakeRepository()
    calls = []
    repository.verify_schema_ready = lambda: calls.append("verified")
    repository.verify_runtime_privileges = lambda: calls.append("privileges-verified")
    repository.initialize = lambda: pytest.fail(
        "runtime application startup must not run schema migrations"
    )
    monkeypatch.setenv(
        "THREATLENS_DATABASE_URL", "postgresql://runtime:unused@127.0.0.1/threatlens"
    )
    monkeypatch.setattr(
        "threatlens.api.app.PostgresRepository", lambda _dsn: repository
    )

    create_app()

    assert calls == ["verified", "privileges-verified"]

def test_app_closes_runtime_connection_when_schema_readiness_fails(monkeypatch):
    repository = FakeRepository()
    closed = []

    def fail_readiness():
        raise RuntimeError("schema is not ready")

    repository.verify_schema_ready = fail_readiness
    repository.close = lambda: closed.append(True)
    monkeypatch.setenv(
        "THREATLENS_DATABASE_URL", "postgresql://runtime:unused@127.0.0.1/threatlens"
    )
    monkeypatch.setattr(
        "threatlens.api.app.PostgresRepository", lambda _dsn: repository
    )

    with pytest.raises(RuntimeError, match="schema is not ready"):
        create_app()

    assert closed == [True]


def test_app_closes_runtime_connection_when_privilege_verification_fails(monkeypatch):
    repository = FakeRepository()
    closed = []
    repository.verify_schema_ready = lambda: None

    def fail_privileges():
        raise RuntimeError("unsafe PostgreSQL runtime identity")

    repository.verify_runtime_privileges = fail_privileges
    repository.close = lambda: closed.append(True)
    monkeypatch.setenv(
        "THREATLENS_DATABASE_URL", "postgresql://runtime:unused@127.0.0.1/threatlens"
    )
    monkeypatch.setattr(
        "threatlens.api.app.PostgresRepository", lambda _dsn: repository
    )

    with pytest.raises(RuntimeError, match="unsafe PostgreSQL runtime identity"):
        create_app()

    assert closed == [True]
