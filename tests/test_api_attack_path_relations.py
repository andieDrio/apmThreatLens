from datetime import UTC, datetime
from uuid import uuid4

import httpx
import pytest

from threatlens.api.app import create_app
from threatlens.auth.service import AuthenticationService, Role
from threatlens.attack_paths.engine import AttackPathRelation, AttackPathRelationType
from threatlens.domain.models import AuditEvent, Finding, Severity


class FakeRepository:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.audit_events = []
        self.login_attempts = {}
        self.relations = {}
        self.source_asset_id = uuid4()
        self.target_asset_id = uuid4()
        self.evidence_id = uuid4()
        self.analysis_snapshot = {
            "relations": [],
            "findings": [],
            "risk_scores": {},
            "risk_levels": {},
        }

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

    def save_user(self, user):
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
        session_id = self.create_session(user_id, token_hash, expires_at)
        try:
            self.save_audit_event(event)
        except Exception:
            self.sessions.pop(token_hash, None)
            raise
        return session_id

    def session_by_token_hash(self, token_hash):
        return self.sessions.get(token_hash)

    def save_audit_event(self, event: AuditEvent):
        self.audit_events.append(event)

    def save_attack_path_relation_with_audit(self, relation, actor_user_id):
        assert relation.validated is False
        self.relations[relation.id] = {
            "id": relation.id,
            "source_asset_id": relation.source_asset_id,
            "target_asset_id": relation.target_asset_id,
            "relationship_type": relation.relationship_type.value,
            "validated": False,
            "validated_at": None,
            "validated_by": None,
            "evidence_ids": list(relation.evidence_ids),
            "actor_user_id": actor_user_id,
        }

    def validate_attack_path_relation_with_audit(self, relation_id, actor_user_id):
        item = self.relations.get(relation_id)
        if item is None:
            raise KeyError(str(relation_id))
        item["validated"] = True
        item["validated_by"] = actor_user_id
        return True

    def attack_path_analysis_inputs(self, *, entry_asset_ids, objective_asset_ids):
        known_assets = {self.source_asset_id, self.target_asset_id}
        if not set(entry_asset_ids + objective_asset_ids).issubset(known_assets):
            raise KeyError("missing asset")
        return self.analysis_snapshot

    def attack_path_relations_read_model(self, limit=50, offset=0):
        ordered = sorted(
            self.relations.values(),
            key=lambda item: str(item.get("created_at") or ""),
            reverse=True,
        )
        items = ordered[offset : offset + limit]
        return {
            "total": len(ordered),
            "limit": limit,
            "offset": offset,
            "items": items,
        }

    def attack_path_relation_by_id(self, relation_id):
        item = self.relations.get(relation_id)
        if item is None:
            raise KeyError(str(relation_id))
        return item


def make_client(role=Role.ANALYST):
    repository = FakeRepository()
    auth = AuthenticationService(repository)
    auth.create_user("operator", "correct-horse-battery-123", role)
    app = create_app(repository=repository, auth_service=auth)
    client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )
    return client, repository


async def login(client):
    response = await client.post(
        "/api/v1/auth/login",
        json={"username": "operator", "password": "correct-horse-battery-123"},
    )
    assert response.status_code == 200
    return response.json()["access_token"]


@pytest.mark.anyio
async def test_attack_path_relation_creation_requires_assess_permission():
    client, repository = make_client(Role.VIEWER)
    async with client:
        token = await login(client)
        response = await client.post(
            "/api/v1/attack-path/relations",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "source_asset_id": str(repository.source_asset_id),
                "target_asset_id": str(repository.target_asset_id),
                "relationship_type": "NETWORK_REACHABILITY",
                "evidence_ids": [str(repository.evidence_id)],
            },
        )
    assert response.status_code == 403
    assert repository.relations == {}


@pytest.mark.anyio
async def test_attack_path_relation_creation_is_explicit_and_unvalidated():
    client, repository = make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            "/api/v1/attack-path/relations",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "source_asset_id": str(repository.source_asset_id),
                "target_asset_id": str(repository.target_asset_id),
                "relationship_type": "NETWORK_REACHABILITY",
                "evidence_ids": [str(repository.evidence_id)],
            },
        )
    assert response.status_code == 201
    body = response.json()
    assert body["validated"] is False
    assert body["relationship_type"] == "NETWORK_REACHABILITY"
    assert body["evidence_ids"] == [str(repository.evidence_id)]
    relation = repository.relations[next(iter(repository.relations))]
    assert relation["actor_user_id"] == repository.users["operator"].id


@pytest.mark.anyio
async def test_attack_path_relation_rejects_unknown_type_and_self_edge():
    client, repository = make_client()
    async with client:
        token = await login(client)
        headers = {"Authorization": f"Bearer {token}"}
        base = {
            "source_asset_id": str(repository.source_asset_id),
            "target_asset_id": str(repository.target_asset_id),
            "relationship_type": "NETWORK_REACHABILITY",
            "evidence_ids": [str(repository.evidence_id)],
        }
        bad_type = await client.post(
            "/api/v1/attack-path/relations",
            headers=headers,
            json={**base, "relationship_type": "MAGIC_TRUST"},
        )
        self_edge = await client.post(
            "/api/v1/attack-path/relations",
            headers=headers,
            json={**base, "target_asset_id": str(repository.source_asset_id)},
        )
    assert bad_type.status_code == 422
    assert self_edge.status_code == 422
    assert repository.relations == {}


@pytest.mark.anyio
async def test_attack_path_relation_validation_requires_validate_permission():
    client, repository = make_client(Role.VIEWER)
    relation_id = uuid4()
    repository.relations[relation_id] = {
        "id": relation_id,
        "source_asset_id": repository.source_asset_id,
        "target_asset_id": repository.target_asset_id,
        "relationship_type": "NETWORK_REACHABILITY",
        "validated": False,
        "validated_at": None,
        "validated_by": None,
        "evidence_ids": [repository.evidence_id],
    }
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/attack-path/relations/{relation_id}/validate",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 403
    assert repository.relations[relation_id]["validated"] is False


@pytest.mark.anyio
async def test_attack_path_relation_validation_binds_authenticated_actor():
    client, repository = make_client()
    relation_id = uuid4()
    repository.relations[relation_id] = {
        "id": relation_id,
        "source_asset_id": repository.source_asset_id,
        "target_asset_id": repository.target_asset_id,
        "relationship_type": "NETWORK_REACHABILITY",
        "validated": False,
        "validated_at": None,
        "validated_by": None,
        "evidence_ids": [repository.evidence_id],
    }
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/attack-path/relations/{relation_id}/validate",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["validated"] is True
    assert body["validated_by"] == str(repository.users["operator"].id)


@pytest.mark.anyio
async def test_attack_path_relation_validation_returns_not_found():
    client, repository = make_client()
    async with client:
        token = await login(client)
        response = await client.post(
            f"/api/v1/attack-path/relations/{uuid4()}/validate",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 404


@pytest.mark.anyio
async def test_attack_path_relation_read_model_requires_authentication():
    client, _ = make_client()
    async with client:
        response = await client.get("/api/v1/attack-path/relations")
    assert response.status_code == 401


@pytest.mark.anyio
async def test_attack_path_relation_read_model_returns_bounded_explicit_relationships():
    client, repository = make_client(Role.VIEWER)
    relation_id = uuid4()
    repository.relations[relation_id] = {
        "id": relation_id,
        "source_asset_id": repository.source_asset_id,
        "target_asset_id": repository.target_asset_id,
        "relationship_type": "NETWORK_REACHABILITY",
        "validated": True,
        "created_at": datetime(2026, 10, 13, tzinfo=UTC),
        "validated_at": None,
        "validated_by": None,
        "evidence_ids": [repository.evidence_id],
    }
    async with client:
        token = await login(client)
        response = await client.get(
            "/api/v1/attack-path/relations?limit=10&offset=0",
            headers={"Authorization": f"Bearer {token}"},
        )
        invalid_limit = await client.get(
            "/api/v1/attack-path/relations?limit=101",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["limit"] == 10
    assert body["offset"] == 0
    assert body["items"][0]["id"] == str(relation_id)
    assert body["items"][0]["validated"] is True
    assert body["items"][0]["evidence_ids"] == [str(repository.evidence_id)]
    assert "content" not in body["items"][0]
    assert invalid_limit.status_code == 422



@pytest.mark.anyio
async def test_attack_path_analysis_requires_assess_permission():
    client, repository = make_client(Role.VIEWER)
    async with client:
        token = await login(client)
        response = await client.post(
            "/api/v1/attack-path/analyze",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "entry_asset_ids": [str(repository.source_asset_id)],
                "objective_asset_ids": [str(repository.target_asset_id)],
            },
        )
    assert response.status_code == 403
    assert not any(
        event.action == "ATTACK_PATH_ANALYSIS_COMPLETED"
        for event in repository.audit_events
    )


@pytest.mark.anyio
async def test_attack_path_analysis_uses_validated_evidence_backed_graph_and_audits_actor():
    client, repository = make_client()
    relation = AttackPathRelation(
        source_asset_id=repository.source_asset_id,
        target_asset_id=repository.target_asset_id,
        relationship_type=AttackPathRelationType.NETWORK_REACHABILITY,
        evidence_ids=(repository.evidence_id,),
        validated=True,
    )
    finding = Finding(
        title="Exposed administrative service",
        asset_id=repository.target_asset_id,
        evidence_ids=(repository.evidence_id,),
        severity=Severity.HIGH,
        confidence=0.95,
        source="test-provider",
    )
    repository.analysis_snapshot = {
        "relations": [relation],
        "findings": [finding],
        "risk_scores": {finding.id: 0.82},
        "risk_levels": {finding.id: "HIGH"},
    }
    async with client:
        token = await login(client)
        response = await client.post(
            "/api/v1/attack-path/analyze",
            headers={"Authorization": f"Bearer {token}"},
            json={
                "entry_asset_ids": [str(repository.source_asset_id)],
                "objective_asset_ids": [str(repository.target_asset_id)],
                "max_hops": 4,
                "max_paths": 10,
            },
        )
    assert response.status_code == 200
    body = response.json()
    assert len(body["paths"]) == 1
    assert body["paths"][0]["asset_ids"] == [
        str(repository.source_asset_id),
        str(repository.target_asset_id),
    ]
    assert body["paths"][0]["relation_ids"] == [str(relation.id)]
    assert body["paths"][0]["finding_ids"] == [str(finding.id)]
    assert body["paths"][0]["score"] == 0.82
    event = repository.audit_events[-1]
    assert event.action == "ATTACK_PATH_ANALYSIS_COMPLETED"
    assert event.actor_user_id == repository.users["operator"].id


@pytest.mark.anyio
async def test_attack_path_analysis_rejects_duplicate_or_overlapping_asset_sets():
    client, repository = make_client()
    async with client:
        token = await login(client)
        headers = {"Authorization": f"Bearer {token}"}
        duplicate = await client.post(
            "/api/v1/attack-path/analyze",
            headers=headers,
            json={
                "entry_asset_ids": [
                    str(repository.source_asset_id),
                    str(repository.source_asset_id),
                ],
                "objective_asset_ids": [str(repository.target_asset_id)],
            },
        )
        overlapping = await client.post(
            "/api/v1/attack-path/analyze",
            headers=headers,
            json={
                "entry_asset_ids": [str(repository.source_asset_id)],
                "objective_asset_ids": [str(repository.source_asset_id)],
            },
        )
    assert duplicate.status_code == 422
    assert overlapping.status_code == 422
