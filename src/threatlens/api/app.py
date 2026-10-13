"""HTTP application boundary for the ThreatLens control plane."""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from threatlens.auth.service import AuthenticationService, Permission
from threatlens.attack_paths.engine import (
    AttackPathAnalyzer,
    AttackPathRelation,
    AttackPathRelationType,
)
from threatlens.evidence.service import EvidenceValidationService
from threatlens.domain.models import AuditEvent, Campaign, FindingState, Scope
from threatlens.evidence.validation import EvidenceValidationState
from threatlens.orchestration.engine import ScanOrchestrator
from threatlens.providers.runtime import ProviderRegistry
from threatlens.risk.engine import RiskContext, RiskEngine
from threatlens.safety.policy import ExecutionPolicy
from threatlens.storage.postgres import PostgresRepository


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int


class ServiceReadModel(BaseModel):
    id: str
    protocol: str
    port: int
    service_name: str | None = None
    version: str | None = None


class AssetReadModel(BaseModel):
    id: str
    canonical_id: str
    asset_type: str
    value: str
    first_seen_at: str
    last_seen_at: str
    services: list[ServiceReadModel]


class AssetListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AssetReadModel]


class FindingReadModel(BaseModel):
    id: str
    title: str
    asset_id: str
    asset_canonical_id: str
    state: str
    severity: str
    vulnerability_id: str | None = None
    cwe: str | None = None
    cve: str | None = None
    cvss: float | None = None
    confidence: float
    source: str
    detected_at: str
    service_id: str | None = None
    service_protocol: str | None = None
    service_port: int | None = None
    service_name: str | None = None
    service_version: str | None = None
    endpoint: str | None = None
    parameter: str | None = None
    location: str | None = None


class FindingListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[FindingReadModel]


class CampaignReadModel(BaseModel):
    id: str
    name: str
    authorized: bool
    state: str
    created_at: str
    include: list[str]
    exclude: list[str]


class CampaignListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[CampaignReadModel]


class ScanReadModel(BaseModel):
    execution_id: str
    campaign_id: str
    campaign_name: str
    provider_name: str
    state: str
    queued_at: str
    started_at: str | None = None
    finished_at: str | None = None
    heartbeat_at: str | None = None
    error: str | None = None


class ScanListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[ScanReadModel]


class DashboardSummary(BaseModel):
    campaigns: int
    assets: int
    services: int
    findings: int
    findings_by_severity: dict[str, int]
    scans_by_state: dict[str, int]


class PrincipalResponse(BaseModel):
    user_id: str
    username: str
    role: str
    session_id: str


class CampaignCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    include: list[str] = Field(min_length=1, max_length=1000)
    exclude: list[str] = Field(default_factory=list, max_length=1000)
    authorized: bool


class CampaignCreateResponse(CampaignReadModel):
    pass


class ScanQueueRequest(BaseModel):
    provider_name: str = Field(min_length=1, max_length=128)


class ScanQueueResponse(BaseModel):
    execution_id: str
    campaign_id: str
    provider_name: str
    state: str


class ScanControlResponse(BaseModel):
    execution_id: str
    action: str
    state: str
    changed: bool


class FindingRemediationRequest(BaseModel):
    state: str
    rationale: str = Field(min_length=1, max_length=4096)


class FindingRemediationResponse(BaseModel):
    finding_id: str
    action: str
    state: str
    changed: bool


class RiskContextRequest(BaseModel):
    exploitability: float | None = Field(default=None, ge=0.0, le=1.0)
    exposure: float | None = Field(default=None, ge=0.0, le=1.0)
    asset_criticality: float | None = Field(default=None, ge=0.0, le=1.0)
    business_impact: float | None = Field(default=None, ge=0.0, le=1.0)
    threat_relevance: float | None = Field(default=None, ge=0.0, le=1.0)
    control_coverage: float | None = Field(default=None, ge=0.0, le=1.0)
    source: str | None = Field(default=None, min_length=1, max_length=256)


class RiskFactorResponse(BaseModel):
    name: str
    score: float
    weight: float
    rationale: str
    source: str
    contribution: float


class RiskAssessmentResponse(BaseModel):
    assessment_id: str
    finding_id: str
    level: str
    score: float
    factors: list[RiskFactorResponse]
    explanation: list[str]
    inputs_used: list[str]
    missing_inputs: list[str]
    context_source: str | None = None

class RiskAssessmentReadModel(BaseModel):
    assessment_id: str
    finding_id: str
    level: str
    score: float
    context: dict[str, object]
    factors: list[RiskFactorResponse]
    explanation: list[str]
    inputs_used: list[str]
    missing_inputs: list[str]
    context_source: str | None = None
    created_at: str


class RiskAssessmentListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[RiskAssessmentReadModel]



class AttackPathRelationReadModel(BaseModel):
    id: str
    source_asset_id: str
    target_asset_id: str
    relationship_type: str
    validated: bool
    evidence_ids: list[str]
    created_at: str
    validated_at: str | None = None
    validated_by: str | None = None


class AttackPathRelationListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[AttackPathRelationReadModel]


class EvidenceReadModel(BaseModel):
    id: str
    kind: str
    source: str
    captured_at: str
    sha256: str
    metadata: dict[str, str]


class EvidenceListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    items: list[EvidenceReadModel]


class AttackPathAnalysisRequest(BaseModel):
    entry_asset_ids: list[UUID] = Field(min_length=1, max_length=100)
    objective_asset_ids: list[UUID] = Field(min_length=1, max_length=100)
    max_hops: int = Field(default=8, ge=1, le=12)
    max_paths: int = Field(default=100, ge=1, le=100)


class AttackPathResultReadModel(BaseModel):
    asset_ids: list[str]
    relation_ids: list[str]
    finding_ids: list[str]
    score: float
    risk_level: str
    explanation: list[str]


class AttackPathAnalysisResponse(BaseModel):
    paths: list[AttackPathResultReadModel]
    ignored_relation_ids: list[str]
    entry_asset_ids: list[str]
    objective_asset_ids: list[str]
    max_hops: int
    max_paths: int


class AttackPathRelationCreateRequest(BaseModel):
    source_asset_id: UUID
    target_asset_id: UUID
    relationship_type: str = Field(min_length=1, max_length=64)
    evidence_ids: list[UUID] = Field(min_length=1, max_length=100)


class AttackPathRelationResponse(BaseModel):
    id: str
    source_asset_id: str
    target_asset_id: str
    relationship_type: str
    validated: bool
    evidence_ids: list[str]
    validated_at: str | None = None
    validated_by: str | None = None


class EvidenceValidationRequest(BaseModel):
    evidence_id: UUID | None = None
    state: str
    rationale: str = Field(min_length=1, max_length=4096)
    supporting_evidence_ids: list[UUID] = Field(default_factory=list, max_length=100)


class EvidenceValidationResponse(BaseModel):
    id: str
    evidence_id: str
    state: str
    validator: str
    rationale: str
    validated_at: str
    supporting_evidence_ids: list[str]


@dataclass(frozen=True, slots=True)
class APIContext:
    repository: object
    auth: AuthenticationService
    orchestrator: ScanOrchestrator
    evidence_validation: EvidenceValidationService
    provider_registry: ProviderRegistry


def create_app(
    repository=None, auth_service=None, orchestrator=None, provider_registry=None
) -> FastAPI:
    """Create the API with injected persistence/auth dependencies."""
    if repository is None:
        dsn = os.getenv("THREATLENS_DATABASE_URL")
        if not dsn:
            raise RuntimeError("THREATLENS_DATABASE_URL is required")
        repository = PostgresRepository(dsn)
        repository.initialize()
    if auth_service is None:
        auth_service = AuthenticationService(repository)
    if orchestrator is None:
        orchestrator = ScanOrchestrator(repository, ExecutionPolicy(), auth_service)
    if provider_registry is None:
        provider_registry = ProviderRegistry()
    context = APIContext(
        repository=repository,
        auth=auth_service,
        orchestrator=orchestrator,
        evidence_validation=EvidenceValidationService(repository),
        provider_registry=provider_registry,
    )

    app = FastAPI(
        title="APM ThreatLens API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.state.context = context

    ui_directory = Path(__file__).resolve().parent.parent / "ui"
    app.mount(
        "/ui/assets",
        StaticFiles(directory=ui_directory / "assets"),
        name="ui-assets",
    )

    @app.get("/", include_in_schema=False)
    def dashboard_ui() -> FileResponse:
        return FileResponse(
            ui_directory / "index.html",
            headers={
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "same-origin",
                "Content-Security-Policy": (
                    "default-src 'self'; script-src 'self'; style-src 'self'; "
                    "connect-src 'self'; img-src 'self' data:; object-src 'none'; "
                    "base-uri 'none'; frame-ancestors 'none'"
                ),
            },
        )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    def principal(
        authorization: str | None = Header(default=None),
    ):
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = authorization[7:].strip()
        try:
            return context.auth.authenticate_session(token)
        except PermissionError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="session is invalid or expired",
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

    def require(permission: Permission):
        def dependency(current=Depends(principal)):
            try:
                context.auth.authorize(current, permission)
            except PermissionError as exc:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
            return current

        return dependency

    @app.post("/api/v1/auth/login", response_model=LoginResponse)
    def login(request: LoginRequest, http_request: Request) -> LoginResponse:
        # Only trust the direct peer address. Forwarded headers require an explicit trusted-proxy
        # boundary and are intentionally ignored here to prevent client-controlled rate-limit keys.
        peer_host = http_request.client.host if http_request.client else "unknown"
        try:
            peer_host = ipaddress.ip_address(peer_host).compressed
        except ValueError:
            peer_host = "unknown"
        normalized_username = request.username.strip().casefold()
        client_key = "client:" + hashlib.sha256(peer_host.encode("utf-8")).hexdigest()
        identity_material = f"{peer_host}\0{normalized_username}".encode()
        identity_key = "identity:" + hashlib.sha256(identity_material).hexdigest()
        rate_limiter = getattr(context.repository, "record_login_attempts", None)
        if not callable(rate_limiter):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="durable login protection unavailable",
            )
        now = datetime.now(UTC)
        attempts = rate_limiter(
            (client_key, identity_key), now=now, window_seconds=60
        )
        limits = {client_key: 30, identity_key: 5}
        exceeded = [
            (key, limits[key], count, window_started_at)
            for key, (count, window_started_at) in attempts.items()
            if count > limits[key]
        ]
        if exceeded:
            # Audit only the threshold crossing, not every blocked request, to avoid turning
            # repeated rejected traffic into unbounded audit writes.
            for key, limit, count, _ in exceeded:
                if count == limit + 1:
                    context.repository.save_audit_event(
                        AuditEvent(
                            actor_user_id=None,
                            action="LOGIN_RATE_LIMITED",
                            resource_type="AUTH",
                            outcome="DENIED",
                            detail="scope=client" if key == client_key else "scope=client_username",
                        )
                    )
            retry_after = max(
                1,
                *(
                    math.ceil(
                        (window_started_at + timedelta(seconds=60) - now).total_seconds()
                    )
                    for _, _, _, window_started_at in exceeded
                ),
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="too many login attempts; retry later",
                headers={"Retry-After": str(retry_after)},
            )
        try:
            _, token = context.auth.authenticate(request.username, request.password)
        except PermissionError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication failed"
            ) from exc
        return LoginResponse(
            access_token=token,
            expires_in=int(context.auth.session_ttl.total_seconds()),
        )

    @app.post("/api/v1/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
    def logout(current=Depends(principal)) -> None:
        context.auth.logout(current)

    @app.get("/api/v1/dashboard/summary", response_model=DashboardSummary)
    def dashboard_summary(current=Depends(require(Permission.READ))) -> DashboardSummary:
        summary = context.repository.dashboard_summary()
        return DashboardSummary(**summary)

    @app.get("/api/v1/assets", response_model=AssetListResponse)
    def assets(
        current=Depends(require(Permission.READ)),
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ) -> AssetListResponse:
        result = context.repository.assets_read_model(limit=limit, offset=offset)
        items = []
        for item in result["items"]:
            normalized = dict(item)
            normalized["first_seen_at"] = item["first_seen_at"].isoformat()
            normalized["last_seen_at"] = item["last_seen_at"].isoformat()
            normalized["services"] = [ServiceReadModel(**service) for service in item["services"]]
            items.append(AssetReadModel(**normalized))
        return AssetListResponse(
            total=result["total"],
            limit=result["limit"],
            offset=result["offset"],
            items=items,
        )

    @app.get("/api/v1/campaigns", response_model=CampaignListResponse)
    def campaigns(
        current=Depends(require(Permission.READ)),
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ) -> CampaignListResponse:
        result = context.repository.campaigns_read_model(limit=limit, offset=offset)
        items = []
        for item in result["items"]:
            normalized = dict(item)
            normalized["created_at"] = item["created_at"].isoformat()
            items.append(CampaignReadModel(**normalized))
        return CampaignListResponse(
            total=result["total"],
            limit=result["limit"],
            offset=result["offset"],
            items=items,
        )

    @app.post(
        "/api/v1/campaigns",
        response_model=CampaignCreateResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_campaign(
        request: CampaignCreateRequest,
        current=Depends(require(Permission.ADMIN)),
    ) -> CampaignCreateResponse:
        if not request.authorized:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="explicit campaign authorization is required",
            )
        try:
            campaign = Campaign(
                name=request.name,
                scope=Scope(
                    include=tuple(request.include),
                    exclude=tuple(request.exclude),
                ),
                authorized=True,
            )
            context.repository.save_campaign_with_audit(campaign, current.user_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        return CampaignCreateResponse(
            id=str(campaign.id),
            name=campaign.name,
            authorized=campaign.authorized,
            state=campaign.state.value,
            created_at=campaign.created_at.isoformat(),
            include=list(campaign.scope.include),
            exclude=list(campaign.scope.exclude),
        )

    @app.post(
        "/api/v1/attack-path/relations",
        response_model=AttackPathRelationResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_attack_path_relation(
        request: AttackPathRelationCreateRequest,
        current=Depends(require(Permission.ASSESS)),
    ) -> AttackPathRelationResponse:
        try:
            relation_type = AttackPathRelationType(request.relationship_type)
            relation = AttackPathRelation(
                source_asset_id=request.source_asset_id,
                target_asset_id=request.target_asset_id,
                relationship_type=relation_type,
                evidence_ids=tuple(request.evidence_ids),
            )
            context.repository.save_attack_path_relation_with_audit(
                relation, current.user_id
            )
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(exc),
            ) from exc
        return AttackPathRelationResponse(
            id=str(relation.id),
            source_asset_id=str(relation.source_asset_id),
            target_asset_id=str(relation.target_asset_id),
            relationship_type=relation.relationship_type.value,
            validated=False,
            evidence_ids=[str(item) for item in relation.evidence_ids],
        )

    @app.post(
        "/api/v1/attack-path/relations/{relation_id}/validate",
        response_model=AttackPathRelationResponse,
    )
    def validate_attack_path_relation(
        relation_id: UUID,
        current=Depends(require(Permission.VALIDATE)),
    ) -> AttackPathRelationResponse:
        try:
            context.repository.validate_attack_path_relation_with_audit(
                relation_id, current.user_id
            )
            item = context.repository.attack_path_relation_by_id(relation_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="attack-path relationship not found",
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(exc),
            ) from exc
        return AttackPathRelationResponse(
            id=str(item["id"]),
            source_asset_id=str(item["source_asset_id"]),
            target_asset_id=str(item["target_asset_id"]),
            relationship_type=str(item["relationship_type"]),
            validated=bool(item["validated"]),
            evidence_ids=[str(value) for value in item["evidence_ids"]],
            validated_at=item["validated_at"].isoformat() if item["validated_at"] else None,
            validated_by=str(item["validated_by"]) if item["validated_by"] else None,
        )

    @app.post(
        "/api/v1/attack-path/analyze",
        response_model=AttackPathAnalysisResponse,
    )
    def analyze_attack_paths(
        request: AttackPathAnalysisRequest,
        current=Depends(require(Permission.ASSESS)),
    ) -> AttackPathAnalysisResponse:
        entry_ids = tuple(request.entry_asset_ids)
        objective_ids = tuple(request.objective_asset_ids)
        if len(set(entry_ids)) != len(entry_ids):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="entry_asset_ids cannot contain duplicates",
            )
        if len(set(objective_ids)) != len(objective_ids):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="objective_asset_ids cannot contain duplicates",
            )
        if set(entry_ids) & set(objective_ids):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="entry and objective assets must be distinct",
            )
        try:
            snapshot = context.repository.attack_path_analysis_inputs(
                entry_asset_ids=entry_ids,
                objective_asset_ids=objective_ids,
            )
            result = AttackPathAnalyzer().analyze(
                entry_asset_ids=entry_ids,
                objective_asset_ids=objective_ids,
                relations=snapshot["relations"],
                findings=snapshot["findings"],
                risk_scores=snapshot["risk_scores"],
                risk_levels=snapshot["risk_levels"],
                max_hops=request.max_hops,
                max_paths=request.max_paths,
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="one or more requested assets do not exist",
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        context.repository.save_audit_event(
            AuditEvent(
                actor_user_id=current.user_id,
                action="ATTACK_PATH_ANALYSIS_COMPLETED",
                resource_type="ATTACK_PATH_ANALYSIS",
                outcome="SUCCESS",
                detail=(
                    f"entry_count={len(entry_ids)};"
                    f"objective_count={len(objective_ids)};"
                    f"path_count={len(result.paths)};"
                    f"ignored_relation_count={len(result.ignored_relation_ids)};"
                    f"max_hops={request.max_hops};max_paths={request.max_paths}"
                ),
            )
        )
        return AttackPathAnalysisResponse(
            paths=[
                AttackPathResultReadModel(
                    asset_ids=[str(value) for value in path.asset_ids],
                    relation_ids=[str(value) for value in path.relation_ids],
                    finding_ids=[str(value) for value in path.finding_ids],
                    score=path.score,
                    risk_level=path.risk_level,
                    explanation=list(path.explanation),
                )
                for path in result.paths
            ],
            ignored_relation_ids=[str(value) for value in result.ignored_relation_ids],
            entry_asset_ids=[str(value) for value in entry_ids],
            objective_asset_ids=[str(value) for value in objective_ids],
            max_hops=request.max_hops,
            max_paths=request.max_paths,
        )

    @app.get(
        "/api/v1/attack-path/relations",
        response_model=AttackPathRelationListResponse,
    )
    def attack_path_relations(
        current=Depends(require(Permission.READ)),
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ) -> AttackPathRelationListResponse:
        result = context.repository.attack_path_relations_read_model(
            limit=limit, offset=offset
        )
        items = [
            AttackPathRelationReadModel(
                id=str(item["id"]),
                source_asset_id=str(item["source_asset_id"]),
                target_asset_id=str(item["target_asset_id"]),
                relationship_type=str(item["relationship_type"]),
                validated=bool(item["validated"]),
                evidence_ids=[str(value) for value in item["evidence_ids"]],
                created_at=item["created_at"].isoformat(),
                validated_at=(
                    item["validated_at"].isoformat() if item["validated_at"] else None
                ),
                validated_by=(
                    str(item["validated_by"]) if item["validated_by"] else None
                ),
            )
            for item in result["items"]
        ]
        return AttackPathRelationListResponse(
            total=result["total"],
            limit=result["limit"],
            offset=result["offset"],
            items=items,
        )

    @app.get("/api/v1/evidence", response_model=EvidenceListResponse)
    def evidence(
        current=Depends(require(Permission.READ)),
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ) -> EvidenceListResponse:
        result = context.repository.evidence_read_model(limit=limit, offset=offset)
        items = [
            EvidenceReadModel(
                id=item["id"],
                kind=item["kind"],
                source=item["source"],
                captured_at=item["captured_at"].isoformat(),
                sha256=item["sha256"],
                metadata=dict(item["metadata"]),
            )
            for item in result["items"]
        ]
        return EvidenceListResponse(
            total=result["total"],
            limit=result["limit"],
            offset=result["offset"],
            items=items,
        )

    @app.post(
        "/api/v1/evidence/{evidence_id}/validations",
        response_model=EvidenceValidationResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def create_evidence_validation(
        evidence_id: UUID,
        request: EvidenceValidationRequest,
        current=Depends(require(Permission.VALIDATE)),
    ) -> EvidenceValidationResponse:
        try:
            state = EvidenceValidationState(request.state)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="invalid validation state"
            ) from exc
        if state is EvidenceValidationState.SUPERSEDED:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="SUPERSEDED requires an existing validation transition",
            )
        try:
            validation = context.evidence_validation.create(
                evidence_id=evidence_id,
                state=state,
                validator=current.username,
                actor_user_id=current.user_id,
                rationale=request.rationale,
                supporting_evidence_ids=tuple(request.supporting_evidence_ids),
            )
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        return EvidenceValidationResponse(
            id=str(validation.id),
            evidence_id=str(validation.evidence_id),
            state=validation.state.value,
            validator=validation.validator,
            rationale=validation.rationale,
            validated_at=validation.validated_at.isoformat(),
            supporting_evidence_ids=[str(item) for item in validation.supporting_evidence_ids],
        )

    @app.post(
        "/api/v1/evidence/validations/{validation_id}/transition",
        response_model=EvidenceValidationResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def transition_evidence_validation(
        validation_id: UUID,
        request: EvidenceValidationRequest,
        current=Depends(require(Permission.VALIDATE)),
    ) -> EvidenceValidationResponse:
        try:
            state = EvidenceValidationState(request.state)
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="invalid validation state") from exc
        if state is EvidenceValidationState.PENDING:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="PENDING is only valid when creating a validation",
            )
        try:
            if state is EvidenceValidationState.SUPERSEDED:
                if request.evidence_id is None:
                    raise HTTPException(
                        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                        detail="evidence_id is required for lifecycle transitions",
                    )
                validation = context.evidence_validation.supersede(
                    previous_id=validation_id,
                    evidence_id=request.evidence_id,
                    validator=current.username,
                    actor_user_id=current.user_id,
                    rationale=request.rationale,
                    supporting_evidence_ids=tuple(request.supporting_evidence_ids),
                )
            else:
                if request.evidence_id is None:
                    raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="evidence_id is required for lifecycle transitions")
                validation = context.evidence_validation.transition(
                    previous_id=validation_id,
                    evidence_id=request.evidence_id,
                    state=state,
                    validator=current.username,
                    actor_user_id=current.user_id,
                    rationale=request.rationale,
                    supporting_evidence_ids=tuple(request.supporting_evidence_ids),
                )
        except (KeyError, ValueError) as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        return EvidenceValidationResponse(
            id=str(validation.id),
            evidence_id=str(validation.evidence_id),
            state=validation.state.value,
            validator=validation.validator,
            rationale=validation.rationale,
            validated_at=validation.validated_at.isoformat(),
            supporting_evidence_ids=[str(item) for item in validation.supporting_evidence_ids],
        )

    @app.get("/api/v1/scans", response_model=ScanListResponse)
    def scans(
        current=Depends(require(Permission.READ)),
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ) -> ScanListResponse:
        result = context.repository.scans_read_model(limit=limit, offset=offset)
        items = []
        for item in result["items"]:
            normalized = dict(item)
            for field_name in ("queued_at", "started_at", "finished_at", "heartbeat_at"):
                value = item[field_name]
                normalized[field_name] = value.isoformat() if value is not None else None
            items.append(ScanReadModel(**normalized))
        return ScanListResponse(
            total=result["total"],
            limit=result["limit"],
            offset=result["offset"],
            items=items,
        )

    @app.get("/api/v1/findings", response_model=FindingListResponse)
    def findings(
        current=Depends(require(Permission.READ)),
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ) -> FindingListResponse:
        result = context.repository.findings_read_model(limit=limit, offset=offset)
        items = []
        for item in result["items"]:
            normalized = dict(item)
            normalized["detected_at"] = item["detected_at"].isoformat()
            items.append(FindingReadModel(**normalized))
        return FindingListResponse(
            total=result["total"],
            limit=result["limit"],
            offset=result["offset"],
            items=items,
        )

    @app.get(
        "/api/v1/findings/{finding_id}/risk-assessments",
        response_model=RiskAssessmentListResponse,
    )
    def finding_risk_assessments(
        finding_id: UUID,
        current=Depends(require(Permission.READ)),
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
    ) -> RiskAssessmentListResponse:
        try:
            context.repository.finding_by_id(finding_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="finding not found",
            ) from exc

        result = context.repository.risk_assessments_read_model(
            finding_id=finding_id,
            limit=limit,
            offset=offset,
        )
        items = []
        for item in result["items"]:
            items.append(
                RiskAssessmentReadModel(
                    assessment_id=item["assessment_id"],
                    finding_id=item["finding_id"],
                    level=item["level"],
                    score=item["score"],
                    context=dict(item["context"]),
                    factors=[RiskFactorResponse(**factor) for factor in item["factors"]],
                    explanation=list(item["explanation"]),
                    inputs_used=list(item["inputs_used"]),
                    missing_inputs=list(item["missing_inputs"]),
                    context_source=item["context_source"],
                    created_at=item["created_at"].isoformat(),
                )
            )
        return RiskAssessmentListResponse(
            total=result["total"],
            limit=result["limit"],
            offset=result["offset"],
            items=items,
        )

    @app.post(
        "/api/v1/findings/{finding_id}/risk-assessments",
        response_model=RiskAssessmentResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def assess_finding_risk(
        finding_id: UUID,
        request: RiskContextRequest,
        current=Depends(require(Permission.ASSESS)),
    ) -> RiskAssessmentResponse:
        try:
            finding = context.repository.finding_by_id(finding_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="finding not found",
            ) from exc

        try:
            risk_context = RiskContext(
                exploitability=request.exploitability,
                exposure=request.exposure,
                asset_criticality=request.asset_criticality,
                business_impact=request.business_impact,
                threat_relevance=request.threat_relevance,
                control_coverage=request.control_coverage,
                source=request.source,
            )
            assessment = RiskEngine().assess(finding, risk_context)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        context_payload = {
            key: value
            for key, value in {
                "exploitability": request.exploitability,
                "exposure": request.exposure,
                "asset_criticality": request.asset_criticality,
                "business_impact": request.business_impact,
                "threat_relevance": request.threat_relevance,
                "control_coverage": request.control_coverage,
                "source": request.source,
            }.items()
            if value is not None
        }
        assessment_id = context.repository.save_risk_assessment_with_audit(
            assessment, context_payload, current.user_id
        )
        return RiskAssessmentResponse(
            assessment_id=str(assessment_id),
            finding_id=assessment.finding_id,
            level=assessment.level.value,
            score=assessment.score,
            factors=[
                RiskFactorResponse(
                    name=factor.name,
                    score=factor.score,
                    weight=factor.weight,
                    rationale=factor.rationale,
                    source=factor.source,
                    contribution=round(factor.contribution, 4),
                )
                for factor in assessment.factors
            ],
            explanation=list(assessment.explanation),
            inputs_used=list(assessment.inputs_used),
            missing_inputs=list(assessment.missing_inputs),
            context_source=assessment.context_source,
        )

    @app.post(
        "/api/v1/findings/{finding_id}/remediation",
        response_model=FindingRemediationResponse,
    )
    def remediate_finding(
        finding_id: UUID,
        request: FindingRemediationRequest,
        current=Depends(require(Permission.REMEDIATE)),
    ) -> FindingRemediationResponse:
        try:
            target_state = FindingState(request.state)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="invalid finding state",
            ) from exc

        try:
            changed, state, allowed = (
                context.repository.transition_finding_remediation_with_audit(
                    finding_id=finding_id,
                    target_state=target_state,
                    actor_user_id=current.user_id,
                    rationale=request.rationale,
                )
            )
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="finding not found",
            ) from exc

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="invalid finding remediation transition",
            )

        return FindingRemediationResponse(
            finding_id=str(finding_id),
            action="REMEDIATE",
            state=state.value,
            changed=changed,
        )

    @app.post(
        "/api/v1/campaigns/{campaign_id}/scans",
        response_model=ScanQueueResponse,
        status_code=status.HTTP_201_CREATED,
    )
    def queue_scan(
        campaign_id: UUID,
        request: ScanQueueRequest,
        current=Depends(require(Permission.ASSESS)),
    ) -> ScanQueueResponse:
        try:
            campaign = context.repository.campaign_by_id(campaign_id)
            _, provider = context.provider_registry.get(request.provider_name)
            scan = context.orchestrator.queue(campaign, provider, principal=current)
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
        return ScanQueueResponse(
            execution_id=str(scan.execution_id),
            campaign_id=str(scan.campaign_id),
            provider_name=scan.provider_name,
            state=scan.state.value,
        )

    @app.post("/api/v1/scans/{execution_id}/cancel", response_model=ScanControlResponse)
    def cancel_scan(
        execution_id: UUID, current=Depends(require(Permission.ASSESS))
    ) -> ScanControlResponse:
        try:
            changed = context.orchestrator.cancel(execution_id, principal=current)
            state = context.repository.scan_state(execution_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="scan not found"
            ) from exc
        return ScanControlResponse(
            execution_id=str(execution_id),
            action="CANCEL",
            state=state.value,
            changed=changed,
        )

    @app.post("/api/v1/scans/{execution_id}/recover-stale", response_model=ScanControlResponse)
    def recover_stale_scan(
        execution_id: UUID, current=Depends(require(Permission.ASSESS))
    ) -> ScanControlResponse:
        try:
            changed = context.orchestrator.recover_stale(execution_id, principal=current)
            state = context.repository.scan_state(execution_id)
        except KeyError as exc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="scan not found"
            ) from exc
        return ScanControlResponse(
            execution_id=str(execution_id),
            action="RECOVER_STALE",
            state=state.value,
            changed=changed,
        )

    @app.get("/api/v1/me", response_model=PrincipalResponse)
    def me(current=Depends(require(Permission.READ))) -> PrincipalResponse:
        return PrincipalResponse(
            user_id=str(current.user_id),
            username=current.username,
            role=current.role.value,
            session_id=str(current.session_id),
        )

    return app
