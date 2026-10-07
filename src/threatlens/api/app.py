"""HTTP application boundary for the ThreatLens control plane."""

from __future__ import annotations

import os
from dataclasses import dataclass

from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from pydantic import BaseModel, Field

from threatlens.auth.service import AuthenticationService, Permission
from threatlens.orchestration.engine import ScanOrchestrator
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


class ScanControlResponse(BaseModel):
    execution_id: str
    action: str
    state: str
    changed: bool


@dataclass(frozen=True, slots=True)
class APIContext:
    repository: object
    auth: AuthenticationService
    orchestrator: ScanOrchestrator


def create_app(repository=None, auth_service=None, orchestrator=None) -> FastAPI:
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
    context = APIContext(repository=repository, auth=auth_service, orchestrator=orchestrator)

    app = FastAPI(
        title="APM ThreatLens API",
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    app.state.context = context

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
    def login(request: LoginRequest) -> LoginResponse:
        try:
            _, token = context.auth.authenticate(request.username, request.password)
        except PermissionError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
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

    @app.post("/api/v1/scans/{execution_id}/cancel", response_model=ScanControlResponse)
    def cancel_scan(execution_id: str, current=Depends(require(Permission.ASSESS))) -> ScanControlResponse:
        from uuid import UUID

        try:
            parsed_execution_id = UUID(execution_id)
            context.orchestrator.cancel(parsed_execution_id, principal=current)
            state = context.repository.scan_state(parsed_execution_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="invalid execution_id",
            ) from exc
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found") from exc
        return ScanControlResponse(
            execution_id=execution_id,
            action="CANCEL",
            state=state.value,
            changed=state.value == "CANCELLED",
        )

    @app.post("/api/v1/scans/{execution_id}/recover-stale", response_model=ScanControlResponse)
    def recover_stale_scan(
        execution_id: str, current=Depends(require(Permission.ASSESS))
    ) -> ScanControlResponse:
        from uuid import UUID

        try:
            parsed_execution_id = UUID(execution_id)
            changed = context.orchestrator.recover_stale(parsed_execution_id, principal=current)
            state = context.repository.scan_state(parsed_execution_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="invalid execution_id",
            ) from exc
        except KeyError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="scan not found") from exc
        return ScanControlResponse(
            execution_id=execution_id,
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
