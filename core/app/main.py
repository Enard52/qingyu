from __future__ import annotations

from dataclasses import asdict
from functools import lru_cache
from contextlib import asynccontextmanager
import logging

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from .config import Settings, get_settings, require_capability_token
from .control_plane import InMemoryControlPlane, UnavailableControlPlane
from .db import get_db, session_factory
from .errors import CoreError
from .schemas import GenesisRequest, IdentityStatus, MutationRequest, MutationResult
from .services import CoreFoundationService
from .service_factory import build_core_service, CoreRuntimeDependencies
from .control_plane.r1_admission import AdmissionError


logger = logging.getLogger(__name__)
@asynccontextmanager
async def lifespan(application):
    settings = application.state.settings or get_settings()
    if settings.control_plane_backend == "r1_https":
        service = build_core_service(settings, runtime=application.state.runtime)
        # Pending work remains closed until same-ID reconciliation succeeds.
        from starlette.concurrency import run_in_threadpool
        await run_in_threadpool(service.reconcile_pending)
        application.state.service = service
    yield
    service = getattr(application.state, "service", None)
    if service is not None and hasattr(service, "client"):
        service.client.close()


app = FastAPI(title="Qingyu Core", version="0.1.0", lifespan=lifespan)
app.state.settings = None
app.state.runtime = None


@lru_cache
def _authority_for(settings_key: tuple[str, str, str | None]) -> InMemoryControlPlane | UnavailableControlPlane:
    backend, env, store = settings_key
    if backend == "memory":
        return InMemoryControlPlane()
    return UnavailableControlPlane()


def get_service(request: Request, settings: Settings = Depends(get_settings)):
    if not settings.core_database_url:
        raise CoreError("CORE_DATABASE_URL_REQUIRED")
    existing = getattr(request.app.state, "service", None)
    if existing is not None:
        return existing
    return build_core_service(settings, runtime=getattr(request.app.state, "runtime", None))


def _require_governance_capability(
    settings: Settings = Depends(get_settings),
    capability: str | None = Header(default=None, alias="X-Core-Governance-Capability"),
) -> None:
    try:
        require_capability_token(settings, capability)
    except PermissionError as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "governance_capability_required"},
        ) from exc


@app.exception_handler(CoreError)
async def core_error_handler(_request, exc: CoreError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": {"code": exc.code}},
        headers={"Cache-Control": "private, no-store"},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "qingyu-core", "check": "liveness"}


@app.exception_handler(AdmissionError)
async def admission_error(_request, _error):
    return JSONResponse(status_code=503, content={"detail": {"code": "R1_NOT_ADMITTED"}})


@app.get("/health/ready")
def readiness(service=Depends(get_service)):
    status_value = service.identity_status()
    if status_value.status != "READY":
        raise HTTPException(503, "CORE_NOT_READY")
    return {"readiness": "ready"}


@app.get(
    "/api/v1/core/identity/status",
    response_model=IdentityStatus,
    dependencies=[Depends(_require_governance_capability)],
)
def identity_status(service: CoreFoundationService = Depends(get_service)) -> IdentityStatus:
    return service.identity_status()


@app.post(
    "/internal/v1/genesis",
    response_model=dict,
    dependencies=[Depends(_require_governance_capability)],
)
def bootstrap_genesis(
    request: GenesisRequest,
    service: CoreFoundationService = Depends(get_service),
) -> dict:
    result = service.bootstrap_genesis(request)
    return asdict(result)


@app.post(
    "/internal/v1/mutations",
    response_model=MutationResult,
    dependencies=[Depends(_require_governance_capability)],
)
def governed_mutation(
    request: MutationRequest,
    service: CoreFoundationService = Depends(get_service),
) -> MutationResult:
    return service.governed_mutation(request)


def create_app(*, settings: Settings | None = None, runtime: CoreRuntimeDependencies | None = None) -> FastAPI:
    application = FastAPI(title="Qingyu Core", version="0.1.0", lifespan=lifespan)
    # Rebind route dependency providers to this application; sharing APIRoute
    # instances would retain the global app's configuration/capability source.
    application.include_router(app.router)
    application.exception_handlers.update(app.exception_handlers)
    application.state.settings, application.state.runtime = settings, runtime
    if settings is not None:
        application.dependency_overrides[get_settings] = lambda: settings
    return application
