from __future__ import annotations

from dataclasses import asdict
from functools import lru_cache
import logging

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import JSONResponse

from .config import Settings, get_settings, require_capability_token
from .control_plane import InMemoryControlPlane, UnavailableControlPlane
from .db import get_db, session_factory
from .errors import CoreError
from .schemas import GenesisRequest, IdentityStatus, MutationRequest, MutationResult
from .services import CoreFoundationService


logger = logging.getLogger(__name__)
app = FastAPI(title="Qingyu Core", version="0.1.0")


@lru_cache
def _authority_for(settings_key: tuple[str, str]) -> InMemoryControlPlane | UnavailableControlPlane:
    backend, env = settings_key
    if backend == "memory":
        return InMemoryControlPlane()
    return UnavailableControlPlane()


def get_service(settings: Settings = Depends(get_settings)) -> CoreFoundationService:
    if not settings.core_database_url:
        raise CoreError("CORE_DATABASE_URL_REQUIRED")
    authority = _authority_for((settings.control_plane_backend, settings.app_env))
    return CoreFoundationService(session_factory(settings), authority)


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
    return {"status": "ok", "service": "qingyu-core"}


@app.get("/api/v1/core/identity/status", response_model=IdentityStatus)
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
