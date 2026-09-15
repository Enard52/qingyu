"""Authenticated HTTPS operation API; canonical signed bytes are the only success."""
from __future__ import annotations

from collections.abc import Callable
import hmac
import ssl
from uuid import UUID

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from .r1_admission import AdmissionError
from .r1_commands import AbortAuthorization, AuthenticatedCaller, CommitAuthorization
from .r1_coordinator import R1Coordinator
from .r1_postgres_store import StoreError
from .r1_protocol import ProtocolError


class ScopedBearerAuthenticator:
    """Secret resolution belongs to the independent Authority process only."""
    def __init__(self, credential_provider: Callable[[], str], caller: AuthenticatedCaller):
        self._credential_provider, self._caller = credential_provider, caller

    def __call__(self, token: str) -> AuthenticatedCaller:
        expected = self._credential_provider()
        if not isinstance(expected, str) or not expected or not hmac.compare_digest(token, expected):
            raise PermissionError("Authority authentication failed")
        return self._caller


def create_authority_app(*, coordinator: R1Coordinator,
                         authenticator: Callable[[str], AuthenticatedCaller]) -> FastAPI:
    if not isinstance(coordinator, R1Coordinator) or not callable(authenticator):
        raise AdmissionError("admitted coordinator and server authentication required")
    app = FastAPI(title="Qingyu R1 Authority", version="1")
    app.state.coordinator = coordinator

    async def caller_for(request: Request) -> AuthenticatedCaller:
        # The supported server disables proxy_headers. Forwarded headers never
        # upgrade HTTP here; direct TLS is the authority of the ASGI scheme.
        if request.scope.get("scheme") != "https":
            raise HTTPException(403, "HTTPS_REQUIRED")
        values = request.headers.getlist("authorization")
        if len(values) != 1 or not values[0].startswith("Bearer "):
            raise HTTPException(401, "AUTHENTICATION_REQUIRED")
        token = values[0][7:]
        if not token or any(ord(ch) < 33 or ord(ch) > 126 for ch in token):
            raise HTTPException(401, "AUTHENTICATION_REQUIRED")
        try:
            caller = authenticator(token)
        except Exception:
            raise HTTPException(401, "AUTHENTICATION_REQUIRED") from None
        if not isinstance(caller, AuthenticatedCaller):
            raise HTTPException(401, "AUTHENTICATION_REQUIRED")
        return caller

    async def body_for(request: Request) -> bytes:
        if request.headers.get("content-type", "").split(";", 1)[0].lower() != "application/json":
            raise HTTPException(415, "CANONICAL_JSON_REQUIRED")
        chunks, size = [], 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > 1_000_000:
                raise HTTPException(413, "REQUEST_TOO_LARGE")
            chunks.append(chunk)
        return b"".join(chunks)

    def operation(value: str) -> str:
        try:
            if str(UUID(value)) != value:
                raise ValueError
        except (ValueError, TypeError):
            raise HTTPException(400, "CANONICAL_OPERATION_ID_REQUIRED") from None
        return value

    def signed(wire: bytes) -> Response:
        return Response(wire, media_type="application/json", headers={"Cache-Control": "private, no-store"})

    @app.exception_handler(ProtocolError)
    async def protocol_error(_request, _error):
        return JSONResponse({"error": "PROTOCOL_REJECTED"}, status_code=409)

    @app.exception_handler(AdmissionError)
    async def admission_error(_request, _error):
        return JSONResponse({"error": "AUTHORITY_NOT_ADMITTED"}, status_code=503)

    @app.exception_handler(StoreError)
    async def store_error(_request, error):
        return JSONResponse({"error": error.code}, status_code=503 if error.code == "DATABASE_UNAVAILABLE" else 409)

    @app.get("/health/live")
    def live():
        return {"liveness": "ok"}

    @app.get("/health/ready")
    def ready():
        coordinator.admission.verify()
        coordinator.admission.check_store(coordinator.store.describe())
        return {"readiness": "admitted"}

    @app.post("/v1/operations")
    async def prepare(request: Request):
        caller = await caller_for(request)
        return signed(await run_in_threadpool(coordinator.prepare, await body_for(request), caller))

    @app.get("/v1/operations/{operation_id}")
    async def query(operation_id: str, request: Request):
        caller = await caller_for(request)
        result = await run_in_threadpool(coordinator.query, operation(operation_id), caller)
        if result is None:
            raise HTTPException(404, "OPERATION_UNKNOWN")
        return signed(result)

    @app.post("/v1/operations/{operation_id}/commit")
    async def commit(operation_id: str, request: Request):
        caller = await caller_for(request)
        authorization = CommitAuthorization.from_wire(await body_for(request))
        return signed(await run_in_threadpool(coordinator.decide, operation(operation_id), authorization, caller))

    @app.post("/v1/operations/{operation_id}/abort")
    async def abort(operation_id: str, request: Request):
        caller = await caller_for(request)
        authorization = AbortAuthorization.from_wire(await body_for(request))
        return signed(await run_in_threadpool(coordinator.decide, operation(operation_id), authorization, caller))

    return app


def authority_server_config(app: FastAPI, *, host: str, port: int,
                            certificate_file: str, private_key_file: str):
    """Build (never start) the supported direct-TLS server; no proxy trust."""
    import uvicorn
    config = uvicorn.Config(app, host=host, port=port, proxy_headers=False,
                            ssl_certfile=certificate_file, ssl_keyfile=private_key_file,
                            ssl_version=ssl.PROTOCOL_TLS_SERVER, log_level="warning")
    config.load()
    config.ssl.minimum_version = ssl.TLSVersion.TLSv1_3
    return config
