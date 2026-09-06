from typing import Annotated
from fastapi import Depends, FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
import logging
from .errors import safe_database_error
from .auth import require_token
from .config import get_settings
from .logging_config import configure_logging
from .api_import import router as import_router
from .api_archive import router as archive_router

settings = get_settings()
configure_logging(settings.log_level)
app = FastAPI(title=settings.app_name, version="0.1.0")
app.include_router(archive_router)
app.include_router(import_router)

@app.exception_handler(SQLAlchemyError)
async def database_error_handler(request, exc):
    error_code = safe_database_error(exc)
    logging.getLogger(__name__).error("database operation failed", extra={"error_code": error_code})
    return JSONResponse(status_code=500, content={"detail": {"code": error_code}})

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name, "version": "0.1.0"}

@app.get("/api/v1/protected-ping")
def protected_ping(_: Annotated[None, Depends(require_token)]) -> dict[str, str]:
    return {"status": "ok"}
