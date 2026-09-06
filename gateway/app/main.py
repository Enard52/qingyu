from typing import Annotated
from fastapi import Depends, FastAPI
from .auth import require_token
from .config import get_settings
from .logging_config import configure_logging

settings = get_settings()
configure_logging(settings.log_level)
app = FastAPI(title=settings.app_name, version="0.1.0")

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name, "version": "0.1.0"}

@app.get("/api/v1/protected-ping")
def protected_ping(_: Annotated[None, Depends(require_token)]) -> dict[str, str]:
    return {"status": "ok"}
