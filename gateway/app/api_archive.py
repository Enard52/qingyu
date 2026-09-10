import logging
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy.orm import Session

from .api_import import _write_upload_with_limit
from .archive.service import ArchiveService
from .auth import require_token
from .config import get_settings
from .db import get_db
from .importers.staging import create_prejob_generation

router = APIRouter(prefix="/api/v1/archive", dependencies=[Depends(require_token)])
logger = logging.getLogger(__name__)


@router.post("/objects", status_code=201)
def archive_object(
    file: UploadFile = File(...),
    source_platform: str = Form("unknown"),
    db: Session = Depends(get_db),
) -> dict:
    settings = get_settings()
    root = Path(settings.archive_root)
    generation = create_prejob_generation(root, "uploads")
    staging_input = generation.payload_path()
    try:
        _write_upload_with_limit(file, staging_input, settings.import_upload_max_bytes)
        result = ArchiveService(root, db).archive_file(
            staging_input,
            file.filename,
            source_platform,
            file.content_type,
        )
    finally:
        cleanup = generation.close(remove=True)
        if cleanup is not None and cleanup.status not in {"deleted", "missing"}:
            logger.warning(
                "archive upload staging cleanup incomplete",
                extra={"cleanup_outcome": cleanup.status},
            )
    return {
        "object_id": str(result.object_id),
        "sha256": result.sha256,
        "size_bytes": result.size_bytes,
        "relative_path": result.relative_path,
        "duplicate": result.duplicate,
        "manifest_path": str(result.manifest_path),
    }
