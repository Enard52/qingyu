from pathlib import Path
import os
import tempfile
from typing import Annotated
from fastapi import APIRouter, Depends, File, Form, UploadFile
from sqlalchemy.orm import Session
from .auth import require_token
from .config import get_settings
from .db import get_db
from .archive.service import ArchiveService

router = APIRouter(prefix="/api/v1/archive", dependencies=[Depends(require_token)])

@router.post("/objects", status_code=201)
def archive_object(file: UploadFile = File(...), source_platform: str = Form("unknown"), db: Session = Depends(get_db)) -> dict:
    settings = get_settings()
    staging_dir = Path(settings.archive_root) / "staging"
    staging_dir.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="upload-", dir=staging_dir)
    os.close(fd)
    staging_input = Path(name)
    try:
        with staging_input.open("wb") as out:
            while chunk := file.file.read(1024 * 1024):
                out.write(chunk)
        result = ArchiveService(Path(settings.archive_root), db).archive_file(staging_input, file.filename, source_platform, file.content_type)
    finally:
        staging_input.unlink(missing_ok=True)
    return {"object_id": str(result.object_id), "sha256": result.sha256, "size_bytes": result.size_bytes, "relative_path": result.relative_path, "duplicate": result.duplicate, "manifest_path": str(result.manifest_path)}
