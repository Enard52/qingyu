import os
import tempfile
from pathlib import Path
from typing import Annotated
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session
from .auth import require_token
from .config import get_settings
from .db import get_db
from .models import ArchiveObservation, ImportJob, SourceAccount
from .archive.service import ArchiveService
from .importers.generic import GenericTreeParser
from .importers.status import PENDING
from .importers.worker import ImportWorker

router = APIRouter(prefix="/api/v1", dependencies=[Depends(require_token)])

@router.post("/import/chatgpt", status_code=status.HTTP_202_ACCEPTED)
def create_import(file: UploadFile = File(...), source_platform: str = Form("chatgpt"), db: Session = Depends(get_db)) -> dict:
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(415, "仅支持 ZIP 导入")
    root = Path(get_settings().archive_root)
    root.joinpath("staging").mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix="import-upload-", dir=root / "staging")
    os.close(fd)
    temp = Path(name)
    try:
        with temp.open("wb") as out:
            while chunk := file.file.read(1024 * 1024): out.write(chunk)
        archived = ArchiveService(root, db).archive_file(temp, file.filename, source_platform, file.content_type)
        account = db.scalar(select(SourceAccount).where(SourceAccount.platform == source_platform, SourceAccount.account_label == "default"))
        if account is None:
            account = SourceAccount(platform=source_platform, account_label="default", metadata_json={})
            db.add(account); db.flush()
        job = ImportJob(source_account_id=account.id, archive_object_id=archived.object_id, parser_name=GenericTreeParser.name, parser_version=GenericTreeParser.version, status=PENDING, report_json={})
        db.add(job); db.flush()
        observation = db.get(ArchiveObservation, archived.observation_id)
        observation.import_job_id = job.id
        db.commit()
        return {"import_job_id": str(job.id)}
    finally:
        temp.unlink(missing_ok=True)

@router.get("/import-jobs/{job_id}")
def get_import_job(job_id: str, db: Session = Depends(get_db)) -> dict:
    job = db.get(ImportJob, job_id)
    if job is None: raise HTTPException(404, "Import Job not found")
    return {"import_job_id": str(job.id), "status": job.status, "result_code": job.result_code, "error_code": job.error_code, "progress": job.checkpoint, "counts": {"discovered": job.discovered_count, "imported": job.imported_count, "skipped": job.skipped_count, "failed": job.failed_count}, "errors": job.error_summary, "report": job.report_json}


@router.post("/import-jobs/{job_id}/retry", status_code=status.HTTP_202_ACCEPTED)
def retry_import_job(job_id: str, db: Session = Depends(get_db)) -> dict:
    job = db.get(ImportJob, job_id)
    if job is None:
        raise HTTPException(404, "Import Job not found")
    db.rollback()
    if not ImportWorker(db).retry(job_id):
        raise HTTPException(409, "Import Job is not retryable")
    return {"import_job_id": str(job_id), "status": PENDING}

