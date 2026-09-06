from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..models import ImportJob

class ImportWorker:
    """Small durable processor loop; no in-memory task state is authoritative."""
    def __init__(self, db: Session):
        self.db = db

    def claim_next(self) -> ImportJob | None:
        job = self.db.scalar(select(ImportJob).where(ImportJob.status == "pending").order_by(ImportJob.created_at).with_for_update(skip_locked=True))
        if job is None:
            return None
        job.status = "running"
        job.started_at = datetime.now(timezone.utc)
        self.db.commit()
        return job

    def mark_failed(self, job: ImportJob, error: str, report: dict | None = None) -> None:
        job.status = "failed"
        job.finished_at = datetime.now(timezone.utc)
        job.error_summary = error
        job.report_json = report or {}
        self.db.commit()
