from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..models import ImportJob

class ImportWorker:
    """Small durable processor loop; no in-memory task state is authoritative."""
    def __init__(self, db: Session):
        self.db = db

    def recover_stale(self, lease_duration: int = 300) -> int:
        now = datetime.now(timezone.utc)
        jobs = self.db.scalars(select(ImportJob).where(ImportJob.status == "running", ImportJob.lease_expires_at < now)).all()
        for job in jobs:
            if job.attempt_count < job.max_attempts:
                job.status = "pending"; job.error_summary = "retry_after_stale: lease_expired"
            else:
                job.status = "failed"; job.finished_at = now; job.error_summary = "worker_crash: lease_expired"
        self.db.commit()
        return len(jobs)

    def claim_next(self, lease_duration: int = 300) -> ImportJob | None:
        job = self.db.scalar(select(ImportJob).where(ImportJob.status == "pending").order_by(ImportJob.created_at).with_for_update(skip_locked=True))
        if job is None:
            return None
        job.status = "running"
        now = datetime.now(timezone.utc)
        job.started_at = job.started_at or now
        job.attempt_count += 1
        job.last_heartbeat_at = now
        job.lease_expires_at = now + timedelta(seconds=lease_duration)
        self.db.commit()
        return job

    def heartbeat(self, job: ImportJob, lease_duration: int = 300) -> None:
        now = datetime.now(timezone.utc)
        job.last_heartbeat_at = now
        job.lease_expires_at = now + timedelta(seconds=lease_duration)
        self.db.commit()

    def mark_failed(self, job: ImportJob, error: str, report: dict | None = None) -> None:
        job.status = "failed"
        job.finished_at = datetime.now(timezone.utc)
        job.error_summary = error
        job.report_json = report or {}
        self.db.commit()
