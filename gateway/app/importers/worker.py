from datetime import datetime, timezone, timedelta
import uuid
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from ..models import ImportJob

class ImportWorker:
    def __init__(self, db: Session): self.db = db
    def recover_stale(self) -> int:
        now = datetime.now(timezone.utc); jobs = self.db.scalars(select(ImportJob).where(ImportJob.status == "running", ImportJob.lease_expires_at < now)).all()
        for j in jobs:
            j.lease_token = None
            if j.attempt_count < j.max_attempts: j.status = "pending"; j.error_summary = "retry_after_stale: lease_expired"
            else: j.status = "failed"; j.finished_at = now; j.error_summary = "worker_crash: lease_expired"
        self.db.commit(); return len(jobs)
    def claim_next(self, lease_duration: int = 300) -> ImportJob | None:
        job = self.db.scalar(select(ImportJob).where(ImportJob.status == "pending").order_by(ImportJob.created_at).with_for_update(skip_locked=True))
        if job is None: return None
        now = datetime.now(timezone.utc); job.status = "running"; job.started_at = job.started_at or now; job.first_started_at = job.first_started_at or now; job.last_attempt_started_at = now; job.attempt_count += 1; job.last_heartbeat_at = now; job.lease_expires_at = now + timedelta(seconds=lease_duration); job.lease_token = uuid.uuid4(); self.db.commit(); return job
    def _owned(self, job, token, values: dict) -> bool:
        result = self.db.execute(update(ImportJob).where(ImportJob.id == job.id, ImportJob.status == "running", ImportJob.lease_token == token).values(**values)); self.db.commit(); return result.rowcount == 1

    def assert_ownership(self, job, token) -> None:
        now = datetime.now(timezone.utc)
        current = self.db.scalar(select(ImportJob).where(ImportJob.id == job.id, ImportJob.status == "running", ImportJob.lease_token == token, ImportJob.lease_expires_at > now))
        if current is None: raise LeaseLost("ownership_lost")

    def attempt_staging_path(self, root, job) -> str:
        self.assert_ownership(job, job.lease_token)
        return str(root / "staging" / str(job.id) / str(job.attempt_count) / str(job.lease_token))
    def heartbeat(self, job, token, lease_duration: int = 300) -> bool:
        now = datetime.now(timezone.utc); return self._owned(job, token, {"last_heartbeat_at": now, "lease_expires_at": now + timedelta(seconds=lease_duration)})
    def update_progress(self, job, token, checkpoint: dict) -> bool: return self._owned(job, token, {"checkpoint": checkpoint})
    def mark_completed(self, job, token, report: dict | None = None) -> bool: return self._owned(job, token, {"status": "completed", "finished_at": datetime.now(timezone.utc), "report_json": report or {}})
    def mark_failed(self, job, token, error: str, report: dict | None = None) -> bool: return self._owned(job, token, {"status": "failed", "finished_at": datetime.now(timezone.utc), "error_summary": error, "report_json": report or {}})

class LeaseLost(RuntimeError):
    pass
