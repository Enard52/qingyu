from datetime import datetime, timezone, timedelta
import uuid
from sqlalchemy import func, select, update
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from ..archive.manifest import sync_manifest_from_archive_object
from ..models import ArchiveObject, ImportJob

class ImportWorker:
    def __init__(self, db: Session): self.db = db
    def _fresh_session(self) -> Session:
        return sessionmaker(bind=self.db.get_bind(), autoflush=False, expire_on_commit=False)()
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
        job_id = job.id if isinstance(job, ImportJob) else job
        values = {k: (database_wall_clock() if k in {"last_heartbeat_at", "finished_at"} else v) for k, v in values.items()}
        with self._fresh_session() as lifecycle:
            result = lifecycle.execute(update(ImportJob).where(ownership_predicate(job_id, token)).values(**values))
            if result.rowcount != 1:
                lifecycle.rollback()
                return False
            lifecycle.commit()
            return True

    def assert_ownership(self, job, token) -> None:
        if token is None: raise LeaseRequired("lease_required")
        current = self.db.scalar(select(ImportJob).where(ownership_predicate(job.id, token)).with_for_update())
        if current is None:
            self.db.rollback()
            raise LeaseLost("ownership_lost")

    def attempt_staging_path(self, root, job) -> str:
        self.assert_ownership(job, job.lease_token)
        return str(root / "staging" / str(job.id) / str(job.attempt_count) / str(job.lease_token))
    def heartbeat(self, job, token, lease_duration: int = 300) -> bool:
        return self._owned(job, token, {"last_heartbeat_at": database_wall_clock(), "lease_expires_at": database_wall_clock() + timedelta(seconds=lease_duration)})
    def update_progress(self, job, token, checkpoint: dict) -> bool: return self._owned(job, token, {"checkpoint": checkpoint})
    def mark_completed(self, job, token, report: dict | None = None, result_code: str = "imported", counts: dict | None = None) -> bool:
        values = {"status": "completed", "finished_at": database_wall_clock(), "report_json": report or {}, "result_code": result_code, "lease_token": None, "lease_expires_at": None}
        values.update(counts or {})
        return self._owned(job, token, values)
    def mark_failed(self, job, token, error: str, report: dict | None = None, result_code: str | None = None) -> bool: return self._owned(job, token, {"status": "failed", "finished_at": datetime.now(timezone.utc), "error_summary": error, "report_json": report or {}, "error_code": error, "result_code": result_code or "failed", "lease_token": None, "lease_expires_at": None})

    def mark_archive_integrity_failure(
        self,
        *,
        job_id,
        token,
        archive_object_id,
        archive_root: Path,
        integrity_error: str,
        report: dict,
    ) -> None:
        with self._fresh_session() as lifecycle:
            with lifecycle.begin():
                owned_job = lifecycle.scalar(
                    select(ImportJob)
                    .where(ownership_predicate(job_id, token))
                    .with_for_update()
                )
                if owned_job is None:
                    raise LeaseLost("ownership_lost")
                archive = lifecycle.scalar(
                    select(ArchiveObject)
                    .where(ArchiveObject.id == archive_object_id)
                    .with_for_update()
                )
                if archive is None:
                    raise ValueError("archive_object_missing")
                archive.integrity_status = "integrity_failure"
                archive.integrity_error = integrity_error
                archive.integrity_checked_at = database_wall_clock()
                owned_job.status = "failed"
                owned_job.result_code = "archive_integrity_failure"
                owned_job.error_code = "archive_integrity_failure"
                owned_job.error_summary = "archive_integrity_failure"
                owned_job.report_json = report
                owned_job.finished_at = database_wall_clock()
                owned_job.lease_token = None
                owned_job.lease_expires_at = None

            archive = lifecycle.get(ArchiveObject, archive_object_id)
            lifecycle.refresh(archive)
            sync_manifest_from_archive_object(archive_root, archive)

class LeaseLost(RuntimeError):
    pass

class LeaseRequired(RuntimeError):
    pass


def database_wall_clock():
    return func.clock_timestamp()


def ownership_predicate(job_id, token):
    return (
        (ImportJob.id == job_id)
        & (ImportJob.status == "running")
        & ImportJob.lease_token.is_not(None)
        & (ImportJob.lease_token == token)
        & ImportJob.lease_expires_at.is_not(None)
        & (ImportJob.lease_expires_at > database_wall_clock())
    )
