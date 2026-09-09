from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
import uuid
from sqlalchemy import exists, func, or_, select, update
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker

from ..archive.manifest import sync_manifest_from_archive_object
from ..models import ArchiveObject, ImportBatchCommit, ImportJob
from .status import COMPLETED, FAILED, PARTIAL, PENDING, RETRYABLE_STATUSES, RUNNING


@dataclass(frozen=True)
class ClaimedJob:
    """Commit-stable Worker claim data; accessing it can never issue SQL."""
    job_id: uuid.UUID
    lease_token: uuid.UUID
    attempt_count: int
    source_account_id: uuid.UUID
    archive_object_id: uuid.UUID

    @property
    def id(self):
        return self.job_id

class ImportWorker:
    def __init__(self, db: Session): self.db = db
    def _fresh_session(self) -> Session:
        return sessionmaker(bind=self.db.get_bind(), autoflush=False, expire_on_commit=False)()
    def recover_stale(self) -> int:
        observed = self.db.execute(select(ImportJob.id, ImportJob.lease_token, ImportJob.lease_expires_at, ImportJob.attempt_count, ImportJob.max_attempts).where(ImportJob.status == RUNNING, ImportJob.lease_expires_at <= database_wall_clock())).all()
        self.db.rollback(); recovered = 0
        for job_id, token, expiry, attempts, maximum in observed:
            recovered += int(self.recover_observed(job_id, token, expiry, attempts, maximum))
        return recovered

    def recover_observed(self, job_id, token, expiry, attempts, maximum) -> bool:
        with self._fresh_session() as lifecycle:
            with lifecycle.begin():
                owned = lifecycle.scalar(
                    select(ImportJob)
                    .where(
                        ImportJob.id == job_id,
                        ImportJob.status == RUNNING,
                        ImportJob.lease_token == token,
                        ImportJob.lease_expires_at == expiry,
                        ImportJob.lease_expires_at <= database_wall_clock(),
                        ImportJob.attempt_count == attempts,
                        ImportJob.max_attempts == maximum,
                    )
                    .with_for_update()
                )
                if owned is None:
                    return False
                owned.lease_token = None
                owned.lease_expires_at = None
                if owned.attempt_count < owned.max_attempts:
                    owned.status = PENDING
                    owned.error_summary = "retry_after_stale: lease_expired"
                    return True

                batches = lifecycle.scalars(
                    select(ImportBatchCommit)
                    .where(ImportBatchCommit.import_job_id == job_id)
                    .order_by(ImportBatchCommit.sequence_no)
                ).all()
                terminal, durable_counts, terminal_report = durable_terminal_state(
                    batches, owned.report_json
                )
                owned.status = terminal
                owned.result_code = terminal
                owned.error_code = "lease_expired"
                owned.finished_at = database_wall_clock()
                owned.error_summary = "worker_crash: lease_expired"
                owned.report_json = terminal_report
                apply_durable_counts(owned, batches, durable_counts)
                return True
    def claim_next(self, lease_duration: int = 300) -> ClaimedJob | None:
        job = self.db.scalar(
            select(ImportJob)
            .where(
                ImportJob.status == PENDING,
                ImportJob.attempt_count < ImportJob.max_attempts,
            )
            .order_by(ImportJob.created_at)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if job is None: return None
        now = datetime.now(timezone.utc)
        token = uuid.uuid4()
        job.status = RUNNING; job.started_at = job.started_at or now; job.first_started_at = job.first_started_at or now; job.last_attempt_started_at = now; job.attempt_count += 1; job.last_heartbeat_at = now; job.lease_expires_at = now + timedelta(seconds=lease_duration); job.lease_token = token
        self.db.flush()
        claimed = ClaimedJob(
            job_id=job.id,
            lease_token=token,
            attempt_count=job.attempt_count,
            source_account_id=job.source_account_id,
            archive_object_id=job.archive_object_id,
        )
        self.db.commit()
        return claimed
    def _owned(self, job, token, values: dict) -> bool:
        job_id = getattr(job, "id", job)
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

    def check_ownership(self, job, token) -> None:
        job_id = getattr(job, "id", job)
        if token is None: raise LeaseRequired("lease_required")
        with self._fresh_session() as lifecycle:
            if lifecycle.scalar(select(ImportJob.id).where(ownership_predicate(job_id, token))) is None:
                raise LeaseLost("ownership_lost")

    def attempt_staging_path(self, root, job) -> str:
        self.check_ownership(job, job.lease_token)
        return str(root / "staging" / str(job.id) / str(job.attempt_count) / str(job.lease_token))
    def heartbeat(self, job, token, lease_duration: int = 300) -> bool:
        return self._owned(job, token, {"last_heartbeat_at": database_wall_clock(), "lease_expires_at": database_wall_clock() + timedelta(seconds=lease_duration)})
    def advance_checkpoint(self, job, token, sequence_no: int, batch_key: str) -> bool:
        job_id = getattr(job, "id", job)
        checkpoint = {"committed_batches": sequence_no, "last_batch_key": batch_key}
        durable_batch = exists(
            select(ImportBatchCommit.id).where(
                ImportBatchCommit.import_job_id == job_id,
                ImportBatchCommit.sequence_no == sequence_no,
                ImportBatchCommit.batch_key == batch_key,
            )
        )
        with self._fresh_session() as lifecycle:
            result = lifecycle.execute(
                update(ImportJob)
                .where(
                    ownership_predicate(job_id, token),
                    ImportJob.checkpoint_sequence < sequence_no,
                    durable_batch,
                )
                .values(checkpoint_sequence=sequence_no, checkpoint=checkpoint)
            )
            if result.rowcount == 1:
                lifecycle.commit()
                return True
            lifecycle.rollback()
        with self._fresh_session() as lifecycle:
            current = lifecycle.scalar(
                select(ImportJob.checkpoint_sequence).where(ownership_predicate(job_id, token))
            )
            return current is not None and current >= sequence_no

    def update_progress(self, job, token, checkpoint: dict) -> bool:
        sequence = checkpoint.get("committed_batches")
        if not isinstance(sequence, int) or sequence < 0:
            raise ValueError("invalid_checkpoint_sequence")
        return self.advance_checkpoint(job, token, sequence, checkpoint.get("last_batch_key", ""))
    def mark_completed(self, job, token, report: dict | None = None, result_code: str = "imported", counts: dict | None = None) -> bool:
        values = {"status": COMPLETED, "finished_at": database_wall_clock(), "report_json": report or {}, "result_code": result_code, "lease_token": None, "lease_expires_at": None}
        values.update(counts or {})
        return self._owned(job, token, values)
    def mark_failed(self, job, token, error: str, report: dict | None = None, result_code: str | None = None) -> bool: return self._owned(job, token, {"status": FAILED, "finished_at": database_wall_clock(), "error_summary": error, "report_json": report or {}, "error_code": error, "result_code": result_code or FAILED, "lease_token": None, "lease_expires_at": None})

    def mark_failed_or_partial(self, job, token, error: str, report: dict | None = None, result_code: str | None = None) -> str:
        job_id = getattr(job, "id", job)
        with self._fresh_session() as lifecycle:
            with lifecycle.begin():
                owned = lifecycle.scalar(select(ImportJob).where(ownership_predicate(job_id, token)).with_for_update())
                if owned is None:
                    raise LeaseLost("ownership_lost")
                batches = lifecycle.scalars(
                    select(ImportBatchCommit)
                    .where(ImportBatchCommit.import_job_id == job_id)
                    .order_by(ImportBatchCommit.sequence_no)
                ).all()
                terminal, durable_counts, terminal_report = durable_terminal_state(batches, report)
                owned.status = terminal
                owned.finished_at = database_wall_clock()
                owned.error_summary = error
                owned.report_json = terminal_report
                owned.error_code = error
                owned.result_code = result_code or terminal
                owned.lease_token = None
                owned.lease_expires_at = None
                apply_durable_counts(owned, batches, durable_counts)
        return terminal

    def retry(
        self,
        job_id,
        expected_parser_name: str | None = None,
        expected_parser_version: str | None = None,
    ) -> bool:
        retry_conditions = [
            ImportJob.id == job_id,
            ImportJob.status.in_(RETRYABLE_STATUSES),
            ImportJob.lease_token.is_(None),
            ImportJob.attempt_count < ImportJob.max_attempts,
            ImportJob.error_code.is_distinct_from("archive_integrity_failure"),
            ImportJob.result_code.is_distinct_from("archive_integrity_failure"),
            exists(
                select(ArchiveObject.id).where(
                    ArchiveObject.id == ImportJob.archive_object_id,
                    ArchiveObject.integrity_status == "verified",
                )
            ),
        ]
        if expected_parser_name is not None:
            retry_conditions.append(
                or_(ImportJob.status != PARTIAL, ImportJob.parser_name == expected_parser_name)
            )
        if expected_parser_version is not None:
            retry_conditions.append(
                or_(ImportJob.status != PARTIAL, ImportJob.parser_version == expected_parser_version)
            )
        with self._fresh_session() as lifecycle:
            result = lifecycle.execute(
                update(ImportJob)
                .where(*retry_conditions)
                .values(
                    status=PENDING,
                    result_code=None,
                    error_code=None,
                    error_summary=None,
                    finished_at=None,
                    lease_expires_at=None,
                )
            )
            if result.rowcount != 1:
                lifecycle.rollback()
                return False
            lifecycle.commit()
            return True

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
                owned_job.status = FAILED
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
        & (ImportJob.status == RUNNING)
        & ImportJob.lease_token.is_not(None)
        & (ImportJob.lease_token == token)
        & ImportJob.lease_expires_at.is_not(None)
        & (ImportJob.lease_expires_at > database_wall_clock())
    )


def durable_terminal_state(batches, report):
    terminal = PARTIAL if batches else FAILED
    durable_counts = {
        key: sum(int(batch.counts_delta.get(key, 0)) for batch in batches)
        for key in ("discovered_count", "imported_count", "skipped_count", "failed_count")
    }
    terminal_report = dict(report or {})
    if batches:
        terminal_report["durable_batches"] = len(batches)
        terminal_report["durable_counts"] = durable_counts
    return terminal, durable_counts, terminal_report


def apply_durable_counts(job, batches, durable_counts):
    if not batches:
        return
    job.discovered_count = durable_counts["discovered_count"]
    job.imported_count = durable_counts["imported_count"]
    job.skipped_count = durable_counts["skipped_count"]
    job.failed_count = durable_counts["failed_count"]
    job.items_discovered = durable_counts["discovered_count"]
    job.items_imported = durable_counts["imported_count"]
    job.items_skipped = durable_counts["skipped_count"]
    job.items_failed = durable_counts["failed_count"]
