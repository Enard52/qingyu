from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ImportJob


@dataclass
class StagingCleanupResult:
    deleted: list[Path] = field(default_factory=list)
    skipped_active: list[Path] = field(default_factory=list)
    skipped_recent: list[Path] = field(default_factory=list)
    skipped_unknown: list[Path] = field(default_factory=list)
    failed: list[Path] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        return {
            "deleted": len(self.deleted),
            "skipped_active": len(self.skipped_active),
            "skipped_recent": len(self.skipped_recent),
            "skipped_unknown": len(self.skipped_unknown),
            "failed": len(self.failed),
        }


def cleanup_failed_staging(
    root: Path,
    db: Session,
    retention_days: int = 7,
    dry_run: bool = False,
    protected_paths=None,
) -> StagingCleanupResult:
    """Clean attempt staging only when database lifecycle proves it inactive."""
    result = StagingCleanupResult()
    base = (root / "staging").resolve()
    if not base.exists():
        return result
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    protected = {Path(path).resolve() for path in (protected_paths or [])}

    parsed: list[tuple[Path, uuid.UUID]] = []
    for job_dir in base.iterdir():
        if not job_dir.is_dir():
            result.skipped_unknown.append(job_dir.resolve())
            continue
        try:
            job_id = uuid.UUID(job_dir.name)
        except ValueError:
            result.skipped_unknown.append(job_dir.resolve())
            continue
        leaves = _attempt_leaves(base, job_dir, result)
        parsed.extend((leaf, job_id) for leaf in leaves)

    job_ids = {job_id for _, job_id in parsed}
    jobs = {
        job.id: job
        for job in db.scalars(select(ImportJob).where(ImportJob.id.in_(job_ids))).all()
    } if job_ids else {}

    for path, job_id in parsed:
        if path in protected:
            result.skipped_active.append(path)
            continue
        job = jobs.get(job_id)
        if job is not None and job.status in {"pending", "running"}:
            result.skipped_active.append(path)
            continue
        if job is not None and job.status not in {"completed", "failed"}:
            result.skipped_unknown.append(path)
            continue
        try:
            modified = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
        except OSError:
            result.failed.append(path)
            continue
        if modified >= cutoff:
            result.skipped_recent.append(path)
            continue
        if dry_run:
            result.deleted.append(path)
            continue
        try:
            shutil.rmtree(path)
            result.deleted.append(path)
        except OSError:
            result.failed.append(path)
    return result


def _attempt_leaves(base: Path, job_dir: Path, result: StagingCleanupResult) -> list[Path]:
    leaves = []
    for attempt_dir in job_dir.iterdir():
        if not attempt_dir.is_dir() or not attempt_dir.name.isdigit():
            result.skipped_unknown.append(attempt_dir.resolve())
            continue
        for lease_dir in attempt_dir.iterdir():
            path = lease_dir.resolve()
            if not lease_dir.is_dir() or base not in path.parents:
                result.skipped_unknown.append(path)
                continue
            try:
                uuid.UUID(lease_dir.name)
            except ValueError:
                result.skipped_unknown.append(path)
                continue
            leaves.append(path)
    return leaves
