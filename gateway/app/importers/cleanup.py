from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import ImportJob
from .status import ACTIVE_STATUSES, TERMINAL_STATUSES


@dataclass
class StagingCleanupResult:
    deleted: list[Path] = field(default_factory=list)
    skipped_active: list[Path] = field(default_factory=list)
    skipped_recent: list[Path] = field(default_factory=list)
    skipped_unknown: list[Path] = field(default_factory=list)
    failed: list[Path] = field(default_factory=list)
    _outcomes: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def record(self, outcome: str, path: Path) -> None:
        path = _lexical_path(path)
        identity = os.path.normcase(str(path))
        if identity in self._outcomes:
            return
        self._outcomes[identity] = outcome
        getattr(self, outcome).append(path)

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
    base = _lexical_path(root / "staging")
    if not base.exists():
        return result
    if _is_link_like(base):
        result.record("skipped_unknown", base)
        return result
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    protected = {_identity(Path(path)) for path in (protected_paths or [])}

    parsed: list[tuple[Path, uuid.UUID, int, uuid.UUID]] = []
    for job_dir in _children(base):
        if _is_link_like(job_dir) or not _is_directory(job_dir):
            result.record("skipped_unknown", job_dir)
            continue
        try:
            job_id = uuid.UUID(job_dir.name)
        except ValueError:
            result.record("skipped_unknown", job_dir)
            continue
        leaves = _attempt_leaves(base, job_dir, result)
        parsed.extend((leaf, job_id, attempt, token) for leaf, attempt, token in leaves)

    job_ids = {job_id for _, job_id, _, _ in parsed}
    jobs = {
        job.id: job
        for job in db.scalars(select(ImportJob).where(ImportJob.id.in_(job_ids))).all()
    } if job_ids else {}
    database_now = db.scalar(select(func.current_timestamp()))

    for path, job_id, attempt, token in parsed:
        if _identity(path) in protected:
            result.record("skipped_active", path)
            continue
        job = jobs.get(job_id)
        if job is not None and _has_active_ownership(job, attempt, token, database_now):
            result.record("skipped_active", path)
            continue
        if job is not None and _has_live_lease(job, database_now):
            result.record("skipped_unknown", path)
            continue
        if job is not None and job.status in ACTIVE_STATUSES:
            result.record("skipped_active", path)
            continue
        if job is not None and job.status not in TERMINAL_STATUSES:
            result.record("skipped_unknown", path)
            continue
        if not _tree_is_safe(path, base):
            result.record("skipped_unknown", path)
            continue
        try:
            modified = datetime.fromtimestamp(os.lstat(path).st_mtime, timezone.utc)
        except OSError:
            result.record("failed", path)
            continue
        if modified >= cutoff:
            result.record("skipped_recent", path)
            continue
        if dry_run:
            result.record("deleted", path)
            continue
        try:
            _quarantine_and_remove(path, base)
            result.record("deleted", path)
        except UnsafeStagingPath:
            result.record("skipped_unknown", path)
        except OSError:
            result.record("failed", path)
    return result


class UnsafeStagingPath(RuntimeError):
    pass


def _lexical_path(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _identity(path: Path) -> str:
    return os.path.normcase(str(_lexical_path(path)))


def _is_link_like(path: Path) -> bool:
    try:
        details = os.lstat(path)
    except OSError:
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = getattr(details, "st_file_attributes", 0)
    return stat.S_ISLNK(details.st_mode) or bool(attributes & reparse_flag) or os.path.ismount(path)


def _is_directory(path: Path) -> bool:
    try:
        return stat.S_ISDIR(os.lstat(path).st_mode)
    except OSError:
        return False


def _children(path: Path) -> list[Path]:
    try:
        with os.scandir(path) as entries:
            return [_lexical_path(Path(entry.path)) for entry in entries]
    except OSError:
        return []


def _inside(path: Path, base: Path) -> bool:
    try:
        _lexical_path(path).relative_to(_lexical_path(base))
        return True
    except ValueError:
        return False


def _has_active_ownership(job: ImportJob, attempt: int, token: uuid.UUID, database_now: datetime) -> bool:
    return (
        job.lease_token is not None
        and job.lease_expires_at is not None
        and job.attempt_count == attempt
        and job.lease_token == token
        and job.lease_expires_at > database_now
    )


def _has_live_lease(job: ImportJob, database_now: datetime) -> bool:
    return (
        job.lease_token is not None
        and job.lease_expires_at is not None
        and job.lease_expires_at > database_now
    )


def _tree_is_safe(candidate: Path, base: Path) -> bool:
    candidate = _lexical_path(candidate)
    base = _lexical_path(base)
    if not _inside(candidate, base):
        return False
    current = candidate
    while current != base:
        if _is_link_like(current):
            return False
        current = current.parent
    stack = [candidate]
    while stack:
        current = stack.pop()
        if not _inside(current, base) or _is_link_like(current):
            return False
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    child = _lexical_path(Path(entry.path))
                    if not _inside(child, candidate) or _is_link_like(child):
                        return False
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(child)
        except OSError:
            return False
    try:
        resolved_base = base.resolve(strict=True)
        resolved_candidate = candidate.resolve(strict=True)
        resolved_candidate.relative_to(resolved_base)
    except (OSError, ValueError):
        return False
    return True


def _restore_quarantine(quarantine: Path, original: Path) -> None:
    if os.path.lexists(quarantine) and not os.path.lexists(original):
        try:
            os.replace(quarantine, original)
        except OSError:
            pass


def _quarantine_and_remove(path: Path, base: Path) -> None:
    quarantine = path.with_name(f".{path.name}.cleanup-{uuid.uuid4()}")
    os.replace(path, quarantine)
    try:
        if not _tree_is_safe(quarantine, base):
            raise UnsafeStagingPath("unsafe_after_quarantine")
        _remove_tree_without_links(quarantine)
    except Exception:
        _restore_quarantine(quarantine, path)
        raise


def _remove_tree_without_links(path: Path) -> None:
    with _directory_identity_guard(path):
        if _is_link_like(path):
            raise UnsafeStagingPath("link_like_path")
        with os.scandir(path) as entries:
            children = [Path(entry.path) for entry in entries]
        for child in children:
            if _is_link_like(child):
                raise UnsafeStagingPath("link_like_entry")
            if _is_directory(child):
                quarantine = child.with_name(f".{child.name}.cleanup-{uuid.uuid4()}")
                os.replace(child, quarantine)
                try:
                    _remove_tree_without_links(quarantine)
                except Exception:
                    _restore_quarantine(quarantine, child)
                    raise
            else:
                os.unlink(child)
    os.rmdir(path)


@contextmanager
def _directory_identity_guard(path: Path):
    """Prevent a Windows directory path from being replaced while traversed."""
    if os.name != "nt":
        yield
        return

    import ctypes
    from ctypes import wintypes

    create_file = ctypes.windll.kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    handle = create_file(
        str(path),
        0x10080,  # DELETE | FILE_READ_ATTRIBUTES
        0x1 | 0x2,  # FILE_SHARE_READ | FILE_SHARE_WRITE; deliberately no DELETE
        None,
        3,  # OPEN_EXISTING
        0x02000000 | 0x00200000,  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
        None,
    )
    invalid_handle = wintypes.HANDLE(-1).value
    if handle in (None, 0, invalid_handle):
        raise OSError(ctypes.get_last_error(), "directory_identity_guard_failed")
    try:
        yield
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def _attempt_leaves(base: Path, job_dir: Path, result: StagingCleanupResult) -> list[tuple[Path, int, uuid.UUID]]:
    leaves = []
    for attempt_dir in _children(job_dir):
        if _is_link_like(attempt_dir) or not _is_directory(attempt_dir) or not attempt_dir.name.isdigit():
            result.record("skipped_unknown", attempt_dir)
            continue
        attempt = int(attempt_dir.name)
        for lease_dir in _children(attempt_dir):
            path = _lexical_path(lease_dir)
            if _is_link_like(lease_dir) or not _is_directory(lease_dir) or not _inside(path, base):
                result.record("skipped_unknown", path)
                continue
            try:
                token = uuid.UUID(lease_dir.name)
            except ValueError:
                result.record("skipped_unknown", path)
                continue
            leaves.append((path, attempt, token))
    return leaves
