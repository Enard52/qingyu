import hashlib
import mimetypes
import os
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from ..models import ArchiveObject, ArchiveObservation
from .manifest import sync_manifest_from_archive_object

SAFE_NAME = re.compile(r"^[^<>:\"/\\|?*\x00-\x1f]+$")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

@dataclass(frozen=True)
class ArchiveResult:
    object_id: uuid.UUID
    sha256: str
    size_bytes: int
    relative_path: str
    duplicate: bool
    manifest_path: Path
    observation_id: uuid.UUID

class ArchiveIntegrityError(IOError): pass
class ArchiveService:
    def __init__(self, root: Path, db: Session, fault_hook=None):
        self.root = root
        self.staging = root / "staging"
        self.objects = root / "archive" / "objects"
        self.manifests = root / "manifests"
        self.db = db
        self.fault_hook = fault_hook or (lambda event: None)

    def archive_file(self, source: Path, original_filename: str | None = None, source_platform: str = "unknown", media_type: str | None = None) -> ArchiveResult:
        if not SAFE_NAME.fullmatch(original_filename or source.name) or Path(original_filename or source.name).name != (original_filename or source.name):
            raise ValueError("非法文件名")
        if not source.is_file():
            raise FileNotFoundError(source)
        self.staging.mkdir(parents=True, exist_ok=True)
        self.objects.mkdir(parents=True, exist_ok=True)
        self.manifests.mkdir(parents=True, exist_ok=True)
        fd, staged_name = tempfile.mkstemp(prefix="incoming-", dir=self.staging)
        os.close(fd)
        staged = Path(staged_name)
        try:
            shutil.copyfile(source, staged)
            size = staged.stat().st_size
            sha = _sha256_file(staged)
            rel = Path("archive") / "objects" / sha[:2] / sha
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            with staged.open("r+b") as staged_file:
                os.fsync(staged_file.fileno())
            try:
                os.link(staged, target)
                duplicate = False
            except FileExistsError:
                duplicate = True
            if duplicate:
                actual = _sha256_file(target)
                if actual != sha:
                    existing_bad = self.db.scalar(select(ArchiveObject).where(ArchiveObject.sha256 == sha))
                    if existing_bad:
                        existing_bad.integrity_status = "integrity_failure"
                        existing_bad.integrity_error = f"digest_mismatch:{actual}"
                        existing_bad.integrity_checked_at = datetime.now(timezone.utc)
                        self.db.commit()
                        self._write_manifest(existing_bad)
                    raise ArchiveIntegrityError(f"archive_integrity_failure: expected={sha} actual={actual}")
            else:
                actual = _sha256_file(target)
                if actual != sha:
                    raise ArchiveIntegrityError("archive_integrity_failure: post_write_digest_mismatch")
            self.fault_hook("file_published")
            self.db.execute(select(func.pg_advisory_xact_lock(func.hashtext(sha))))
            existing = self.db.scalar(select(ArchiveObject).where(ArchiveObject.sha256 == sha, ArchiveObject.size_bytes == size))
            if existing:
                if existing.integrity_status != "verified":
                    self._write_manifest(existing)
                    raise ArchiveIntegrityError("archive_integrity_failure: explicit reverify required")
                existing.integrity_checked_at = datetime.now(timezone.utc)
                object_id = existing.id
                record = existing
            else:
                record = ArchiveObject(sha256=sha, size_bytes=size, relative_path=rel.as_posix(), media_type=media_type or mimetypes.guess_type(source.name)[0] or "application/octet-stream", integrity_status="verified", integrity_checked_at=datetime.now(timezone.utc), metadata_json={})
                self.db.add(record)
                self.db.commit()
                object_id = record.id
            observed_media_type = media_type or mimetypes.guess_type(source.name)[0] or "application/octet-stream"
            observation = ArchiveObservation(archive_object_id=object_id, original_filename=original_filename or source.name, source_platform=source_platform, source_path=str(source), logical_path=original_filename or source.name, metadata_json={"observed_media_type": observed_media_type})
            self.db.add(observation)
            self.db.commit()
            self.fault_hook("database_committed")
            manifest_path = self._write_manifest(record)
            return ArchiveResult(object_id, sha, size, rel.as_posix(), duplicate, manifest_path, observation.id)
        finally:
            if staged.exists():
                staged.unlink()

    def cleanup_staging(self):
        from ..importers.cleanup import cleanup_failed_staging
        return cleanup_failed_staging(self.root, self.db)

    def _write_manifest(self, record: ArchiveObject) -> Path:
        return sync_manifest_from_archive_object(self.root, record)


