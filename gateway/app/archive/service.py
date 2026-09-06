import hashlib
import json
import mimetypes
import os
import re
import shutil
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import select
from sqlalchemy.orm import Session
from ..models import ArchiveObject, ArchiveObservation

SAFE_NAME = re.compile(r"^[^<>:\"/\\|?*\x00-\x1f]+$")

@dataclass(frozen=True)
class ArchiveResult:
    object_id: uuid.UUID
    sha256: str
    size_bytes: int
    relative_path: str
    duplicate: bool
    manifest_path: Path

class ArchiveIntegrityError(IOError): pass
class ArchiveService:
    def __init__(self, root: Path, db: Session):
        self.root = root
        self.staging = root / "staging"
        self.objects = root / "archive" / "objects"
        self.manifests = root / "manifests"
        self.db = db

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
            digest = hashlib.sha256()
            with staged.open("rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
            sha = digest.hexdigest()
            rel = Path("archive") / "objects" / sha[:2] / sha
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            duplicate = target.exists()
            if duplicate:
                actual = hashlib.sha256(target.read_bytes()).hexdigest()
                if actual != sha:
                    existing_bad = self.db.scalar(select(ArchiveObject).where(ArchiveObject.sha256 == sha))
                    if existing_bad:
                        existing_bad.integrity_status = "integrity_failure"
                        existing_bad.integrity_error = f"digest_mismatch:{actual}"
                        self.db.commit()
                        self._write_manifest(existing_bad)
                    raise ArchiveIntegrityError(f"archive_integrity_failure: expected={sha} actual={actual}")
            else:
                os.replace(staged, target)
                actual = hashlib.sha256(target.read_bytes()).hexdigest()
                if actual != sha:
                    raise ArchiveIntegrityError("archive_integrity_failure: post_write_digest_mismatch")
            existing = self.db.scalar(select(ArchiveObject).where(ArchiveObject.sha256 == sha, ArchiveObject.size_bytes == size))
            if existing:
                if existing.integrity_status != "verified":
                    self._write_manifest(existing)
                    raise ArchiveIntegrityError("archive_integrity_failure: explicit reverify required")
                object_id = existing.id
                record = existing
            else:
                record = ArchiveObject(sha256=sha, size_bytes=size, relative_path=rel.as_posix(), media_type=media_type or mimetypes.guess_type(source.name)[0] or "application/octet-stream", integrity_status="verified", metadata_json={})
                self.db.add(record)
                self.db.commit()
                object_id = record.id
            self.db.add(ArchiveObservation(archive_object_id=object_id, original_filename=original_filename or source.name, source_platform=source_platform, source_path=str(source), logical_path=original_filename or source.name, metadata_json={}))
            self.db.commit()
            manifest_path = self._write_manifest(record)
            return ArchiveResult(object_id, sha, size, rel.as_posix(), duplicate, manifest_path)
        finally:
            if staged.exists():
                staged.unlink()

    def cleanup_staging(self) -> int:
        count = 0
        if self.staging.exists():
            for path in self.staging.iterdir():
                if path.is_file():
                    path.unlink()
                    count += 1
        return count

    def _write_manifest(self, record: ArchiveObject) -> Path:
        manifest = {
            "manifest_version": 2,
            "object_id": str(record.id),
            "sha256": record.sha256,
            "expected_sha256": record.sha256,
            "size_bytes": record.size_bytes,
            "relative_path": record.relative_path,
            "media_type": record.media_type,
            "integrity_status": record.integrity_status,
            "integrity_checked_at": datetime.now(timezone.utc).isoformat(),
            "integrity_error": record.integrity_error,
        }
        path = self.manifests / f"{record.sha256}.json"
        path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
        return path


