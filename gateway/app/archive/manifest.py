import json
import os
import tempfile
from pathlib import Path

from ..models import ArchiveObject


def render_manifest(record: ArchiveObject) -> dict:
    return {
        "manifest_version": 2,
        "object_id": str(record.id),
        "sha256": record.sha256,
        "expected_sha256": record.sha256,
        "size_bytes": record.size_bytes,
        "relative_path": record.relative_path,
        "media_type": record.media_type,
        "integrity_status": record.integrity_status,
        "integrity_checked_at": record.integrity_checked_at.isoformat() if record.integrity_checked_at else None,
        "integrity_error": record.integrity_error,
    }


def sync_manifest_from_archive_object(root: Path, record: ArchiveObject) -> Path:
    manifests = root / "manifests"
    manifests.mkdir(parents=True, exist_ok=True)
    target = manifests / f"{record.sha256}.json"
    fd, temporary_name = tempfile.mkstemp(prefix=f".{record.sha256}-", suffix=".tmp", dir=manifests)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(render_manifest(record), output, ensure_ascii=False, indent=2)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)
    return target
