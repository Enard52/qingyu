import json, shutil
from pathlib import Path
from .zip_staging import safe_extract, ZipLimits, UnsafeZipError
from .service import ImportService
from .generic import ParserRegistry
from .worker import ImportWorker, LeaseLost
from ..models import ArchiveObject

class ImportProcessor:
    def __init__(self, db, archive_root: Path, limits: ZipLimits = ZipLimits()): self.db, self.root, self.limits = db, archive_root, limits
    def process(self, job, token) -> dict:
        worker = ImportWorker(self.db); worker.assert_ownership(job, token)
        obj = self.db.get(ArchiveObject, job.archive_object_id)
        if obj is None: raise ValueError("archive_object_missing")
        source = self.root / obj.relative_path
        attempt = Path(worker.attempt_staging_path(self.root, job)); attempt.mkdir(parents=True, exist_ok=True)
        keep = False
        try:
            if source.suffix.lower() == ".zip" or obj.media_type == "application/zip":
                scan = safe_extract(source, attempt, self.limits)
                files = list(attempt.rglob("*")); candidates = [p for p in files if p.is_file() and p.suffix.lower() == ".json" and p.name in {"fixture.json", "conversations.json"}]
                unknown = [str(p.relative_to(attempt)) for p in files if p.is_file() and p not in candidates]
                if not candidates: raise UnsupportedStructure("unsupported_structure")
                payload = json.loads(candidates[0].read_text(encoding="utf-8"))
                detection, parser = ParserRegistry().detect(payload)
                if detection != "matched": raise UnsupportedStructure(detection)
                report = ImportService(self.db).import_fixture(payload, job.archive_object_id, job=job, lease_token=token)
                result = dict(report.report_json); result.update({"scan": scan, "unknown": [{"type":"unknown_file","detail":x,"severity":"info"} for x in unknown]}); job.report_json = result; job.result_code = "imported"; self.db.commit(); return result
            raise UnsupportedStructure("unsupported_structure")
        except UnsupportedStructure:
            keep = True; worker.mark_failed(job, token, "unsupported_structure", {"unknown": [{"type":"unsupported_structure","detail":"no registered parser matched","severity":"error"}]}); job.result_code = "unsupported_structure"; self.db.commit(); raise
        finally:
            if not keep: shutil.rmtree(attempt, ignore_errors=True)

class UnsupportedStructure(ValueError): pass
