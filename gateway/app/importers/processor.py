import hashlib, json, shutil, zipfile
from pathlib import Path
from .zip_staging import safe_extract, ZipLimits
from .service import ImportService
from .generic import ParserRegistry, ParserValidationError
from .worker import ImportWorker, LeaseLost
from ..models import ArchiveObject

class ImportProcessor:
    def __init__(self, db, archive_root: Path, limits: ZipLimits = ZipLimits()): self.db, self.root, self.limits = db, archive_root, limits
    def process(self, job, token) -> dict:
        job_id = job.id
        worker=ImportWorker(self.db); worker.check_ownership(job, token)
        obj=self.db.get(ArchiveObject, job.archive_object_id)
        if obj is None: raise ValueError('archive_object_missing')
        if obj.integrity_status != 'verified':
            raise ValueError('archive_integrity_failure')
        source=self.root/obj.relative_path; attempt=Path(worker.attempt_staging_path(self.root, job)); attempt.mkdir(parents=True, exist_ok=True); keep=False
        try:
            verified_source = attempt / '_verified_input.zip'
            actual_size, actual_sha = copy_and_verify_archive(source, verified_source)
            if actual_size != obj.size_bytes or actual_sha != obj.sha256:
                raise ArchiveConsumptionIntegrityError(
                    archive_object_id=obj.id,
                    expected_sha256=obj.sha256,
                    actual_sha256=actual_sha,
                    expected_size=obj.size_bytes,
                    actual_size=actual_size,
                )
            if not zipfile.is_zipfile(verified_source): raise UnsupportedStructure('unsupported_structure')
            extract_root = attempt / 'extracted'
            scan=safe_extract(verified_source, extract_root, self.limits)
            files=list(extract_root.rglob('*')); candidates=[p for p in files if p.is_file() and p.suffix.lower()=='.json' and p.name in {'fixture.json','conversations.json'}]
            unknown=[str(p.relative_to(extract_root)) for p in files if p.is_file() and p not in candidates]
            if not candidates: raise UnsupportedStructure('unsupported_structure')
            if len(candidates) != 1: raise UnsupportedStructure('ambiguous_structure')
            payload=json.loads(candidates[0].read_text(encoding='utf-8')); detection,parser=ParserRegistry().detect(payload)
            if detection != 'matched': raise UnsupportedStructure(detection)
            source_member = candidates[0].relative_to(extract_root).as_posix()
            unknown_fields = parser.validate(payload, source_member)
            outcome=ImportService(self.db).import_fixture(payload, job.archive_object_id, job=job, lease_token=token, source_member=source_member, parser=parser, unknown_entries=unknown_fields)
            result=dict(outcome.report); result.update({'scan':scan,'unknown':[{'type':'unknown_file','detail':x,'severity':'info','raw_pointer':str(x)} for x in unknown]}); result['imported_messages']=result.get('messages',{}).get('new',0); result['imported_conversations']=result.get('conversations',{}).get('new',0)
            if not worker.mark_completed(job_id, token, result, 'imported', outcome.counts): raise LeaseLost('ownership_lost')
            return result
        except LeaseLost:
            keep=True; self.db.rollback(); raise
        except ArchiveConsumptionIntegrityError as exc:
            keep=True
            self.db.rollback()
            worker.mark_archive_integrity_failure(
                job_id=job_id,
                token=token,
                archive_object_id=exc.archive_object_id,
                archive_root=self.root,
                integrity_error=str(exc),
                report={'errors':[{'type':'archive_integrity_failure','detail':str(exc),'severity':'error'}]},
            )
            raise
        except ParserValidationError as exc:
            keep=True; self.db.rollback()
            report={'errors':[dict(item, severity='error') for item in exc.errors]}
            if not worker.mark_failed(job_id, token, 'parser_validation_error', report, 'parser_validation_error'): raise LeaseLost('ownership_lost')
            raise
        except UnsupportedStructure as exc:
            keep=True
            self.db.rollback()
            if not worker.mark_failed(job_id, token, str(exc), {'unknown':[{'type':str(exc),'detail':'no registered parser matched','severity':'error'}]}, str(exc)): raise LeaseLost('ownership_lost')
            raise
        except Exception as exc:
            keep=True
            self.db.rollback()
            if not worker.mark_failed(job_id, token, type(exc).__name__, {'errors':[{'type':'processor_error','detail':str(exc),'severity':'error'}]}): raise LeaseLost('ownership_lost')
            raise
        finally:
            if not keep: shutil.rmtree(attempt, ignore_errors=True)

class UnsupportedStructure(ValueError): pass

class ArchiveConsumptionIntegrityError(IOError):
    def __init__(self, *, archive_object_id, expected_sha256: str, actual_sha256: str, expected_size: int, actual_size: int):
        self.archive_object_id = archive_object_id
        self.expected_sha256 = expected_sha256
        self.actual_sha256 = actual_sha256
        self.expected_size = expected_size
        self.actual_size = actual_size
        super().__init__(
            f'archive_integrity_failure: expected={expected_sha256}/{expected_size} '
            f'actual={actual_sha256}/{actual_size}'
        )


def copy_and_verify_archive(source: Path, destination: Path) -> tuple[int, str]:
    digest = hashlib.sha256(); size = 0
    with source.open('rb') as src, destination.open('xb') as dst:
        for chunk in iter(lambda: src.read(1024 * 1024), b''):
            dst.write(chunk); digest.update(chunk); size += len(chunk)
    return size, digest.hexdigest()
