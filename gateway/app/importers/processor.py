import hashlib, json, shutil
from pathlib import Path
from .zip_staging import safe_extract, ZipLimits
from .service import ImportService
from .generic import ParserRegistry
from .worker import ImportWorker, LeaseLost
from ..models import ArchiveObject

class ImportProcessor:
    def __init__(self, db, archive_root: Path, limits: ZipLimits = ZipLimits()): self.db, self.root, self.limits = db, archive_root, limits
    def process(self, job, token) -> dict:
        worker=ImportWorker(self.db); worker.assert_ownership(job, token)
        obj=self.db.get(ArchiveObject, job.archive_object_id)
        if obj is None: raise ValueError('archive_object_missing')
        if obj.integrity_status != 'verified':
            raise ValueError('archive_integrity_failure')
        source=self.root/obj.relative_path; attempt=Path(worker.attempt_staging_path(self.root, job)); attempt.mkdir(parents=True, exist_ok=True); keep=False
        try:
            if source.suffix.lower() != '.zip' and obj.media_type != 'application/zip': raise UnsupportedStructure('unsupported_structure')
            verified_source = attempt / '_verified_input.zip'
            actual_size, actual_sha = copy_and_verify_archive(source, verified_source)
            if actual_size != obj.size_bytes or actual_sha != obj.sha256:
                raise ArchiveConsumptionIntegrityError(f'archive_integrity_failure: expected={obj.sha256}/{obj.size_bytes} actual={actual_sha}/{actual_size}')
            extract_root = attempt / 'extracted'
            scan=safe_extract(verified_source, extract_root, self.limits)
            files=list(extract_root.rglob('*')); candidates=[p for p in files if p.is_file() and p.suffix.lower()=='.json' and p.name in {'fixture.json','conversations.json'}]
            unknown=[str(p.relative_to(extract_root)) for p in files if p.is_file() and p not in candidates]
            if not candidates: raise UnsupportedStructure('unsupported_structure')
            payload=json.loads(candidates[0].read_text(encoding='utf-8')); detection,_=ParserRegistry().detect(payload)
            if detection != 'matched': raise UnsupportedStructure(detection)
            outcome=ImportService(self.db).import_fixture(payload, job.archive_object_id, job=job, lease_token=token)
            result=dict(outcome.report); result.update({'scan':scan,'unknown':[{'type':'unknown_file','detail':x,'severity':'info','raw_pointer':str(x)} for x in unknown]}); result['imported_messages']=result.get('messages',{}).get('new',0); result['imported_conversations']=result.get('conversations',{}).get('new',0)
            if not worker.mark_completed(job, token, result, 'imported', outcome.counts): raise LeaseLost('ownership_lost')
            return result
        except LeaseLost:
            keep=True; raise
        except ArchiveConsumptionIntegrityError as exc:
            keep=True
            obj.integrity_status='integrity_failure'; obj.integrity_error=str(exc)
            if not worker.mark_failed(job, token, 'archive_integrity_failure', {'errors':[{'type':'archive_integrity_failure','detail':str(exc),'severity':'error'}]}, 'archive_integrity_failure'):
                self.db.rollback(); raise LeaseLost('ownership_lost')
            raise
        except UnsupportedStructure as exc:
            keep=True
            if not worker.mark_failed(job, token, str(exc), {'unknown':[{'type':str(exc),'detail':'no registered parser matched','severity':'error'}]}, str(exc)): raise LeaseLost('ownership_lost')
            raise
        except Exception as exc:
            keep=True
            if not worker.mark_failed(job, token, type(exc).__name__, {'errors':[{'type':'processor_error','detail':str(exc),'severity':'error'}]}): raise LeaseLost('ownership_lost')
            raise
        finally:
            if not keep: shutil.rmtree(attempt, ignore_errors=True)

class UnsupportedStructure(ValueError): pass

class ArchiveConsumptionIntegrityError(IOError): pass


def copy_and_verify_archive(source: Path, destination: Path) -> tuple[int, str]:
    digest = hashlib.sha256(); size = 0
    with source.open('rb') as src, destination.open('xb') as dst:
        for chunk in iter(lambda: src.read(1024 * 1024), b''):
            dst.write(chunk); digest.update(chunk); size += len(chunk)
    return size, digest.hexdigest()
