def test_worker_module_imports():
    from app.importers.worker import ImportWorker
    assert ImportWorker is not None

def test_stale_job_is_requeued_or_failed():
    from datetime import datetime, timezone, timedelta
    from sqlalchemy.orm import Session
    from app.db import engine
    from app.models import ImportJob, SourceAccount, ArchiveObject
    from app.importers.worker import ImportWorker
    with Session(engine) as db:
        account = SourceAccount(platform="test-worker", account_label="w", metadata_json={})
        archive = ArchiveObject(sha256="a" * 64, size_bytes=0, relative_path="x", media_type="x", integrity_status="verified", metadata_json={})
        db.add_all([account, archive]); db.flush()
        job = ImportJob(source_account_id=account.id, archive_object_id=archive.id, parser_name="x", parser_version="x", status="running", attempt_count=1, max_attempts=3, lease_expires_at=datetime.now(timezone.utc)-timedelta(seconds=1), report_json={})
        db.add(job); db.commit()
        assert ImportWorker(db).recover_stale() == 1
        db.refresh(job)
        assert job.status == "pending"
