import hashlib
import json
import os
import threading
import time
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.db import engine
from app.importers.cleanup import cleanup_failed_staging
from app.importers.worker import ImportWorker
from app.importers.worker_runtime import WorkerRuntime
from app.models import ArchiveObject, Attachment, Conversation, ImportJob, Message, MessageObservation, MessageRevision, SourceAccount
import app.importers.processor as processor_module
import app.importers.cleanup as cleanup_module


def _clear(db):
    for model in (Attachment,MessageObservation,MessageRevision,Message,Conversation,ImportJob,SourceAccount,ArchiveObject): db.execute(delete(model))
    db.commit()


def _job(db,status,lease_expires_at=None):
    account=SourceAccount(platform='cleanup',account_label=str(uuid.uuid4()),metadata_json={})
    archive=ArchiveObject(sha256=uuid.uuid4().hex*2,size_bytes=1,relative_path='unused',media_type='x',integrity_status='verified',metadata_json={})
    db.add_all([account,archive]); db.flush()
    token=uuid.uuid4()
    job=ImportJob(source_account_id=account.id,archive_object_id=archive.id,parser_name='fixture',parser_version='1',status=status,lease_token=token if status=='running' else None,lease_expires_at=lease_expires_at,attempt_count=1,report_json={})
    db.add(job); db.commit()
    return job, token


def _attempt(root,job_id,token,attempt=1,days_old=10):
    path=root/'staging'/str(job_id)/str(attempt)/str(token); path.mkdir(parents=True); (path/'diagnostic').write_text('x')
    stamp=time.time()-days_old*86400; os.utime(path,(stamp,stamp)); return path.resolve()


def test_pending_running_and_expired_running_attempts_are_protected(tmp_path):
    with Session(engine,expire_on_commit=False) as db:
        _clear(db)
        pending,pending_token=_job(db,'pending')
        running,running_token=_job(db,'running',datetime.now(timezone.utc)+timedelta(minutes=5))
        expired,expired_token=_job(db,'running',datetime.now(timezone.utc)-timedelta(minutes=5))
        paths={
            _attempt(tmp_path,pending.id,pending_token),
            _attempt(tmp_path,running.id,running_token),
            _attempt(tmp_path,expired.id,expired_token),
        }
        result=cleanup_failed_staging(tmp_path,db,retention_days=7)
        assert set(result.skipped_active)==paths and not result.deleted
        assert all(path.exists() for path in paths)


def test_terminal_orphan_recent_and_unknown_paths_are_classified(tmp_path):
    with Session(engine,expire_on_commit=False) as db:
        _clear(db)
        completed,completed_token=_job(db,'completed')
        failed,failed_token=_job(db,'failed')
        completed_path=_attempt(tmp_path,completed.id,completed_token)
        failed_path=_attempt(tmp_path,failed.id,failed_token)
        orphan_path=_attempt(tmp_path,uuid.uuid4(),uuid.uuid4())
        recent_path=_attempt(tmp_path,uuid.uuid4(),uuid.uuid4(),days_old=1)
        unknown=tmp_path/'staging'/'not-a-job'; unknown.mkdir(parents=True)
        active_upload=tmp_path/'staging'/'import-upload-active'; active_upload.write_text('upload')
        result=cleanup_failed_staging(tmp_path,db,retention_days=7)
        assert set(result.deleted)=={completed_path,failed_path,orphan_path}
        assert result.skipped_recent==[recent_path]
        assert {unknown.resolve(),active_upload.resolve()} <= set(result.skipped_unknown)
        assert active_upload.exists()
        assert result.counts=={'deleted':3,'skipped_active':0,'skipped_recent':1,'skipped_unknown':2,'failed':0}


def test_cleanup_delete_failure_is_reported_without_silent_success(tmp_path,monkeypatch):
    with Session(engine) as db:
        _clear(db); path=_attempt(tmp_path,uuid.uuid4(),uuid.uuid4())
        monkeypatch.setattr(cleanup_module.shutil,'rmtree',lambda candidate: (_ for _ in ()).throw(PermissionError('busy')))
        result=cleanup_failed_staging(tmp_path,db,7)
        assert result.deleted==[] and result.failed==[path] and path.exists()


def test_expired_attempt_survives_cleanup_recovery_and_retry_claim(tmp_path):
    with Session(engine,expire_on_commit=False) as db:
        _clear(db); job,token_a=_job(db,'running',datetime.now(timezone.utc)-timedelta(minutes=1)); old_path=_attempt(tmp_path,job.id,token_a)
        assert cleanup_failed_staging(tmp_path,db,7).skipped_active==[old_path]
        assert ImportWorker(db).recover_stale()==1
        claim=ImportWorker(db).claim_next(60); assert claim.job_id==job.id and claim.lease_token!=token_a
        new_path=Path(ImportWorker(db).attempt_staging_path(tmp_path,claim)); new_path.mkdir(parents=True)
        result=cleanup_failed_staging(tmp_path,db,7)
        assert set(result.skipped_active)=={old_path,new_path.resolve()}


def test_cleanup_cannot_delete_attempt_while_processor_is_copying(tmp_path,monkeypatch):
    root=tmp_path/'concurrent'; payload={'schema_marker':'qingyu-fixture-v1','conversations':[{'id':'cleanup-concurrent','mapping':{}}]}; source=tmp_path/'input.zip'
    with zipfile.ZipFile(source,'w') as archive: archive.writestr('fixture.json',json.dumps(payload))
    content=source.read_bytes(); digest=hashlib.sha256(content).hexdigest(); target=root/'archive'/'objects'/digest[:2]/digest; target.parent.mkdir(parents=True); target.write_bytes(content)
    with Session(engine) as db:
        _clear(db); account=SourceAccount(platform='cleanup-runtime',account_label=str(uuid.uuid4()),metadata_json={}); archive=ArchiveObject(sha256=digest,size_bytes=len(content),relative_path=target.relative_to(root).as_posix(),media_type='application/zip',integrity_status='verified',metadata_json={}); db.add_all([account,archive]); db.flush(); job=ImportJob(source_account_id=account.id,archive_object_id=archive.id,parser_name='fixture',parser_version='1',status='pending',report_json={}); db.add(job); db.commit(); job_id=job.id
    entered=threading.Event(); release=threading.Event(); original=processor_module.copy_and_verify_archive
    def paused_copy(*args):
        result=original(*args); entered.set(); assert release.wait(2); return result
    monkeypatch.setattr(processor_module,'copy_and_verify_archive',paused_copy)
    runtime=WorkerRuntime(root,poll_interval=.01,heartbeat_interval=.02,lease_duration=5); thread=threading.Thread(target=runtime.run_once); thread.start(); assert entered.wait(2)
    attempt=next((root/'staging'/str(job_id)).glob('*/*')).resolve(); old=time.time()-10*86400; os.utime(attempt,(old,old))
    with Session(engine) as cleanup_db:
        result=cleanup_failed_staging(root,cleanup_db,7); assert result.skipped_active==[attempt] and attempt.exists()
    release.set(); thread.join(timeout=3); assert not thread.is_alive()
    with Session(engine) as db: assert db.get(ImportJob,job_id).status=='completed'
