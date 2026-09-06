import time
import uuid

import pytest
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.db import engine
from app.importers.service import ImportService
from app.importers.worker import ImportWorker, LeaseLost, LeaseRequired
from app.models import ArchiveObject, Conversation, ImportJob, SourceAccount


def _job(db):
    account = SourceAccount(platform="aud04", account_label=str(uuid.uuid4()), metadata_json={})
    archive = ArchiveObject(sha256=uuid.uuid4().hex * 2, size_bytes=1, relative_path="unused", media_type="application/json", integrity_status="verified", metadata_json={})
    db.add_all([account, archive]); db.flush()
    job = ImportJob(source_account_id=account.id, archive_object_id=archive.id, parser_name="fixture", parser_version="0.1", status="pending", report_json={})
    db.add(job); db.commit()
    return job, archive


def _payload(conversation_id):
    return {"schema_marker": "qingyu-fixture-v1", "conversations": [{"id": conversation_id, "mapping": {}, "current_node": None}]}


def test_database_wall_clock_expires_inside_existing_transaction():
    with Session(engine) as db:
        job, _ = _job(db); worker = ImportWorker(db); job = worker.claim_next(1); token = job.lease_token
        worker.assert_ownership(job, token)
        time.sleep(1.2)
        with pytest.raises(LeaseLost): worker.assert_ownership(job, token)
        assert worker.heartbeat(job, token) is False


def test_missing_token_cannot_write_business_data():
    with Session(engine) as db:
        job, archive = _job(db); job = ImportWorker(db).claim_next(60)
        identity = f"blocked-{uuid.uuid4()}"
        with pytest.raises(LeaseRequired):
            ImportService(db).import_fixture(_payload(identity), archive.id, job=job, lease_token=None)
        assert db.query(Conversation).filter_by(external_conversation_id=identity).count() == 0


def test_stale_worker_cannot_overwrite_new_worker_final_state():
    with Session(engine) as db:
        job, _ = _job(db); worker = ImportWorker(db); job = worker.claim_next(60); token_a = job.lease_token
        token_b = uuid.uuid4()
        db.execute(update(ImportJob).where(ImportJob.id == job.id).values(lease_token=token_b, report_json={"owner": "B"}, items_imported=9, result_code="B")); db.commit()
        assert worker.mark_completed(job, token_a, {"owner": "A"}, "A", {"items_imported": 1}) is False
        assert worker.mark_failed(job, token_a, "A-error", {"owner": "A"}, "A") is False
        db.expire_all(); current = db.get(ImportJob, job.id)
        assert current.report_json == {"owner": "B"}
        assert current.items_imported == 9 and current.result_code == "B" and current.lease_token == token_b
