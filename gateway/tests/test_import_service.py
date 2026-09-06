import uuid
from pathlib import Path
import pytest
from sqlalchemy import delete
from sqlalchemy.orm import Session
from app.db import engine
from app.models import ArchiveObject, SourceAccount, ImportJob, Conversation, Message, MessageRevision, MessageObservation
from app.importers.service import ImportService

@pytest.fixture()
def import_db():
    with Session(engine) as db:
        for model in (MessageObservation, MessageRevision, Message, Conversation, ImportJob, SourceAccount, ArchiveObject):
            db.execute(delete(model))
        archive = ArchiveObject(sha256=uuid.uuid4().hex * 2, size_bytes=1, relative_path="archive/objects/test", media_type="application/json", integrity_status="verified", metadata_json={})
        db.add(archive)
        db.flush()
        yield db, archive.id
        db.rollback()

def test_import_service_persists_tree(import_db):
    db, archive_id = import_db
    payload = {"conversations": [{"id": "c1", "title": "Fixture", "current_node": "n2", "mapping": {"n1": {"parent": None, "message": {"author": {"role": "user"}, "content": {"parts": ["hi"]}}}, "n2": {"parent": "n1", "message": {"author": {"role": "assistant"}, "content": {"parts": ["hello"]}}}}}]}
    job = ImportService(db).import_fixture(payload, archive_id)
    assert job.status == "completed"
    assert db.query(Conversation).count() == 1
    assert db.query(Message).count() == 2
    assert db.query(MessageRevision).count() == 2
    assert db.query(MessageObservation).count() == 2
