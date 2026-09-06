import io, json, zipfile
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.config import get_settings
from app.db import engine
from app.importers.query import ImportedTreeQuery
from app.importers.worker_runtime import WorkerRuntime
from app.main import app
from app.models import ArchiveObject, ArchiveObservation, Attachment, Conversation, ImportJob, Message, MessageObservation, MessageRevision, SourceAccount


def _clear(db):
    for model in (Attachment,MessageObservation,MessageRevision,Message,Conversation,ArchiveObservation,ImportJob,SourceAccount,ArchiveObject): db.execute(delete(model))
    db.commit()


def test_post_to_worker_to_snapshot_and_report(tmp_path: Path):
    root=tmp_path/'data'; get_settings().archive_root=str(root)
    payload={'schema_marker':'qingyu-fixture-v1','conversations':[{'id':'e2e','current_node':'child','mapping':{'root':{'parent':None,'message':{'author':{'role':'user'},'content':{'parts':['hi']}}},'child':{'parent':'root','message':{'author':{'role':'assistant'},'content':{'parts':['hello']}}}}}]}
    content=io.BytesIO()
    with zipfile.ZipFile(content,'w') as archive: archive.writestr('nested/fixture.json',json.dumps(payload))
    with Session(engine) as db: _clear(db)
    client=TestClient(app); headers={'Authorization':'Bearer qingyu-test-token-only'}
    response=client.post('/api/v1/import/chatgpt',headers=headers,files={'file':('export.zip',content.getvalue(),'application/octet-stream')})
    assert response.status_code==202; job_id=response.json()['import_job_id']
    with Session(engine) as db: assert db.get(ImportJob,job_id).status=='pending'
    assert WorkerRuntime(root,poll_interval=.01,heartbeat_interval=.05,lease_duration=5).run_once()
    result=client.get(f'/api/v1/import-jobs/{job_id}',headers=headers); body=result.json(); assert body['status']=='completed' and body['result_code']=='imported'; assert body['counts']['imported']==2
    with Session(engine) as db:
        job=db.get(ImportJob,job_id); conversation=db.query(Conversation).filter_by(external_conversation_id='e2e').one(); assert db.query(Message).count()==2 and db.query(MessageRevision).count()==2 and db.query(MessageObservation).count()==2
        current=ImportedTreeQuery(db).get_current_path(conversation.id,job.id); assert [row.external_node_id for row in current]==['root','child']; assert all(row.metadata_json['zip_member']=='nested/fixture.json' for row in current)
        archive=db.get(ArchiveObject,job.archive_object_id); assert (root/archive.relative_path).exists(); assert db.query(ArchiveObservation).filter_by(import_job_id=job.id).count()==1
    assert not list((root/'staging'/job_id).glob('*/*'))
