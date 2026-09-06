import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.db import engine
from app.importers.generic import GenericTreeParser, ParserRegistry, ParserValidationError
from app.importers.service import ImportService
from app.models import ArchiveObject, Attachment, Conversation, ImportJob, Message, MessageObservation, MessageRevision, SourceAccount


def test_top_level_array_is_structured_unsupported():
    assert ParserRegistry().detect([]) == ('unsupported_structure', None)


def test_full_validation_reports_unknown_fields_and_bad_later_conversation():
    parser=GenericTreeParser(); payload={'schema_marker':'qingyu-fixture-v1','extra':1,'conversations':[{'id':'valid','mapping':{}},{'id':'bad','mapping':[]} ]}
    with pytest.raises(ParserValidationError) as caught: parser.validate(payload,'fixture.json')
    assert caught.value.errors[0]['raw_pointer']=='/conversations/1/mapping'
    unknown_payload={'schema_marker':'qingyu-fixture-v1','extra':1,'conversations':[]}
    assert parser.validate(unknown_payload,'fixture.json')[0] == {'type':'unknown_field','severity':'warning','file':'fixture.json','field':'extra','raw_pointer':'/extra'}


def test_invalid_later_conversation_persists_nothing():
    with Session(engine) as db:
        for model in (Attachment,MessageObservation,MessageRevision,Message,Conversation,ImportJob,SourceAccount,ArchiveObject): db.execute(delete(model))
        account=SourceAccount(platform='parser',account_label='stable',metadata_json={}); archive=ArchiveObject(sha256='5'*64,size_bytes=1,relative_path='x',media_type='x',integrity_status='verified',metadata_json={}); db.add_all([account,archive]); db.flush(); job=ImportJob(source_account_id=account.id,archive_object_id=archive.id,parser_name='fixture',parser_version='1',status='running',lease_token=uuid.uuid4(),lease_expires_at=datetime.now(timezone.utc)+timedelta(minutes=1),report_json={}); db.add(job); db.commit()
        payload={'schema_marker':'qingyu-fixture-v1','conversations':[{'id':'valid','mapping':{}},{'id':'bad','mapping':[]}]}
        with pytest.raises(ParserValidationError): ImportService(db).import_fixture(payload,archive.id,job=job,lease_token=job.lease_token,parser=GenericTreeParser())
        assert db.query(Conversation).count()==0
