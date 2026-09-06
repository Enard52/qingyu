import json, zipfile
from pathlib import Path
from sqlalchemy.orm import Session
from app.db import engine
from app.models import ArchiveObject, SourceAccount, ImportJob
from app.importers.processor import ImportProcessor
from app.importers.worker import ImportWorker

def test_zip_processor_fixture(tmp_path: Path):
    root=tmp_path/'data'; (root/'archive/objects/aa').mkdir(parents=True)
    payload={"schema_marker":"qingyu-fixture-v1","conversations":[{"id":"pc1","title":"p","mapping":{"n1":{"parent":None,"message":{"author":{"role":"user"},"content":{"parts":["x"]}}}},"current_node":"n1"}]}
    z=tmp_path/'x.zip'
    with zipfile.ZipFile(z,'w') as f:f.writestr('fixture.json',json.dumps(payload))
    sha='a'*64; objpath=root/'archive/objects/aa'/sha; objpath.write_bytes(z.read_bytes())
    with Session(engine) as db:
        a=ArchiveObject(sha256=sha,size_bytes=z.stat().st_size,relative_path=f'archive/objects/aa/{sha}',media_type='application/zip',integrity_status='verified',metadata_json={}); s=SourceAccount(platform='proc',account_label='p',metadata_json={}); db.add_all([a,s]); db.flush(); j=ImportJob(source_account_id=s.id,archive_object_id=a.id,parser_name='generic-tree-fixture',parser_version='0.1',status='pending',report_json={}); db.add(j); db.commit(); job=ImportWorker(db).claim_next(); result=ImportProcessor(db,root).process(job,job.lease_token); assert result['imported_messages']==1
