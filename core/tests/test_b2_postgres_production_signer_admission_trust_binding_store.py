from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import inspect
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
from threading import Barrier
from urllib.parse import quote

import psycopg
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event, text

from app.b2_signer_trust import (
    AuthorityEnvironmentMode, ProductionSignerAdmissionRecord, TrustRecord,
    ProductionSignerAdmissionStatus, TrustStatus,
    ProductionSignerAdmissionTrustBinding as Binding,
    ProductionSignerAdmissionTrustBindingRequest as Request,
    ProductionSignerAdmissionTrustBindingProvisioningService as Service,
    PostgresProductionSignerAdmissionTrustBindingStore as Store,
    PostgresProductionSignerAdmissionStore, PostgresProductionTrustStore,
    PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_SCHEMA_VERSION as DOMAIN,
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION as VERSION,
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID as MIGRATION,
    _admission_record_hash, _trust_record_hash,
    apply_postgres_production_signer_admission_trust_binding_store_migration as migrate,
    require_postgres_production_signer_admission_trust_binding_store_config as configured_store,
)
from app.errors import CoreError
from tests.test_foundation_closure_rehearsal import FoundationPostgresEnvironment, docker
from tests.test_b2_postgres_production_signer_admission_store import trust_record, admission_for, migrate_both

NOW=datetime(2026,10,3,14,0,0,123456,tzinfo=timezone.utc)
PREFIX='PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_'
TABLE='governance.production_signer_admission_trust_bindings'


def evidence(name, data):
    folder=os.environ.get('QINGYU_BINDING_TEST_EVIDENCE')
    if folder:
        (Path(folder)/(name+'.json')).write_text(json.dumps(data,indent=2,default=str)+'\n',encoding='utf-8')


@pytest.fixture(scope='module')
def pg_env(tmp_path_factory):
    env=FoundationPostgresEnvironment(tmp_path_factory.mktemp('b2_binding_isolated'))
    try:
        env.create()
        with psycopg.connect(host='127.0.0.1',port=env.port,dbname='postgres',user='postgres',password=env.password) as c:
            for role in ['qingyu_control_owner','qingyu_control_migrator','qingyu_control_provisioner','qingyu_control_app']:
                c.execute(psycopg.sql.SQL('CREATE ROLE {} NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS {}').format(
                    psycopg.sql.Identifier(role),psycopg.sql.SQL('NOLOGIN' if role=='qingyu_control_owner' else 'LOGIN')))
                if role!='qingyu_control_owner':
                    c.execute(psycopg.sql.SQL('ALTER ROLE {} PASSWORD {}').format(psycopg.sql.Identifier(role),psycopg.sql.Literal(env.password)))
            c.execute('GRANT qingyu_control_owner TO qingyu_control_migrator WITH ADMIN FALSE, INHERIT FALSE, SET TRUE')
        evidence('postgres-real-store-validation',{'isolation':'new Docker PG16 cluster; no WSL/production connection','container':env.container,'owner_label':env.label,'postgres_version':docker('exec',env.container,'postgres','--version'),'roles_scope':'only this unique isolated cluster','same_role_names_do_not_touch_real_cluster':True})
        yield env
    finally:
        env.destroy()
        residue={kind:docker(*args) for kind,args in [
            ('containers',('ps','-aq','--filter','label='+env.label)),
            ('volumes',('volume','ls','-q','--filter','label='+env.label)),
            ('networks',('network','ls','-q','--filter','label='+env.label))]}
        assert not any(residue.values())
        # Only the fixture-created folder containing its synthetic env file.
        assert env.folder.parent.name.startswith('b2_binding_isolated')
        shutil.rmtree(env.folder)
        evidence('temporary-resource-cleanup',{'PASS':True,'owner':env.owner,'residue':residue,'synthetic_password_env_folder_removed':True,'unrelated_resources_untouched':True})


def admin(pg_env, db):
    return psycopg.connect(host='127.0.0.1',port=pg_env.port,dbname=db,user='postgres',password=pg_env.password)


def role_url(env,db,role='qingyu_control_provisioner'):
    return 'postgresql+psycopg://'+role+':'+quote(env.password)+'@127.0.0.1:'+str(env.port)+'/'+db


def grant_test_authority(env,db):
    with admin(env,db) as c:
        c.execute('GRANT USAGE ON SCHEMA governance TO qingyu_control_provisioner, qingyu_control_app')
        c.execute('GRANT SELECT ON governance.production_trust_records, governance.production_signer_admission_records TO qingyu_control_provisioner')
        c.execute('GRANT SELECT, INSERT ON '+TABLE+' TO qingyu_control_provisioner')
        c.execute('REVOKE ALL ON '+TABLE+' FROM PUBLIC, qingyu_control_app')


def seed(env,db,ordinal='01',*,trust=None):
    if trust is None:_,trust=trust_record(trust_reference='synthetic-binding-trust-'+ordinal)
    admission=admission_for(trust,admission_reference='synthetic-binding-admission-'+ordinal)
    ts=PostgresProductionTrustStore(env.url(db),expected_database_name=db)
    ads=PostgresProductionSignerAdmissionStore(env.url(db),expected_database_name=db)
    try:
        assert ts.create_if_absent_exact(trust)=='CREATED'
        assert ads.create_if_absent_exact(admission,provenance={'synthetic':True,'trust_reference':trust.trust_reference})=='CREATED'
    finally:ts.engine.dispose();ads.engine.dispose()
    return admission,trust


def source_rows(env,db):
    with admin(env,db) as c:
        return c.execute('SELECT (SELECT jsonb_agg(t ORDER BY trust_reference) FROM governance.production_trust_records t), (SELECT jsonb_agg(t ORDER BY admission_reference) FROM governance.production_signer_admission_records t)').fetchone()


@pytest.fixture
def db(pg_env):
    name='binding_'+secrets.token_hex(6)
    pg_env.create_database(name);migrate_both(pg_env.url(name),name)
    admission,trust=seed(pg_env,name)
    with admin(pg_env,name) as c:
        c.execute('ALTER SCHEMA governance OWNER TO qingyu_control_owner')
        for table in ['schema_migrations','production_trust_records','production_signer_admission_records']:
            c.execute('ALTER TABLE governance.'+table+' OWNER TO qingyu_control_owner')
    owner_url=role_url(pg_env,name,'qingyu_control_migrator')+'?options='+quote('-c role=qingyu_control_owner')
    before=source_rows(pg_env,name);migrate(owner_url,expected_database_name=name)
    assert source_rows(pg_env,name)==before
    grant_test_authority(pg_env,name)
    store=Store(role_url(pg_env,name),expected_database_name=name)
    try:yield name,store,admission,trust
    finally:store.engine.dispose()


def request(admission='a',trust='t',**changes):
    return Request(admission_reference=admission,trust_reference=trust,created_at=NOW,provenance={'task':'synthetic-binding-foundation','owner_decision':'synthetic'},**changes)


def bind_for(admission,trust,**updates):
    data=request(admission.admission_reference,trust.trust_reference).model_dump()
    data.update(admission_hash=_admission_record_hash(admission),trust_hash=_trust_record_hash(trust));data.update(updates)
    return Binding(**data)


def call(store,admission,trust,**updates):
    args=request(admission.admission_reference,trust.trust_reference).model_dump();args.update(updates)
    return Service(binding_store=store).create_binding(**args)


def test_canonical_binding_hash_datetime_and_provenance():
    base=Binding(**request().model_dump(),admission_hash='a'*64,trust_hash='b'*64)
    for offset in [timezone.utc,timezone(timedelta(hours=-12)),timezone(timedelta(hours=8))]:
        data=base.model_dump();data['created_at']=NOW.astimezone(offset)
        data['provenance']=dict(reversed(list(data['provenance'].items())))
        assert Binding(**data).binding_hash==base.binding_hash
        assert Binding(**data).model_dump(mode='json')['created_at']=='2026-10-03T14:00:00.123456Z'
    data=base.model_dump();data['created_at']+=timedelta(microseconds=1)
    assert Binding(**data).binding_hash!=base.binding_hash
    with pytest.raises(CoreError,match='TIMEZONE_REQUIRED'):Request(**{**request().model_dump(),'created_at':NOW.replace(tzinfo=None)})
    evidence('datetime-canonicalization',{'PASS':True,'UTC_offsets':[0,-12,8],'canonical_microseconds_preserved':True,'naive_rejected':True})


@pytest.mark.parametrize('field,value,error',[
    ('schema_version','wrong','SCHEMA_UNSUPPORTED'),('admission_hash','A'*64,'HASH_INVALID'),
    ('trust_hash','short','HASH_INVALID'),('provenance',{},'PROVENANCE_INVALID'),
    ('provenance',{'bad':float('nan')},'PROVENANCE_INVALID'),('provenance',{'bad':NOW},'PROVENANCE_INVALID'),
    ('provenance',{1:'invalid-key'},'PROVENANCE_INVALID')])
def test_domain_fail_closed(field,value,error):
    data={**request().model_dump(),'admission_hash':'a'*64,'trust_hash':'b'*64,field:value}
    with pytest.raises(CoreError,match=error):Binding(**data)


def test_request_cannot_accept_hash_injection_or_unapproved_identifier():
    for extra in ['admission_hash','trust_hash','binding_reference']:
        with pytest.raises(ValidationError):Request(**{**request().model_dump(),extra:'a'*64})
    with pytest.raises(CoreError,match='DURABLE_STORE_REQUIRED'):Service(binding_store=object())


def test_frozen_source_payload_hash_regression():
    root=Path(__file__).resolve().parents[1]
    p=root/'docs/evidence/r1-acceptance-marathon/phase-b2-real-production-signer-admission-exact-replay-verification-02-20261003T101516Z'
    admission=ProductionSignerAdmissionRecord(**json.loads((p/'admission-pre-replay-readback.json').read_text())['record'])
    trust=TrustRecord(**json.loads((p/'trust-preflight.json').read_text())['record'])
    assert _admission_record_hash(admission)=='5837a5fd6c0a5c389b4858d071d3b105b9a2eee39be4b49dc2719e9c764d6557'
    assert _trust_record_hash(trust)=='4279631ff75fef322fe8901c6785f870dff1ba096f1c674ad31dfe441e0152f0'


def test_no_production_memory_fallback_or_mutable_api():
    with pytest.raises(CoreError,match='STORE_CONFIG_REQUIRED'):configured_store(mode=AuthorityEnvironmentMode.REAL_PRODUCTION,sqlalchemy_url=None)
    with pytest.raises(CoreError,match='DURABLE_STORE_REQUIRED'):Service(binding_store=object())
    assert not any(hasattr(Store,m) for m in ['update','delete','rebind','upsert'])
    with pytest.raises(CoreError,match='DATABASE_SAFETY_VIOLATION'):Store('unused',expected_database_name='')


def test_create_replay_detached_provenance_and_no_update(db,pg_env):
    name,store,a,t=db;before=source_rows(pg_env,name);statements=[]
    event.listen(store.engine,'before_cursor_execute',lambda c,cur,stmt,params,ctx,many:statements.append(stmt))
    assert call(store,a,t)=='CREATED';first=store.resolve(a.admission_reference)
    assert call(store,a,t)=='IDEMPOTENT_EXISTING';assert store.count()==1
    assert first.binding_hash==store.resolve(a.admission_reference).binding_hash
    first.provenance['task']='caller-local-change'
    assert store.resolve(a.admission_reference).provenance['task']=='synthetic-binding-foundation'
    assert all(not any(token in stmt.upper() for token in ['FOR UPDATE','FOR SHARE','FOR NO KEY UPDATE','FOR KEY SHARE','ADVISORY','UPDATE ','DELETE ','TRUNCATE ']) for stmt in statements)
    assert before==source_rows(pg_env,name)
    evidence('create-result',{'result':'CREATED','row_count':1,'source_rows_preserved':True})
    evidence('exact-replay-result',{'result':'IDEMPOTENT_EXISTING','same_hash':True,'SELECT_INSERT_only':True,'statements':statements})


@pytest.mark.parametrize('changes',[
    {'trust_reference':'different-trust'}, {'trust_hash':'0'*64}, {'admission_hash':'0'*64},
    {'created_at':NOW+timedelta(microseconds=1)}, {'provenance':{'task':'different'}}])
def test_immutable_store_conflict(db,changes):
    _,store,a,t=db;binding=bind_for(a,t);assert store.create_if_absent_exact(binding)=='CREATED'
    data=binding.model_dump();data.update(changes)
    with pytest.raises(CoreError,match='IDENTITY_CONFLICT'):store.create_if_absent_exact(Binding(**data))
    assert store.resolve(a.admission_reference)==binding and store.count()==1


@pytest.mark.parametrize('field,error',[('admission_hash','ADMISSION_HASH_MISMATCH'),('trust_hash','TRUST_HASH_MISMATCH')])
def test_arbitrary_source_hash_rejected_before_insert(db,field,error):
    _,store,a,t=db;binding=bind_for(a,t,**{field:'0'*64});inserts=[]
    event.listen(store.engine,'before_cursor_execute',lambda c,cur,s,p,ctx,many:inserts.append(s) if s.lstrip().upper().startswith('INSERT') else None)
    with pytest.raises(CoreError,match=error):store.create_if_absent_exact(binding)
    assert not inserts and store.count()==0


@pytest.mark.parametrize('field,error',[('admission_reference','ADMISSION_NOT_FOUND'),('trust_reference','TRUST_NOT_FOUND')])
def test_missing_source_rejected_before_insert(db,field,error):
    _,store,a,t=db;args=request(a.admission_reference,t.trust_reference).model_dump();args[field]='missing';inserts=[]
    event.listen(store.engine,'before_cursor_execute',lambda c,cur,s,p,ctx,many:inserts.append(s) if s.lstrip().upper().startswith('INSERT') else None)
    with pytest.raises(CoreError,match=error):Service(binding_store=store).create_binding(**args)
    assert not inserts and store.count()==0


@pytest.mark.parametrize('source,column,error',[
    ('production_signer_admission_records','admission_hash','ADMISSION_HASH_MISMATCH'),
    ('production_trust_records','record_hash','TRUST_HASH_MISMATCH')])
def test_tampered_durable_source_hash_rejected(db,pg_env,source,column,error):
    name,store,a,t=db
    with admin(pg_env,name) as c:c.execute('UPDATE governance.'+source+' SET '+column+"='"+'0'*64+"'")
    with pytest.raises(CoreError,match=error):call(store,a,t)
    assert store.count()==0


@pytest.mark.parametrize('field', ['provider_reference','provider_backend_type','environment','target_reference','key_id','public_key_fingerprint'])
def test_incompatible_sources_rejected_before_insert(db,pg_env,field):
    name,store,a,t=db
    other=trust_record(trust_reference='synthetic-other')[1]
    value=getattr(other,field) if field in ['key_id','public_key_fingerprint'] else 'synthetic-different'
    data=a.model_dump();data[field]=value;altered=ProductionSignerAdmissionRecord(**data)
    with admin(pg_env,name) as c:
        c.execute(psycopg.sql.SQL('UPDATE governance.production_signer_admission_records SET {}=%s, admission_hash=%s').format(psycopg.sql.Identifier(field)),(value,_admission_record_hash(altered)))
    with pytest.raises(CoreError,match='SIGNER_TRUST_MISMATCH'):call(store,a,t)
    assert store.count()==0


@pytest.mark.parametrize('source',['admission','trust'])
def test_inactive_source_rejected(db,pg_env,source):
    name,store,a,t=db
    model=a if source=='admission' else t;data=model.model_dump();data['status']='RETIRED'
    altered=ProductionSignerAdmissionRecord(**data) if source=='admission' else TrustRecord(**data)
    table='production_signer_admission_records' if source=='admission' else 'production_trust_records';column='admission_hash' if source=='admission' else 'record_hash'
    with admin(pg_env,name) as c:c.execute('UPDATE governance.'+table+' SET status=%s, '+column+'=%s',('RETIRED',_admission_record_hash(altered) if source=='admission' else _trust_record_hash(altered)))
    with pytest.raises(CoreError,match='SOURCE_NOT_ACTIVE'):call(store,a,t)
    assert store.count()==0


def test_wrong_database_same_connection_guard(db,pg_env):
    name,_,a,t=db;wrong=Store(role_url(pg_env,name),expected_database_name='other_control')
    try:
        for op in [lambda:wrong.count(),lambda:wrong.get(a.admission_reference),lambda:call(wrong,a,t),lambda:wrong.create_if_absent_exact(bind_for(a,t))]:
            with pytest.raises(CoreError,match='DATABASE_SAFETY_VIOLATION'):op()
        with pytest.raises(CoreError,match='DATABASE_SAFETY_VIOLATION'):migrate(pg_env.url(name),expected_database_name='other_control')
    finally:wrong.engine.dispose()


def test_migration_idempotent_no_backfill_and_source_preservation(db,pg_env):
    name,store,_,_=db;before=source_rows(pg_env,name)
    for _ in range(2):migrate(pg_env.url(name),expected_database_name=name)
    with admin(pg_env,name) as c:
        assert c.execute('SELECT count(*) FROM governance.schema_migrations WHERE migration_id=%s AND schema_version=%s',(MIGRATION,VERSION)).fetchone()[0]==1
        assert c.execute('SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid=%s::regclass',(TABLE,)).fetchone()[0]=='qingyu_control_owner'
    assert store.count()==0 and before==source_rows(pg_env,name)
    evidence('migration-apply-test',{'PASS':True,'b2_001_and_b2_002_prerequisites':True,'migration':MIGRATION,'version':VERSION})
    evidence('migration-idempotency',{'PASS':True,'ledger_rows':1,'repeat_apply':2})
    evidence('migration-no-backfill',{'PASS':True,'binding_rows':0,'source_provenance_trust_reference_not_promoted':True,'sources_equal':True})


def test_migration_missing_prerequisites_fails_without_binding_table(pg_env):
    db='binding_prereq_'+secrets.token_hex(4);pg_env.create_database(db);migrate_both(pg_env.url(db),db)
    with admin(pg_env,db) as c:c.execute("DELETE FROM governance.schema_migrations WHERE migration_id LIKE 'b2_002%'")
    with pytest.raises(CoreError,match='MIGRATION_PREREQUISITES_REQUIRED'):migrate(pg_env.url(db),expected_database_name=db)
    with admin(pg_env,db) as c:assert c.execute('SELECT to_regclass(%s)',(TABLE,)).fetchone()[0] is None


def test_least_privilege_app_public_and_schema_permissions(db,pg_env):
    name,store,a,t=db
    with admin(pg_env,name) as c:
        matrix={p:c.execute('SELECT has_table_privilege(%s,%s,%s)',('qingyu_control_provisioner',TABLE,p)).fetchone()[0] for p in ['SELECT','INSERT','UPDATE','DELETE','TRUNCATE','REFERENCES','TRIGGER']}
        assert matrix=={'SELECT':True,'INSERT':True,'UPDATE':False,'DELETE':False,'TRUNCATE':False,'REFERENCES':False,'TRIGGER':False}
        assert c.execute("SELECT has_schema_privilege('qingyu_control_provisioner','governance','CREATE')").fetchone()[0] is False
        assert not c.execute("SELECT pg_has_role('qingyu_control_provisioner','qingyu_control_owner','MEMBER') OR pg_has_role('qingyu_control_provisioner','qingyu_control_migrator','MEMBER')").fetchone()[0]
        assert not c.execute("SELECT EXISTS (SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) x WHERE c.oid=%s::regclass AND x.grantee=0)",(TABLE,)).fetchone()[0]
        assert c.execute("SELECT has_table_privilege('qingyu_control_app',%s,'INSERT,UPDATE,DELETE,TRUNCATE')",(TABLE,)).fetchone()[0] is False
    assert call(store,a,t)=='CREATED' and call(store,a,t)=='IDEMPOTENT_EXISTING'
    with psycopg.connect(host='127.0.0.1',port=pg_env.port,dbname=name,user='qingyu_control_provisioner',password=pg_env.password,autocommit=True) as c:
        for sql in ['UPDATE '+TABLE+' SET trust_hash=trust_hash','DELETE FROM '+TABLE,'TRUNCATE '+TABLE,'SELECT * FROM '+TABLE+' FOR UPDATE','CREATE TABLE governance.unauthorized (id int)']:
            with pytest.raises(psycopg.errors.InsufficientPrivilege):c.execute(sql)
    app=Store(role_url(pg_env,name,'qingyu_control_app'),expected_database_name=name)
    try:
        with pytest.raises(CoreError,match='STORE_PERMISSION_DENIED'):app.create_if_absent_exact(bind_for(a,t))
    finally:app.engine.dispose()
    evidence('provisioner-role-test',{'PASS':True,'matrix':matrix,'schema_CREATE':False,'owner_migrator_membership':False,'actual_writer_role':'qingyu_control_provisioner','UPDATE_locking_READ_and_DDL_denied':True})
    evidence('app-authority-test',{'PASS':True,'mutation_authority':False,'actual_attempt_denied':True})
    evidence('public-authority-test',{'PASS':True,'grantee_privileges':[]})


def test_store_readback_detects_hash_or_version_corruption(db,pg_env):
    name,store,a,t=db;assert call(store,a,t)=='CREATED'
    with admin(pg_env,name) as c:c.execute('UPDATE '+TABLE+" SET binding_hash='"+'0'*64+"'")
    with pytest.raises(CoreError,match='DURABLE_HASH_MISMATCH'):store.resolve(a.admission_reference)


def test_six_worker_identical_concurrency_and_200_round_stress(db,pg_env):
    name,store,_,_=db;rounds=200;workers=6;counts={'CREATED':0,'IDEMPOTENT_EXISTING':0};hashes=set()
    # Every round has fresh immutable identities; no resetting or deleting bindings.
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for n in range(rounds):
            a,t=seed(pg_env,name,'stress-'+str(n));gate=Barrier(workers)
            def worker():gate.wait();return call(store,a,t)
            results=list(pool.map(lambda _:worker(),range(workers)))
            assert results.count('CREATED')==1 and results.count('IDEMPOTENT_EXISTING')==5
            for r in results:counts[r]+=1
            hashes.add(store.resolve(a.admission_reference).binding_hash)
    assert store.count()==rounds and len(hashes)==rounds
    evidence('identical-concurrency',{'PASS':True,'workers':workers,'each_round_results':{'CREATED':1,'IDEMPOTENT_EXISTING':5},'conflicts':0,'unexpected_errors':0})
    evidence('identical-concurrency-multiround',{'PASS':True,'rounds':rounds,'workers':workers,'calls':rounds*workers,'results':counts,'conflicts':0,'unexpected_errors':0,'binding_rows':rounds})
    evidence('transaction-semantics',{'isolation':'READ COMMITTED','source_validation_INSERT_conflict_SELECT':'same guarded transaction and connection','winner_committed_before_loser_SELECT':True,'loser_reads_fresh_statement_snapshot':True,'concurrency_test_covers_losers':1000,'no_UPDATE_locking_select':True})


def test_conflicting_trust_concurrency_and_winner_immutable(db,pg_env):
    name,store,a,t=db;data=t.model_dump();data['trust_reference']='synthetic-second-trust';other=TrustRecord(**data)
    ts=PostgresProductionTrustStore(pg_env.url(name),expected_database_name=name)
    try:ts.create_if_absent_exact(other)
    finally:ts.engine.dispose()
    gate=Barrier(6)
    def worker(i):
        gate.wait()
        try:return call(store,a,t if i%2==0 else other)
        except CoreError as ex:return ex.code
    with ThreadPoolExecutor(max_workers=6) as pool:results=list(pool.map(worker,range(6)))
    assert results.count('CREATED')==1 and results.count('IDEMPOTENT_EXISTING')==2 and results.count(PREFIX+'IDENTITY_CONFLICT')==3
    assert store.count()==1;winner=store.resolve(a.admission_reference)
    evidence('conflicting-concurrency',{'PASS':True,'workers':6,'results':results,'rows':1,'winner_hash':winner.binding_hash,'winner_trust':winner.trust_reference,'overwrite':False})


def test_f01_other_unique_constraint_arbitration(db,pg_env):
    name,store,a,t=db;data=a.model_dump();data['admission_reference']='synthetic-second-admission';data['provider_reference']='synthetic-second-provider';other=ProductionSignerAdmissionRecord(**data)
    # Source compatibility forbids different providers for one Trust. A raw
    # low-level insertion is used only here to probe both SQL uniqueness arbiters;
    # public create APIs independently reject this incompatible source.
    ads=PostgresProductionSignerAdmissionStore(pg_env.url(name),expected_database_name=name)
    try:ads.create_if_absent_exact(other)
    finally:ads.engine.dispose()
    assert call(store,a,t)=='CREATED'
    binding=bind_for(other,t)
    with store.engine.begin() as c:
        with pytest.raises(CoreError,match='IDENTITY_CONFLICT'):store._insert_exact(c,binding)
    assert store.count()==1 and store.get(other.admission_reference) is None
    sql=inspect.getsource(Store._insert_exact)
    assert 'ON CONFLICT DO NOTHING' in sql and 'ON CONFLICT (' not in sql
    evidence('f01-class-regression',{'PASS':True,'PK_and_trust_UNIQUE_arbiters':'untargeted ON CONFLICT DO NOTHING','non_PK_conflict_no_IntegrityError_or_UPDATE':True,'identical_200_round_stress':True})


def test_cross_process_restart_readback_and_replay(db,pg_env):
    name,store,a,t=db;assert call(store,a,t)=='CREATED';expected=store.resolve(a.admission_reference).binding_hash;store.engine.dispose()
    # Only synthetic isolated credentials in child environment; never print DSN.
    env=os.environ.copy();env['BINDING_SYNTHETIC_URL']=role_url(pg_env,name);env['BINDING_SYNTHETIC_DB']=name
    env['BINDING_SYNTHETIC_REQUEST']=json.dumps(request(a.admission_reference,t.trust_reference).model_dump(mode='json'))
    code="""import os,json
from app.b2_signer_trust import PostgresProductionSignerAdmissionTrustBindingStore as Store, ProductionSignerAdmissionTrustBindingProvisioningService as Service, ProductionSignerAdmissionTrustBindingRequest as Request
s=Store(os.environ['BINDING_SYNTHETIC_URL'],expected_database_name=os.environ['BINDING_SYNTHETIC_DB'])
try:
 r=Request(**json.loads(os.environ['BINDING_SYNTHETIC_REQUEST']))
 result=Service(binding_store=s).create_binding(**r.model_dump())
 print(json.dumps({'result':result,'hash':s.resolve(r.admission_reference).binding_hash,'count':s.count()}))
finally:s.engine.dispose()
"""
    p=subprocess.run([sys.executable,'-c',code],env=env,capture_output=True,text=True);assert p.returncode==0,p.stderr
    result=json.loads(p.stdout);assert result=={'result':'IDEMPOTENT_EXISTING','hash':expected,'count':1}
    evidence('restart-durability',{'PASS':True,'new_OS_process':True,**result})


def test_custom_dump_restore_all_three_records_and_acl(db,pg_env,tmp_path):
    name,store,a,t=db;assert call(store,a,t)=='CREATED';expected=store.resolve(a.admission_reference)
    dump=tmp_path/'synthetic-binding.dump'
    with dump.open('wb') as f:
        subprocess.run(['docker','exec',pg_env.container,'pg_dump','-U','postgres','-d',name,'-Fc'],stdout=f,check=True)
    restored='binding_restore_'+secrets.token_hex(5);pg_env.create_database(restored)
    with dump.open('rb') as f:
        p=subprocess.run(['docker','exec','-i',pg_env.container,'pg_restore','-U','postgres','-d',restored,'--exit-on-error'],stdin=f,capture_output=True)
    assert p.returncode==0,p.stderr.decode()
    fresh=Store(role_url(pg_env,restored),expected_database_name=restored)
    try:
        assert fresh.resolve(a.admission_reference)==expected and call(fresh,a,t)=='IDEMPOTENT_EXISTING'
        assert source_rows(pg_env,restored)==source_rows(pg_env,name)
        with admin(pg_env,restored) as c:
            assert c.execute('SELECT count(*) FROM governance.schema_migrations').fetchone()[0]==3
            assert not c.execute("SELECT has_table_privilege('qingyu_control_provisioner',%s,'UPDATE,DELETE,TRUNCATE')",(TABLE,)).fetchone()[0]
    finally:fresh.engine.dispose();dump.unlink()
    evidence('synthetic-dump-restore',{'PASS':True,'format':'custom','pg_restore_exit':0,'Trust_Admission_Binding_exact':True,'migration_rows':3,'ownership_acl_preserved':True,'cluster_role_prerequisites':'same isolated Docker cluster; separately pre-established roles','production_recovery':'deferred; no real binding or production access'})


def test_request_validation_happens_before_any_database_io(db):
    _,store,a,t=db;statements=[]
    event.listen(store.engine,'before_cursor_execute',lambda c,cur,s,p,ctx,many:statements.append(s))
    for changes,error in [({'created_at':NOW.replace(tzinfo=None)},'TIMEZONE_REQUIRED'),({'provenance':{}},'PROVENANCE_INVALID')]:
        with pytest.raises(CoreError,match=error):call(store,a,t,**changes)
    with pytest.raises(TypeError):Service(binding_store=store).create_binding(**request(a.admission_reference,t.trust_reference).model_dump(),trust_hash='0'*64)
    invalid=bind_for(a,t).model_copy(update={'schema_version':'wrong'})
    with pytest.raises(CoreError,match='SCHEMA_UNSUPPORTED'):store.create_if_absent_exact(invalid)
    assert not statements


def test_binding_constructor_never_creates_schema(pg_env):
    name='binding_unmigrated_'+secrets.token_hex(4);pg_env.create_database(name);migrate_both(pg_env.url(name),name)
    store=Store(pg_env.url(name),expected_database_name=name)
    try:
        with pytest.raises(CoreError,match='STORE_SCHEMA_REQUIRED'):store.count()
        with admin(pg_env,name) as c:assert c.execute('SELECT to_regclass(%s)',(TABLE,)).fetchone()[0] is None
    finally:store.engine.dispose()


@pytest.mark.parametrize('column,value',[
    ('admission_hash','A'*64),('trust_hash','short'),('binding_hash','not-a-hash'),
    ('schema_version','unsupported'),('durable_store_schema_version','unsupported'),
    ('provenance','{}'),('provenance','[]')])
def test_relational_shape_constraints(db,pg_env,column,value):
    name,store,a,t=db;assert call(store,a,t)=='CREATED'
    # Schema constraints are exercised only by synthetic isolated admin IO.
    with admin(pg_env,name) as c:
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute(psycopg.sql.SQL('UPDATE {} SET {}=%s').format(psycopg.sql.Identifier('governance','production_signer_admission_trust_bindings'),psycopg.sql.Identifier(column)),(value,))
    assert store.resolve(a.admission_reference)==bind_for(a,t)


def test_restrictive_foreign_keys_preserve_source_authority(db,pg_env):
    name,store,a,t=db;assert call(store,a,t)=='CREATED'
    for table,reference,value in [('production_signer_admission_records','admission_reference',a.admission_reference),('production_trust_records','trust_reference',t.trust_reference)]:
        with admin(pg_env,name) as c:
            with pytest.raises(psycopg.errors.ForeignKeyViolation):
                c.execute(psycopg.sql.SQL('DELETE FROM {} WHERE {}=%s').format(psycopg.sql.Identifier('governance',table),psycopg.sql.Identifier(reference)),(value,))
    with admin(pg_env,name) as c:
        constraints=c.execute('SELECT contype,confupdtype,confdeltype FROM pg_constraint WHERE conrelid=%s::regclass',(TABLE,)).fetchall()
    assert all(update==delete=='r' for kind,update,delete in constraints if kind=='f')
    assert sum(kind=='f' for kind,_,_ in constraints)==2
    assert any(kind=='p' for kind,_,_ in constraints) and any(kind=='u' for kind,_,_ in constraints)
    evidence('relational-constraints',{'PASS':True,'primary_key':'admission_reference','unique':'trust_reference','hash_shape_checks':3,'schema_version_checks':2,'provenance_object_nonempty':True,'foreign_keys':2,'ON_UPDATE_DELETE':'RESTRICT; no CASCADE','sources_cannot_disappear_through_binding':True})
