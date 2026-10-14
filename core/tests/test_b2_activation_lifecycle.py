from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from urllib.parse import quote
import uuid
import json
import os

import pytest
from sqlalchemy import create_engine, event, text

from app.b2_activation_lifecycle import ActivationControlStore, ActivationSourceRegistry, activation_hash
from app.b2_activation_readiness import (ProductionTargetContract, SignedMigrationIntent, OwnerApproval,
    activation_candidate_hash, B1_FOUNDATION_CHECKPOINT_COMMIT, B1_FOUNDATION_CHECKPOINT_TAG)
from app.b2_signer_trust import (PostgresProductionTrustStore, PostgresProductionSignerAdmissionStore,
    PostgresProductionSignerAdmissionTrustBindingStore, ProductionSignerAdmissionTrustBindingRequest,
    apply_postgres_production_signer_admission_trust_binding_store_migration,
    AuthorityEnvironmentMode, sign_smi_payload)
from app.control_plane.b2_activation_schema import apply_activation_migration, CORE_REVISION, CONTROL_REVISION
from app.control_plane.r1_validation_codec import c2, decode, h2, ContractError
from app.r1_scoped_activation_core import (OpeningConfiguration, ScopedV2PostgresCore,
    produce_new_genesis_proof, verify_opening, SCOPED_V2_POSTGRES, LEGACY_V1_SQLITE)
from app.service_factory import build_activation_core_service
from app.errors import CoreError
from tests.test_foundation_closure_rehearsal import FoundationPostgresEnvironment
from tests.test_b2_postgres_production_signer_admission_store import trust_record, admission_for, migrate_both
from tests.r1_validation_fixtures import build_world
from tests.r1_validation_legacy_fixtures import make_origin
from tests.r1_validation_restore_fixtures import genesis

MODE = AuthorityEnvironmentMode.SYNTHETIC_PRODUCTION_TEST


def case_evidence(name, data):
    destination=os.environ.get("QINGYU_V2_SYNTHETIC_CASE_EVIDENCE")
    if destination:
        folder=Path(destination);folder.mkdir(exist_ok=True)
        (folder/(name+'.json')).write_text(json.dumps(data,indent=2,default=str)+'\n',encoding='utf-8')


@pytest.fixture(scope="module")
def pg(tmp_path_factory):
    folder = tmp_path_factory.mktemp("synthetic_v2_activation")
    env = FoundationPostgresEnvironment(folder)
    try:
        env.create()
        yield env
    finally:
        env.destroy()
        credential = env.folder / "postgres.env"
        if credential.is_file():
            assert credential.resolve().is_relative_to(folder.resolve())
            credential.unlink()
        if env.folder.is_dir(): env.folder.rmdir()


def new_database(pg, prefix):
    name = "synthetic_" + prefix + "_" + uuid.uuid4().hex[:10]
    pg.create_database(name)
    return name


@pytest.fixture
def scenario(pg):
    control_db, core_db = new_database(pg,"ctl"), new_database(pg,"core")
    admin_control, admin_core = create_engine(pg.url(control_db)), create_engine(pg.url(core_db))
    migrate_both(pg.url(control_db), control_db)
    apply_postgres_production_signer_admission_trust_binding_store_migration(pg.url(control_db), expected_database_name=control_db)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    target = ProductionTargetContract(target_reference="synthetic-v2-target",environment_identity="synthetic-v2-environment",
        environment_class="production",host_reference="synthetic-docker-loopback",database_reference="synthetic-core-db",
        postgres_version_major=16,schema_owner_reference="synthetic-migrator",expected_pre_activation_state="EMPTY_PRE_GENESIS",
        migration_version=CORE_REVISION,allowed_network_boundary="synthetic-loopback",backup_recovery_reference="synthetic-recovery",
        signer_trust_reference="synthetic-v2-trust",authority_reference="synthetic-v2-authority",audit_destination_reference="synthetic-v2-audit",
        activation_lock_reference="synthetic-v2-lock",expected_commit=B1_FOUNDATION_CHECKPOINT_COMMIT,expected_tag=B1_FOUNDATION_CHECKPOINT_TAG)
    signer, trust = trust_record(trust_reference=target.signer_trust_reference,environment=target.environment_identity,target_reference=target.target_reference)
    admission = admission_for(trust,admission_reference="synthetic-v2-admission")
    ts = PostgresProductionTrustStore(pg.url(control_db),expected_database_name=control_db)
    ads = PostgresProductionSignerAdmissionStore(pg.url(control_db),expected_database_name=control_db)
    bs = PostgresProductionSignerAdmissionTrustBindingStore(pg.url(control_db),expected_database_name=control_db)
    ts.create_if_absent_exact(trust); ads.create_if_absent_exact(admission,provenance={"synthetic":True})
    bs.create_from_sources(ProductionSignerAdmissionTrustBindingRequest(admission_reference=admission.admission_reference,
        trust_reference=trust.trust_reference,created_at=now,provenance={"synthetic":True}))
    apply_activation_migration(admin_control,database=control_db,kind="control")
    apply_activation_migration(admin_core,database=core_db,kind="core")
    role = "synthetic_v2_writer_" + uuid.uuid4().hex[:10]
    with admin_control.begin() as c:
        from psycopg import sql
        statement = sql.SQL('CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS').format(sql.Identifier(role),sql.Literal(pg.password))
        c.exec_driver_sql(statement.as_string(c.connection.driver_connection))
        c.execute(text('GRANT USAGE ON SCHEMA governance TO '+role))
        c.execute(text('GRANT SELECT ON ALL TABLES IN SCHEMA governance TO '+role))
        c.execute(text('GRANT INSERT ON governance.activation_authorities, governance.activation_smis TO '+role))
    with admin_core.begin() as c:
        c.execute(text('GRANT USAGE ON SCHEMA r1_core_v2 TO '+role))
        c.execute(text('GRANT SELECT ON ALL TABLES IN SCHEMA r1_core_v2 TO '+role))
        c.execute(text('GRANT INSERT ON r1_core_v2.identity, r1_core_v2.genesis, r1_core_v2.lifecycle TO '+role))
    def url(db): return 'postgresql+psycopg://'+role+':'+quote(pg.password)+'@127.0.0.1:'+str(pg.port)+'/'+db
    source_ts = PostgresProductionTrustStore(url(control_db),expected_database_name=control_db)
    source_ads = PostgresProductionSignerAdmissionStore(url(control_db),expected_database_name=control_db)
    source_bs = PostgresProductionSignerAdmissionTrustBindingStore(url(control_db),expected_database_name=control_db)
    registry = ActivationSourceRegistry(trust_store=source_ts,admission_store=source_ads,binding_store=source_bs,admission_reference=admission.admission_reference)
    world = build_world(); origin,_ = make_origin(world.root,world.trust)
    old,_ = genesis(world,origin)
    auth = decode(old.authorization_wire); binding = decode(old.initializer_binding_wire)
    shift = int(now.timestamp())-540
    auth.update(issued_at=500+shift, expires_at=100000+shift)
    binding.update(admitted_at=500+shift,expires_at=100000+shift)
    world.sign(auth)
    configuration = OpeningConfiguration(world.trust,world.deployment,c2(binding),old.initializer_component_bytes,auth["signed_origin_digest"])
    control = ActivationControlStore(url(control_db),database=control_db,target=target,sources=registry,configuration=configuration)
    proof = produce_new_genesis_proof(authorization_wire=c2(auth),configuration=configuration,receipt_signer=world.receipt_key,
        attempt_id=str(uuid.uuid4()),prepared_event_id=str(uuid.uuid4()),succeeded_event_id=str(uuid.uuid4()),
        prepared_at=540+shift,decided_at=540+shift)
    intent_data = dict(intent_id="synthetic-v2-intent",target_environment=target.environment_identity,target_reference=target.target_reference,
        source_checkpoint=B1_FOUNDATION_CHECKPOINT_COMMIT,source_tag=B1_FOUNDATION_CHECKPOINT_TAG,target_schema_migration_version=CORE_REVISION,
        authority_trust_reference=trust.trust_reference,signer_key_id=trust.key_id,requested_operation="PRODUCTION_GENESIS",
        expected_preconditions=["EMPTY_PRE_GENESIS","SCOPED_V2_POSTGRES"],expected_genesis_behavior="DURABLE_ONCE_THEN_CONTINUATION_ONLY",
        valid_from=now-timedelta(seconds=60),expires_at=now+timedelta(hours=1),owner_approval_reference="synthetic-owner-approval",
        signature_metadata={"signature_ref":"synthetic-signature","signature":"0"*128})
    intent = SignedMigrationIntent(**intent_data)
    intent_data["signature_metadata"]["signature"] = sign_smi_payload(signer,intent.canonical_payload())
    intent = SignedMigrationIntent(**intent_data)
    approval = OwnerApproval(approval_id="synthetic-owner-approval",approval_state="OWNER_APPROVED",
        activation_candidate_hash=activation_candidate_hash(target=target,intent=intent),target_reference=target.target_reference,
        migration_intent_hash=intent.canonical_payload_hash,authority_trust_reference=trust.trust_reference,
        source_checkpoint=B1_FOUNDATION_CHECKPOINT_COMMIT,source_tag=B1_FOUNDATION_CHECKPOINT_TAG,approved_at=now,
        approval_reference=intent.owner_approval_reference)
    core = ScopedV2PostgresCore(url(core_db),database=core_db,control=control,configuration=configuration,mode=MODE)
    statements = []
    for engine in (control.engine,core.engine,source_ts.engine,source_ads.engine,source_bs.engine):
        event.listen(engine,"before_cursor_execute",lambda conn,cursor,statement,parameters,context,many:statements.append(statement))
    s = SimpleNamespace(pg=pg,control_db=control_db,core_db=core_db,admin_control=admin_control,admin_core=admin_core,
        target=target,control=control,core=core,configuration=configuration,proof=proof,intent=intent,approval=approval,
        now=now,signer=signer,world=world,role=role,url=url,statements=statements,registry=registry)
    try: yield s
    finally:
        assert not any(any(x in sql.upper() for x in ("FOR UPDATE","FOR SHARE","FOR NO KEY UPDATE","FOR KEY SHARE","ADVISORY")) for sql in statements)
        for store in (ts,ads,bs,source_ts,source_ads,source_bs,control,core): store.engine.dispose()
        admin_control.dispose(); admin_core.dispose()


def authority(s, **kw):
    return s.control.create_authority(authority_reference=s.target.authority_reference,created_at=s.now,provenance_record={"synthetic":True},**kw)


def dependencies(s):
    a = authority(s)
    smi = s.control.persist_smi(s.intent,authority_reference=s.target.authority_reference,now=s.now)
    return a,smi


def call(s, **changes):
    data = dict(authority_reference=s.target.authority_reference,intent_id=s.intent.intent_id,opening=s.proof,owner_approval=s.approval,now=s.now)
    data.update(changes)
    return s.core.execute_new_genesis(**data)


def resigned_proof(s, **changes):
    auth=decode(s.proof.authorization_wire);auth.update(changes);s.world.sign(auth)
    return produce_new_genesis_proof(authorization_wire=c2(auth),configuration=s.configuration,receipt_signer=s.world.receipt_key,
        attempt_id=str(uuid.uuid4()),prepared_event_id=str(uuid.uuid4()),succeeded_event_id=str(uuid.uuid4()),
        prepared_at=decode(s.proof.prepare_wire)["prepared_at"],decided_at=decode(s.proof.receipt_wire)["decided_at"])


def table_bytes(s):
    with s.admin_core.begin() as c:
        return c.execute(text("SELECT (SELECT jsonb_agg(t) FROM r1_core_v2.identity t), (SELECT jsonb_agg(t) FROM r1_core_v2.genesis t), (SELECT jsonb_agg(t) FROM r1_core_v2.lifecycle t)")).one()


def test_full_synthetic_v2_activation_restart_replay_recovery(scenario,tmp_path):
    s = scenario
    assert s.core.read_pre_genesis_state() == {"status":"PRE_GENESIS"}
    a = authority(s)
    assert s.control.partial_state(authority_reference=s.target.authority_reference,intent_id=s.intent.intent_id)=="AUTHORITY_DURABLE_SMI_ABSENT"
    smi = s.control.persist_smi(s.intent,authority_reference=s.target.authority_reference,now=s.now)
    assert s.control.partial_state(authority_reference=s.target.authority_reference,intent_id=s.intent.intent_id)=="AUTHORITY_AND_SMI_DURABLE_GENESIS_ABSENT"
    service = build_activation_core_service(route=SCOPED_V2_POSTGRES,adapter=s.core,environment_mode=MODE)
    result = service.bootstrap_genesis(authority_reference=s.target.authority_reference,intent_id=s.intent.intent_id,opening=s.proof,owner_approval=s.approval,now=s.now)
    assert result["outcome"]=="GENESIS_DURABLE" and result["identity"]["identity"]==decode(s.proof.authorization_wire)["identity"]
    before = table_bytes(s)
    case_evidence("full-synthetic-activation",{"PASS":True,"environment":s.target.environment_identity,
        "authority_reference":s.target.authority_reference,"authority_hash":a.record_hash,
        "intent_id":s.intent.intent_id,"smi_record_hash":smi.record_hash,"payload_hash":smi.payload["payload_hash"],
        "signed_bytes_hash":smi.payload["signed_bytes_hash"],"core_identity":result["identity"],
        "core_identity_hash":result["identity_hash"],"genesis_hash":result["genesis_hash"],"checkpoint":result["checkpoint"],
        "database_role":s.role,"role_is_superuser":False,"route":SCOPED_V2_POSTGRES})
    s.control.engine.dispose(); s.core.engine.dispose()
    control = ActivationControlStore(s.url(s.control_db),database=s.control_db,target=s.target,sources=s.registry,configuration=s.configuration)
    restarted = ScopedV2PostgresCore(s.url(s.core_db),database=s.core_db,control=control,configuration=s.configuration,mode=MODE)
    try:
        assert control.read_authority(s.target.authority_reference).record_hash==a.record_hash
        assert control.read_smi(s.intent.intent_id).record_hash==smi.record_hash
        assert restarted.verify_core_identity()["identity_hash"]==result["identity_hash"]
        assert call(s,now=s.now+timedelta(days=10))["outcome"]=="GENESIS_ALREADY_DURABLE"
        assert authority(s).outcome=="EXACT_REPLAY"
        assert s.control.persist_smi(s.intent,authority_reference=s.target.authority_reference,now=s.now).outcome=="EXACT_REPLAY"
        assert before==table_bytes(s)
        case_evidence("restart-replay",{"PASS":True,"identity_hash":result["identity_hash"],"genesis_hash":result["genesis_hash"],
            "same_genesis":"GENESIS_ALREADY_DURABLE","authority":"EXACT_REPLAY","smi":"EXACT_REPLAY","entire_root_rows_unchanged":True})
        assert restarted.reconcile_new_genesis(result["genesis_hash"])=="EXACT"
        assert restarted.reconcile_new_genesis("0"*64)=="CONFLICT"
        dumps=[]
        for name in (s.control_db,s.core_db):
            destination=tmp_path/(name+'.sql'); s.pg.dump(name,destination); dumps.append(destination)
        restored_control_db=new_database(s.pg,"restore_ctl"); restored_core_db=new_database(s.pg,"restore_core")
        s.pg.restore(restored_control_db,dumps[0]); s.pg.restore(restored_core_db,dumps[1])
        for db,schema in [(restored_control_db,"governance"),(restored_core_db,"r1_core_v2")]:
            engine=create_engine(s.pg.url(db))
            try:
                with engine.begin() as c:
                    c.execute(text('GRANT USAGE ON SCHEMA '+schema+' TO '+s.role))
                    c.execute(text('GRANT SELECT ON ALL TABLES IN SCHEMA '+schema+' TO '+s.role))
            finally:engine.dispose()
        restored_stores=[PostgresProductionTrustStore(s.url(restored_control_db),expected_database_name=restored_control_db),
            PostgresProductionSignerAdmissionStore(s.url(restored_control_db),expected_database_name=restored_control_db),
            PostgresProductionSignerAdmissionTrustBindingStore(s.url(restored_control_db),expected_database_name=restored_control_db)]
        restored_registry=ActivationSourceRegistry(trust_store=restored_stores[0],admission_store=restored_stores[1],binding_store=restored_stores[2],admission_reference="synthetic-v2-admission")
        rc=ActivationControlStore(s.url(restored_control_db),database=restored_control_db,target=s.target,sources=restored_registry,configuration=s.configuration)
        rr=ScopedV2PostgresCore(s.url(restored_core_db),database=restored_core_db,control=rc,configuration=s.configuration,mode=MODE)
        try:
            assert rr.verify_core_identity()==restarted.verify_core_identity()
            assert rc.read_smi(s.intent.intent_id).wire==smi.wire
            assert rc.read_authority(s.target.authority_reference).wire==a.wire
            case_evidence("synthetic-recovery",{"PASS":True,"source_control_db":s.control_db,"source_core_db":s.core_db,
                "restored_control_db":restored_control_db,"restored_core_db":restored_core_db,
                "core_identity_hash":result["identity_hash"],"genesis_hash":result["genesis_hash"],
                "authority_hash":a.record_hash,"smi_hash":smi.record_hash,"public_signature_reverified":True,
                "verification_role":s.role,"restore_is_activation":False})
        finally:
            for obj in (*restored_stores,rc,rr):obj.engine.dispose()
            for dump in dumps:dump.unlink()
    finally:control.engine.dispose();restarted.engine.dispose()


@pytest.mark.parametrize("phase",["identity","genesis","lifecycle"])
def test_atomicity_rolls_back_all_root_statements(scenario,phase):
    s=scenario;dependencies(s)
    def fail(where):
        if where==phase:raise RuntimeError("injected synthetic failure")
    with pytest.raises(RuntimeError,match="injected"):call(s,failure_hook=fail)
    assert s.core.read_pre_genesis_state()=={"status":"PRE_GENESIS"}
    assert table_bytes(s)==(None,None,None)
    assert s.core.reconcile_new_genesis("0"*64)=="ABSENT"
    assert call(s)["outcome"]=="GENESIS_DURABLE"
    case_evidence("atomicity-"+phase,{"PASS":True,"injected_after":phase,"rollback":"PRE_GENESIS","all_root_rows_absent":True,"subsequent_valid_genesis":"GENESIS_DURABLE"})


@pytest.mark.parametrize("kind",["authority","smi","genesis"])
@pytest.mark.parametrize("conflict",[False,True])
def test_concurrent_exact_or_conflicting_requests(scenario,kind,conflict):
    s=scenario
    if kind!="authority":authority(s)
    if kind=="genesis":s.control.persist_smi(s.intent,authority_reference=s.target.authority_reference,now=s.now)
    barrier=Barrier(2)
    def worker(index):
        barrier.wait()
        try:
            if kind=="authority":
                result=s.control.create_authority(authority_reference=s.target.authority_reference,created_at=s.now,
                    provenance_record={"synthetic":True,"request":index if conflict else 0}).outcome
            elif kind=="smi":
                intent=s.intent.model_copy(deep=True)
                if conflict and index:
                    intent=intent.model_copy(update={"expected_preconditions":["different-synthetic-precondition"]})
                    metadata=intent.signature_metadata.model_copy(update={"signature":sign_smi_payload(s.signer,intent.canonical_payload())})
                    intent=intent.model_copy(update={"signature_metadata":metadata})
                result=s.control.persist_smi(intent,authority_reference=s.target.authority_reference,now=s.now).outcome
            else:
                proof=resigned_proof(s,reason="different synthetic authorization") if conflict and index else s.proof
                result=call(s,opening=proof)["outcome"]
            return result
        except (CoreError,ContractError) as exc:return str(exc)
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(worker,[0,1]))
    created="GENESIS_DURABLE" if kind=="genesis" else "CREATED"
    replay="GENESIS_ALREADY_DURABLE" if kind=="genesis" else "EXACT_REPLAY"
    assert results.count(created)==1,results
    assert (sum("CONFLICT" in x for x in results)==1) if conflict else results.count(replay)==1
    case_evidence("concurrency-"+kind+('-conflict' if conflict else '-exact'),{"PASS":True,"results":results,"isolation":"READ COMMITTED","row_lock_selects":False})


@pytest.mark.parametrize("bad",["missing_authority","missing_smi","signature","target","environment","key","owner","root_signature","receipt_signature","initializer","origin"])
def test_rejected_dependency_or_opening_has_zero_core_writes(scenario,bad):
    s=scenario
    if bad=="missing_authority":
        with pytest.raises((CoreError,ContractError)):call(s)
    else:
        authority(s)
        if bad in {"signature","target","environment","key"}:
            intent=s.intent.model_copy(deep=True)
            if bad=="signature":intent=intent.model_copy(update={"signature_metadata":intent.signature_metadata.model_copy(update={"signature":"0"*128})})
            else:intent=intent.model_copy(update={{"target":"target_reference","environment":"target_environment","key":"signer_key_id"}[bad]:"0"*64 if bad=="key" else "synthetic-wrong"})
            with pytest.raises((CoreError,ContractError)):s.control.persist_smi(intent,authority_reference=s.target.authority_reference,now=s.now)
            assert s.control.read_smi(s.intent.intent_id) is None
        elif bad=="missing_smi":
            with pytest.raises((CoreError,ContractError)):call(s)
        else:
            s.control.persist_smi(s.intent,authority_reference=s.target.authority_reference,now=s.now)
            proof=s.proof;approval=s.approval
            if bad=="owner":approval=approval.model_copy(update={"migration_intent_hash":"0"*64})
            elif bad in {"root_signature","receipt_signature"}:
                field="authorization_wire" if bad=="root_signature" else "receipt_wire"
                value=decode(getattr(proof,field));value[bad]="0"*128;proof=replace(proof,**{field:c2(value)})
            elif bad=="initializer":proof=replace(proof,initializer_component_bytes=b"synthetic-wrong")
            else:
                value=decode(proof.authorization_wire);value["signed_origin_digest"]="0"*64;s.world.sign(value);proof=replace(proof,authorization_wire=c2(value))
            with pytest.raises((CoreError,ContractError)):call(s,opening=proof,owner_approval=approval)
    assert table_bytes(s)==(None,None,None)
    case_evidence("negative-"+bad,{"PASS":True,"case":bad,"core_rows_after_rejection":0})


def test_migration_replay_constraints_and_writer_permissions(scenario):
    s=scenario
    for engine,db,kind in [(s.admin_control,s.control_db,"control"),(s.admin_core,s.core_db,"core")]:
        apply_activation_migration(engine,database=db,kind=kind)
    assert table_bytes(s)==(None,None,None)
    for engine,schema,tables in [(s.admin_control,"governance",["activation_authorities","activation_smis"]),(s.admin_core,"r1_core_v2",["identity","genesis","lifecycle"])]:
        with engine.begin() as c:
            for table in tables:
                perms=c.execute(text("SELECT has_table_privilege(:r,:t,'SELECT'),has_table_privilege(:r,:t,'INSERT'),has_table_privilege(:r,:t,'UPDATE'),has_table_privilege(:r,:t,'DELETE'),has_table_privilege(:r,:t,'TRUNCATE'),has_schema_privilege(:r,:s,'CREATE')"),{"r":s.role,"t":schema+'.'+table,"s":schema}).one()
                assert perms==(True,True,False,False,False,False)
                constraints=c.execute(text("SELECT contype FROM pg_constraint WHERE conrelid=CAST(:t AS regclass)"),{"t":schema+'.'+table}).scalars().all()
                assert 'p' in constraints and 'c' in constraints
    dependencies(s);call(s)
    with pytest.raises(Exception):
        with s.core.engine.begin() as c:c.execute(text("UPDATE r1_core_v2.identity SET record_hash=record_hash"))
    with pytest.raises(Exception):
        with s.admin_core.begin() as c:c.execute(text("DELETE FROM r1_core_v2.identity"))
    assert s.core.verify_core_identity()["status"]=="GENESIS_DURABLE_EXACT"


def test_routes_preserve_legacy_and_real_gate_never_writes(scenario):
    s=scenario
    from app.r1_service import R1CoreConsumer
    with pytest.raises(CoreError,match="R1_LIFECYCLE_NOT_IMPLEMENTED"):R1CoreConsumer._unsupported(None)
    with pytest.raises(CoreError,match="V2_ROUTE_REQUIRED"):build_activation_core_service(route=LEGACY_V1_SQLITE,adapter=s.core,environment_mode=AuthorityEnvironmentMode.REAL_PRODUCTION)
    with pytest.raises(CoreError,match="ENVIRONMENT_MISMATCH"):build_activation_core_service(route=SCOPED_V2_POSTGRES,adapter=s.core,environment_mode=AuthorityEnvironmentMode.REAL_PRODUCTION)
    # No live production store is constructed or connected: exercise the closed
    # gate on an already synthetic adapter before any dependency access.
    s.core.mode=AuthorityEnvironmentMode.REAL_PRODUCTION
    with pytest.raises(CoreError,match="GENESIS_FINAL_OWNER_CONFIRMATION_REQUIRED"):call(s)
    assert table_bytes(s)==(None,None,None)


def test_commit_response_loss_requires_read_only_exact_reconciliation(scenario,monkeypatch):
    import psycopg
    s=scenario;dependencies(s)
    original=s.core.engine.dialect.do_commit
    def lose_response(connection):
        original(connection)
        raise psycopg.OperationalError("synthetic commit response lost")
    with monkeypatch.context() as patch:
        patch.setattr(s.core.engine.dialect,"do_commit",lose_response)
        with pytest.raises(CoreError,match="OUTCOME_UNKNOWN_RECONCILIATION_REQUIRED"):call(s)
    state=s.core.verify_core_identity()
    before=table_bytes(s)
    assert s.core.reconcile_new_genesis(state["genesis_hash"])=="EXACT"
    assert s.core.reconcile_new_genesis("0"*64)=="CONFLICT"
    assert table_bytes(s)==before
    case_evidence("unknown-outcome",{"PASS":True,"error":"B2_GENESIS_OUTCOME_UNKNOWN_RECONCILIATION_REQUIRED",
        "reconciliation":"EXACT","genesis_hash":state["genesis_hash"],"automatic_retry":False,"readback_rewrites":0})
    assert call(s)["outcome"]=="GENESIS_ALREADY_DURABLE"
    assert table_bytes(s)==before


@pytest.mark.parametrize("column,table",[("record_wire","identity"),("proof_hash","genesis"),("checkpoint_hash","lifecycle")])
def test_admin_tampering_is_detected_by_durable_readback(scenario,column,table):
    s=scenario;dependencies(s);call(s)
    with s.admin_core.begin() as c:
        # Attack simulation only in the registered, isolated database. Product
        # APIs expose no reset/repair/delete operation and runtime lacks DDL.
        c.execute(text('ALTER TABLE r1_core_v2.'+table+' DISABLE TRIGGER activation_immutable'))
        if column=="record_wire":
            row=bytes(c.execute(text("SELECT record_wire FROM r1_core_v2.identity")).scalar_one())
            body=decode(row);body["provenance"]={"synthetic-tamper":True}
            c.execute(text("UPDATE r1_core_v2.identity SET record_wire=:wire"),{"wire":c2(body)})
        else:c.execute(text('UPDATE r1_core_v2.'+table+' SET '+column+"='"+'0'*64+"'"))
        c.execute(text('ALTER TABLE r1_core_v2.'+table+' ENABLE TRIGGER activation_immutable'))
    with pytest.raises(ContractError,match="CONFLICTING_STATE"):s.core.verify_core_identity()
    before=table_bytes(s)
    assert s.core.genesis_durable_predicate()=={"status":"GENESIS_DURABLE_CONFLICTING_STATE"}
    assert s.core.reconcile_new_genesis("0"*64)=="CONFLICT"
    assert table_bytes(s)==before


def test_source_binding_tamper_rejects_authority_before_insert(scenario):
    s=scenario
    with s.admin_control.begin() as c:
        c.execute(text("UPDATE governance.production_signer_admission_trust_bindings SET binding_hash=:h"),{"h":"0"*64})
    with pytest.raises(CoreError,match="HASH_MISMATCH"):authority(s)
    with s.admin_control.begin() as c:
        assert c.execute(text("SELECT count(*) FROM governance.activation_authorities")).scalar_one()==0
    assert table_bytes(s)==(None,None,None)


def test_partial_states_restart_and_orchestration(scenario):
    s=scenario
    consumer=build_activation_core_service(route=SCOPED_V2_POSTGRES,adapter=s.core,environment_mode=MODE)
    assert consumer.activation_state(authority_reference=s.target.authority_reference,intent_id=s.intent.intent_id)=="AUTHORITY_ABSENT"
    authority(s);s.control.engine.dispose();s.core.engine.dispose()
    assert consumer.activation_state(authority_reference=s.target.authority_reference,intent_id=s.intent.intent_id)=="AUTHORITY_DURABLE_SMI_ABSENT"
    prepared=consumer.prepare_activation(authority_request=dict(authority_reference=s.target.authority_reference,created_at=s.now,provenance_record={"synthetic":True}),intent=s.intent,now=s.now)
    assert prepared["authority"].outcome=="EXACT_REPLAY" and prepared["smi"].outcome=="CREATED"
    s.control.engine.dispose();s.core.engine.dispose()
    assert consumer.activation_state(authority_reference=s.target.authority_reference,intent_id=s.intent.intent_id)=="AUTHORITY_AND_SMI_DURABLE_GENESIS_ABSENT"
    call(s);s.core.engine.dispose()
    assert consumer.activation_state(authority_reference=s.target.authority_reference,intent_id=s.intent.intent_id)=="GENESIS_DURABLE"


def test_migration_error_rolls_back_tables_and_ledger(pg):
    db=new_database(pg,"migration_rollback");engine=create_engine(pg.url(db))
    def reject_lifecycle(conn,cursor,sql,parameters,context,many):
        if "CREATE TABLE r1_core_v2.lifecycle" in sql:raise RuntimeError("injected migration failure")
    event.listen(engine,"before_cursor_execute",reject_lifecycle)
    try:
        with pytest.raises(RuntimeError,match="injected migration failure"):apply_activation_migration(engine,database=db,kind="core")
        event.remove(engine,"before_cursor_execute",reject_lifecycle)
        with engine.begin() as c:assert c.execute(text("SELECT to_regclass('r1_core_v2.identity'),to_regclass('r1_core_v2.activation_migrations')")).one()==(None,None)
        apply_activation_migration(engine,database=db,kind="core")
        with engine.begin() as c:assert c.execute(text("SELECT count(*) FROM r1_core_v2.identity")).scalar_one()==0
    finally:engine.dispose()


def test_historical_exact_replay_is_distinct_from_current_eligibility(scenario):
    s=scenario;dependencies(s)
    before=table_bytes(s)
    assert authority(s).outcome=="EXACT_REPLAY"
    assert s.control.persist_smi(s.intent,authority_reference=s.target.authority_reference,now=s.now+timedelta(days=10)).outcome=="EXACT_REPLAY"
    with pytest.raises(ContractError,match="valid at execution time"):call(s,now=s.now+timedelta(days=10))
    assert table_bytes(s)==before==(None,None,None)
    call(s)
    before=table_bytes(s)
    assert call(s,now=s.now+timedelta(days=10))["outcome"]=="GENESIS_ALREADY_DURABLE"
    assert table_bytes(s)==before


def test_changed_authority_timestamp_and_provenance_are_conflicts(scenario):
    s=scenario;authority(s)
    for when,prov in [(s.now+timedelta(microseconds=1),{"synthetic":True}),(s.now,{"synthetic":True,"other":1})]:
        with pytest.raises(CoreError,match="IDENTITY_CONFLICT"):
            s.control.create_authority(authority_reference=s.target.authority_reference,created_at=when,provenance_record=prov)
    with s.admin_control.begin() as c:
        assert c.execute(text("SELECT count(*) FROM governance.activation_authorities")).scalar_one()==1


def test_fixed_v2_configuration_cannot_be_changed_after_authority(scenario):
    s=scenario;authority(s)
    bad=replace(s.configuration,signed_origin_digest="0"*64)
    changed=ActivationControlStore(s.url(s.control_db),database=s.control_db,target=s.target,sources=s.registry,configuration=bad)
    try:
        with pytest.raises(ContractError,match="fixed V2 configuration mismatch"):changed.read_authority(s.target.authority_reference)
        with pytest.raises(ContractError,match="configuration mismatch"):
            ScopedV2PostgresCore(s.url(s.core_db),database=s.core_db,control=s.control,configuration=bad,mode=MODE)
    finally:changed.engine.dispose()
    assert table_bytes(s)==(None,None,None)


def test_invalid_signature_racing_valid_smi_cannot_win(scenario):
    s=scenario;authority(s);barrier=Barrier(2)
    bad=s.intent.model_copy(update={"signature_metadata":s.intent.signature_metadata.model_copy(update={"signature":"0"*128})})
    def worker(intent):
        barrier.wait()
        try:return s.control.persist_smi(intent,authority_reference=s.target.authority_reference,now=s.now).outcome
        except CoreError as exc:return str(exc)
    with ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(worker,[bad,s.intent]))
    assert results.count("CREATED")==1 and sum("SIGNATURE" in result for result in results)==1
    assert s.control.read_smi(s.intent.intent_id).payload["intent"]==s.intent.model_dump(mode="json")
    case_evidence("invalid-smi-race",{"PASS":True,"results":results,"invalid_request_committed_rows":0,"valid_request_committed_rows":1})


def test_sqlite_cannot_be_selected_as_v2_adapter(scenario,tmp_path):
    s=scenario;url="sqlite:///"+str(tmp_path/"must-not-exist.db")
    with pytest.raises(ContractError,match="requires PostgreSQL"):
        ScopedV2PostgresCore(url,database=s.core_db,control=s.control,configuration=s.configuration,mode=MODE)
    assert not (tmp_path/"must-not-exist.db").exists()


def test_orchestration_invalid_signature_has_no_dependency_side_effect(scenario):
    s=scenario
    service=build_activation_core_service(route=SCOPED_V2_POSTGRES,adapter=s.core,environment_mode=MODE)
    intent=s.intent.model_copy(update={"signature_metadata":s.intent.signature_metadata.model_copy(update={"signature":"0"*128})})
    with pytest.raises(CoreError,match="SIGNATURE"):
        service.prepare_activation(authority_request=dict(authority_reference=s.target.authority_reference,created_at=s.now,provenance_record={"synthetic":True}),intent=intent,now=s.now)
    assert s.control.read_authority(s.target.authority_reference) is None
    assert s.control.read_smi(s.intent.intent_id) is None
    assert table_bytes(s)==(None,None,None)


def test_technical_failure_preserves_truthful_partial_stage(scenario,monkeypatch):
    s=scenario
    service=build_activation_core_service(route=SCOPED_V2_POSTGRES,adapter=s.core,environment_mode=MODE)
    def unavailable(*a,**kw):raise CoreError("synthetic technical store outage")
    with monkeypatch.context() as patch:
        patch.setattr(s.control,"persist_smi",unavailable)
        with pytest.raises(CoreError,match="technical store outage"):
            service.prepare_activation(authority_request=dict(authority_reference=s.target.authority_reference,created_at=s.now,provenance_record={"synthetic":True}),intent=s.intent,now=s.now)
    s.control.engine.dispose();s.core.engine.dispose()
    assert service.activation_state(authority_reference=s.target.authority_reference,intent_id=s.intent.intent_id)=="AUTHORITY_DURABLE_SMI_ABSENT"
    assert table_bytes(s)==(None,None,None)


@pytest.mark.parametrize("alias",["root_receipt","tls_receipt"])
def test_fixed_signer_roles_cannot_alias_keys(scenario,alias):
    from app.control_plane.r1_validation_crypto import FixedTrust
    from app.control_plane.r1_validation_codec import sha
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    s=scenario;pin=s.configuration.trust.pin;material=s.configuration.deployment
    if alias=="root_receipt":
        pin["operator_root_key_id"]=pin["receipt_key_id"]
        trust=FixedTrust(c2(pin),bytes.fromhex(pin["receipt_public_key"]))
    else:
        public=s.world.receipt_key.public_key().public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
        material=replace(material,tls_spki_der=public);pin["server_spki_sha256"]=sha(public)
        trust=FixedTrust(c2(pin),s.configuration.trust.root_public_key)
    config=replace(s.configuration,trust=trust,deployment=material)
    with pytest.raises(ContractError,match="distinct keys"):config.authority_binding()
    assert table_bytes(s)==(None,None,None)


def test_synthetic_source_cannot_be_promoted_to_production(scenario):
    s=scenario;a=authority(s)
    s.core.mode=AuthorityEnvironmentMode.REAL_PRODUCTION
    with pytest.raises(ContractError,match="synthetic signer source cannot enter production"):
        s.core._environment_source_guard(a)
    assert table_bytes(s)==(None,None,None)
