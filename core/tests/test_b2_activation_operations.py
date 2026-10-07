"""Task-owned PostgreSQL only. No production credentials/guest/provider fixture."""
from dataclasses import replace, FrozenInstanceError
from types import SimpleNamespace
from datetime import timedelta
from pathlib import Path
from urllib.parse import quote
import json
import os
import subprocess
import uuid
from copy import copy

import pytest
from sqlalchemy import create_engine, text, event
from sqlalchemy.exc import DBAPIError, OperationalError

from app.errors import CoreError
from app.b2_activation_lifecycle import ActivationControlStore, ActivationSourceRegistry
from app.b2_signer_trust import (PostgresProductionTrustStore,PostgresProductionSignerAdmissionStore,
    PostgresProductionSignerAdmissionTrustBindingStore,AuthorityEnvironmentMode,
    _trust_record_hash,_admission_record_hash,TrustRecord,ProductionSignerAdmissionRecord,ProductionSignerAdmissionTrustBinding,
    apply_postgres_production_signer_admission_trust_binding_store_migration)
from app.b2_migration_authorization import (ProtectedMigrationTarget,ProductionMigrationAuthorizationVerifier,
    ProductionMigrationAuthorizationEvidence,VerifiedProductionMigrationAuthorization,
    prepare_migration_plan,SYNTHETIC_TEST,POLICY_ID)
from app.b2_genesis_authorization import (VerifiedGenesisAuthorization,GenesisAuthorizationContext,
    GenesisAuthorizationEvidence)
from app.control_plane.b2_activation_schema import CONTROL_REVISION,CORE_REVISION
from app.control_plane.r1_validation_codec import c2,decode,sha
from app.r1_scoped_activation_core import ScopedV2PostgresCore
from ops.b2_activation_access import AccessPolicy,FixedAccess,ROLE_CONFIRMATION,TABLES,ROLES
from ops.b2_activation_operations import (ActivationOperations,OperationalPolicy,RecoveryBoundary,
    MigrationExecutor,PreparedAuthority,PreparedSMI,PreparedGenesis,CONFIRM,capture_then_parse,ExecutionJournal)
from tests.test_b2_activation_lifecycle import pg,scenario,table_bytes,resigned_proof
from tests.test_b2_postgres_production_signer_admission_store import migrate_both
from tests.test_b2_genesis_authorization import anchored


def record(name,data):
    folder=os.environ.get("QINGYU_OPERATIONAL_CASE_EVIDENCE")
    if folder:
        p=Path(folder);p.mkdir(exist_ok=True)
        (p/(name+".json")).write_text(json.dumps(data,indent=2,default=str)+"\n",encoding="utf-8")


def enroll_test_logins(s,access):
    # Credential enrollment is ONLY a synthetic fixture, outside ops requests.
    from psycopg import sql
    with s.admin_control.begin() as c:
        for actor in ROLES:
            role=access.policy.role(actor)
            stmt=sql.SQL("ALTER ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role),sql.Literal(s.pg.password))
            c.exec_driver_sql(stmt.as_string(c.connection.driver_connection))


def transfer_test_ownership(s,access):
    for engine,kind in ((s.admin_control,"control"),(s.admin_core,"core")):
        schema="governance" if kind=="control" else "r1_core_v2"
        owner=access.policy.owner(kind)
        with engine.begin() as c:
            c.exec_driver_sql('ALTER SCHEMA '+schema+' OWNER TO "'+owner+'"')
            for table in c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname=:s"),{"s":schema}).scalars():
                c.exec_driver_sql('ALTER TABLE '+schema+'."'+table+'" OWNER TO "'+owner+'"')
            c.exec_driver_sql('ALTER FUNCTION '+schema+'.activation_immutable() OWNER TO "'+owner+'"')


@pytest.fixture
def op(scenario,tmp_path):
    s=scenario; access=FixedAccess(AccessPolicy(SYNTHETIC_TEST,s.control_db,s.core_db,uuid.uuid4().hex[:10],s.pg.port))
    access.provision(s.admin_control,s.admin_core,confirmation=ROLE_CONFIRMATION)
    enroll_test_logins(s,access); transfer_test_ownership(s,access)
    access.provision_object_acls(s.admin_control,s.admin_core,confirmation=ROLE_CONFIRMATION)
    def url(actor,kind):
        return 'postgresql+psycopg://'+access.policy.role(actor)+':'+quote(s.pg.password)+'@127.0.0.1:'+str(s.pg.port)+'/'+access.policy.database(kind)
    stores=[]
    def control(actor):
        u=url(actor,"control")
        sources=[]
        for cls in (PostgresProductionTrustStore,PostgresProductionSignerAdmissionStore,PostgresProductionSignerAdmissionTrustBindingStore):
            sources.append(cls(u,expected_database_name=s.control_db))
        stores.extend(sources)
        registry=ActivationSourceRegistry(trust_store=sources[0],admission_store=sources[1],binding_store=sources[2],admission_reference=s.registry.admission_reference)
        result=ActivationControlStore(u,database=s.control_db,target=s.target,sources=registry,configuration=s.configuration)
        stores.append(result); return result
    authority=control("authority"); smi=control("smi"); reader=control("reader")
    source=authority.sources.load(s.target)
    policy=OperationalPolicy(access.policy,c2(s.target.model_dump(mode="json")),c2(s.approval.model_dump(mode="json")),
        s.intent.canonical_payload_hash,c2(s.intent.model_dump(mode="json")),
        _trust_record_hash(TrustRecord.model_validate(source["trust"])),
        _admission_record_hash(ProductionSignerAdmissionRecord.model_validate(source["admission"])),
        ProductionSignerAdmissionTrustBinding.model_validate(source["binding"]).binding_hash,s.signer.key_id,*["NON_PRODUCTION:"+x for x in ("foundation","genesis","migration","preapproval")])
    recovery=RecoveryBoundary(SYNTHETIC_TEST,policy.binding_hash,"NON_PRODUCTION:backup",())
    core=ScopedV2PostgresCore(url("genesis","core"),database=s.core_db,control=reader,configuration=s.configuration,mode=AuthorityEnvironmentMode.SYNTHETIC_PRODUCTION_TEST)
    stores.append(core)
    journal_dir=tmp_path/"NON_PRODUCTION";journal_dir.mkdir()
    ops=ActivationOperations(policy,authority_store=authority,smi_store=smi,core=core,signer=s.signer,recovery=recovery,journal=ExecutionJournal(SYNTHETIC_TEST,journal_dir/"operational-state.json"))
    a=ops.prepare_authority(created_at=s.now,provenance_record={"SYNTHETIC_TEST_ONLY":True},intent=s.intent)
    unsigned=s.intent.model_copy(deep=True); unsigned.signature_metadata.signature="0"*128
    sm=ops.prepare_smi(unsigned,a); signed=PreparedSMI(c2({**decode(sm.wire),"intent":s.intent.model_dump(mode="json")}))
    g=ops.prepare_genesis(intent_id=s.intent.intent_id,opening=s.proof)
    ops.recovery=replace(recovery,anchors=tuple((stage,sha(req.wire),"NON_PRODUCTION:verified-recovery-"+stage) for stage,req in (("authority",a),("pre_activation",a),("smi",signed),("genesis",g))))
    core.recovery_verifier=lambda:ops.recovery.verify("genesis",sha(g.wire))
    statements=[]
    for store in stores:
        event.listen(store.engine,"before_cursor_execute",lambda conn,cursor,statement,parameters,context,many:statements.append(statement))
    o=SimpleNamespace(s=s,ops=ops,access=access,a=a,sm=sm,signed=signed,g=g,core=core,url=url,stores=stores,statements=statements)
    try: yield o
    finally:
        for store in stores: store.engine.dispose()


def ready(o):
    a=o.ops.execute_authority(o.a,confirmation=CONFIRM["authority"])
    signed=o.ops.sign_smi(o.sm,confirmation=CONFIRM["smi"])
    assert signed.wire==o.signed.wire
    smi=o.ops.execute_smi(signed,now=o.s.now,confirmation=CONFIRM["smi"])
    assert a["durable_state"]=="AUTHORITY_DURABLE_EXACT" and smi["durable_state"]=="SMI_DURABLE_EXACT"


def owner(o,**changes):
    package=o.ops.owner_request_package(o.g)
    body={**decode(package.wire)["context"],"schema_version":"qingyu-genesis-owner-authorization-v1",
        "decision":"APPROVE_SYNTHETIC_V2_NEW_GENESIS",
        "provenance":{"version":"thread-owner-checkpoint-v1","authorization_reference":"SYNTHETIC_TEST_ONLY:Owner","authorization_sha256":"3"*64}}
    body.update(changes); evidence,verifier=anchored(body)
    o.core._genesis_authorization_verifier=verifier
    return evidence


def test_coordinator_stops_before_owner_and_restarts(op):
    o=op; start=len(o.statements)
    assert o.ops.partial_state(o.a,o.sm)=="OWNER_APPROVED_AUTHORITY_ABSENT"
    assert all(sql.lstrip().upper().startswith("SELECT") for sql in o.statements[start:])
    result=o.ops.pre_genesis_coordinator(o.a,o.sm,o.g,now=o.s.now,
        authority_confirmation=CONFIRM["authority"],smi_confirmation=CONFIRM["smi"])
    assert result["status"]=="GENESIS_FINAL_OWNER_CONFIRMATION_REQUIRED"
    assert o.core.genesis_authorization_verifier is None
    assert o.core.read_pre_genesis_state()["status"]=="PRE_GENESIS"
    assert result["owner_request_package"]["context"]["genesis_request_hash"]
    assert o.ops.partial_state(o.a,o.signed,o.g)=="AUTHORITY_AND_SMI_DURABLE_PRE_GENESIS"
    for store in o.stores: store.engine.dispose()
    assert o.ops.partial_state(o.a,o.signed,o.g)=="AUTHORITY_AND_SMI_DURABLE_PRE_GENESIS"
    record("preapproval-owner-stop",result)


@pytest.mark.parametrize("operation",["authority","smi","genesis","coordinator"])
def test_wrong_confirmations_have_zero_mutation(op,operation):
    o=op; before=len(o.statements)
    with pytest.raises(CoreError,match="CONFIRMATION"):
        if operation=="authority":o.ops.execute_authority(o.a,confirmation=CONFIRM["smi"])
        elif operation=="smi":o.ops.execute_smi(o.sm,now=o.s.now,confirmation=CONFIRM["authority"])
        elif operation=="genesis":o.ops.execute_genesis(o.g,None,now=o.s.now,confirmation=CONFIRM["authority"])
        else:o.ops.pre_genesis_coordinator(o.a,o.sm,o.g,now=o.s.now,authority_confirmation=CONFIRM["authority"],smi_confirmation="wrong")
    assert not any(sql.lstrip().upper().startswith("INSERT") for sql in o.statements[before:])
    assert o.core.read_pre_genesis_state()["status"]=="PRE_GENESIS"


def test_effective_acl_matrix_and_actual_denials(op):
    o=op; report={}
    for actor,kind in (("authority","control"),("smi","control"),("genesis","core"),("reader","control"),("reader","core")):
        engine=create_engine(o.url(actor,kind)); report[actor+":"+kind]=o.access.runtime_preflight(engine,actor,kind)
        denied=["CREATE TABLE public.denied(x int)","CREATE ROLE denied_escalation",
                "SET ROLE "+o.access.policy.owner(kind)]
        table="governance.activation_authorities" if kind=="control" else "r1_core_v2.identity"
        denied += ["UPDATE "+table+" SET record_hash=record_hash","DELETE FROM "+table,"TRUNCATE "+table]
        if actor=="smi":denied.append("INSERT INTO governance.activation_authorities DEFAULT VALUES")
        elif actor=="authority":denied.append("INSERT INTO governance.activation_smis DEFAULT VALUES")
        elif actor=="reader":denied.append("INSERT INTO "+table+" DEFAULT VALUES")
        for sql in denied:
            with pytest.raises(DBAPIError) as err:
                with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as c:c.exec_driver_sql(sql)
            assert err.value.orig.sqlstate=="42501"
        engine.dispose()
    record("effective-acl-and-denials",report)


@pytest.mark.parametrize("operation",["authority","smi","genesis"])
@pytest.mark.parametrize("violation",["wrong_actor","extra_update","extra_membership","temp"])
def test_actor_and_acl_fail_closed(op,operation,violation):
    o=op; ready(o) if operation!="authority" else None
    actor=operation; kind="core" if actor=="genesis" else "control"
    store=o.core if actor=="genesis" else o.ops.authority if actor=="authority" else o.ops.smi
    admin=o.s.admin_core if kind=="core" else o.s.admin_control
    role=o.access.policy.role(actor)
    if violation=="wrong_actor":
        old=store.engine; store.engine=create_engine(o.url("reader",kind))
    else:
        with admin.begin() as c:
            if violation=="extra_update":c.exec_driver_sql('GRANT UPDATE ON '+TABLES[kind][-1]+' TO "'+role+'"')
            elif violation=="temp":c.exec_driver_sql('GRANT TEMP ON DATABASE "'+o.access.policy.database(kind)+'" TO "'+role+'"')
            else:c.exec_driver_sql('GRANT "'+o.access.policy.owner(kind)+'" TO "'+role+'"')
    before=len(o.statements)
    try:
        with pytest.raises(CoreError):
            if actor=="authority":o.ops.execute_authority(o.a,confirmation=CONFIRM[actor])
            elif actor=="smi":o.ops.execute_smi(o.signed,now=o.s.now,confirmation=CONFIRM[actor])
            else:
                e=owner(o);cap=o.ops.verify_owner(o.g,e)
                o.ops.execute_genesis(o.g,cap,now=o.s.now,confirmation=CONFIRM[actor])
        assert not any(sql.lstrip().upper().startswith("INSERT") for sql in o.statements[before:])
    finally:
        if violation=="wrong_actor":store.engine.dispose();store.engine=old


def test_authority_replay_conflict_and_partial_state(op):
    o=op
    first=o.ops.execute_authority(o.a,confirmation=CONFIRM["authority"])
    assert first["transition"]=="OWNER_APPROVED_TO_ACTIVATION_EXECUTING_BEFORE_AUTHORITY_SEND"
    assert json.loads(o.ops.journal.path.read_text())["state"]=="ACTIVATION_EXECUTING"
    assert o.ops.partial_state(o.a,o.sm)=="AUTHORITY_DURABLE_SMI_ABSENT"
    replay=o.ops.execute_authority(o.a,confirmation=CONFIRM["authority"])
    assert replay["canonical_outcome"]=="EXACT_REPLAY"
    conflict=PreparedAuthority(c2({**decode(o.a.wire),"provenance":{"SYNTHETIC_TEST_ONLY":"different"}}))
    with pytest.raises(CoreError,match="CONFLICT"):o.ops.execute_authority(conflict,confirmation=CONFIRM["authority"])
    assert o.ops.reconcile_authority(conflict)=="AUTHORITY_DURABLE_CONFLICTING"
    record("authority-rehearsal",{"first":first,"replay":replay,"conflict":"REJECTED"})


def test_transition_is_persisted_before_first_authority_send(op,monkeypatch):
    o=op;original=o.ops.authority.create_authority;observed=[]
    def send(**request):
        data=json.loads(o.ops.journal.path.read_text(encoding="utf-8"))
        observed.append(data["state"])
        assert o.ops.authority.read_authority(o.s.target.authority_reference) is None
        return original(**request)
    monkeypatch.setattr(o.ops.authority,"create_authority",send)
    o.ops.execute_authority(o.a,confirmation=CONFIRM["authority"])
    assert observed==["ACTIVATION_EXECUTING"]


def test_corrupt_transition_journal_stops_before_activation(op):
    o=op;o.ops.journal.path.write_text("invalid",encoding="utf-8")
    with pytest.raises(CoreError,match="JOURNAL"):o.ops.execute_authority(o.a,confirmation=CONFIRM["authority"])
    assert o.ops.authority.read_authority(o.s.target.authority_reference) is None


@pytest.mark.parametrize("mutation",["wrong_key","signature","authority","payload"])
def test_smi_invalid_inputs_no_persist(op,mutation):
    o=op;o.ops.execute_authority(o.a,confirmation=CONFIRM["authority"])
    body=decode(o.signed.wire)
    if mutation=="signature":body["intent"]["signature_metadata"]["signature"]="0"*128
    elif mutation=="authority":body["authority_hash"]="f"*64
    elif mutation=="wrong_key":body["intent"]["signer_key_id"]="f"*64
    else:body["intent"]["expected_preconditions"]=["wrong"]
    bad=PreparedSMI(c2(body))
    with pytest.raises((CoreError,ValueError)):o.ops.execute_smi(bad,now=o.s.now,confirmation=CONFIRM["smi"])
    assert o.ops.smi.read_smi(o.s.intent.intent_id) is None


def test_smi_replay_reverify_conflict_restart(op):
    o=op;ready(o)
    replay=o.ops.execute_smi(o.signed,now=o.s.now,confirmation=CONFIRM["smi"])
    assert replay["canonical_outcome"]=="EXACT_REPLAY"
    altered=decode(o.signed.wire);altered["intent"]["signature_metadata"]["signature_ref"]="synthetic-other"
    assert o.ops.reconcile_smi(PreparedSMI(c2(altered)))=="SMI_DURABLE_CONFLICTING"
    for store in o.stores:store.engine.dispose()
    assert o.ops.reconcile_smi(o.signed)=="SMI_DURABLE_EXACT"
    record("smi-rehearsal",replay)


def test_future_owner_genesis_full_replay_and_restart(op):
    o=op;ready(o);evidence=owner(o);cap=o.ops.verify_owner(o.g,evidence)
    assert type(cap) is VerifiedGenesisAuthorization
    preflight=o.ops.genesis_preflight(o.g,cap,now=o.s.now)
    assert preflight["authority_reference"]==o.s.target.authority_reference
    result=o.ops.execute_genesis(o.g,cap,now=o.s.now,confirmation=CONFIRM["genesis"])
    assert result["durable_state"]=="GENESIS_DURABLE_EXACT" and result["next_gate"]=="ACCEPTANCE_VERIFYING"
    digest=o.core.read_genesis_state()["genesis_hash"]
    for store in o.stores:store.engine.dispose()
    assert o.core.verify_core_identity()["genesis_hash"]==digest
    assert o.ops.partial_state(o.a,o.signed,o.g)=="GENESIS_DURABLE_EXACT"
    replay=o.ops.execute_genesis(o.g,cap,now=o.s.now,confirmation=CONFIRM["genesis"])
    assert replay["canonical_outcome"]=="GENESIS_ALREADY_DURABLE"
    record("final-genesis-restart",{"first":result,"replay":replay,"genesis_hash":digest,"SYNTHETIC_TEST_ONLY":True})


@pytest.mark.parametrize("field",["decision","classification","foundation_checkpoint","activation_request_hash","authority_reference","authority_hash","intent_id","smi_hash","genesis_request_hash","target_database","environment","adapter"])
def test_owner_context_negative_matrix(op,field):
    o=op;ready(o)
    value="NON_PRODUCTION:wrong" if field!="decision" else "APPROVE_B2_ACTIVATION"
    evidence=owner(o,**{field:value})
    with pytest.raises(CoreError):o.ops.verify_owner(o.g,evidence)
    assert o.core.read_pre_genesis_state()["status"]=="PRE_GENESIS"


@pytest.mark.parametrize("invalid",[None,True,{},"YES","empty_capability","evidence"])
def test_no_genesis_without_verified_capability(op,invalid):
    o=op;ready(o);e=owner(o)
    if invalid=="empty_capability":invalid=object.__new__(VerifiedGenesisAuthorization)
    elif invalid=="evidence":invalid=e
    with pytest.raises((CoreError,AttributeError)):
        o.ops.execute_genesis(o.g,invalid,now=o.s.now,confirmation=CONFIRM["genesis"])
    assert o.core.read_pre_genesis_state()["status"]=="PRE_GENESIS"


def test_stale_request_recovery_and_wrong_checkpoint_rejected(op):
    o=op;ready(o);e=owner(o);cap=o.ops.verify_owner(o.g,e)
    changed=decode(o.g.wire);changed["opening_wire"]=__import__('app.r1_scoped_activation_core',fromlist=['encode_opening']).encode_opening(resigned_proof(o.s,expires_at=int(o.s.now.timestamp())+7200)).hex()
    with pytest.raises((CoreError,ValueError)):o.ops.execute_genesis(PreparedGenesis(c2(changed)),cap,now=o.s.now,confirmation=CONFIRM["genesis"])
    bad=replace(e,checkpoint_tag_wire=e.checkpoint_tag_wire+b"wrong")
    with pytest.raises(CoreError):o.ops.verify_owner(o.g,bad)
    o.ops.recovery=replace(o.ops.recovery,anchors=())
    with pytest.raises(CoreError,match="RECOVERY"):o.ops.execute_genesis(o.g,cap,now=o.s.now,confirmation=CONFIRM["genesis"])
    assert o.core.read_pre_genesis_state()["status"]=="PRE_GENESIS"


@pytest.mark.parametrize("operation",["authority","smi","genesis"])
def test_postcommit_loss_never_retries_and_reconciles(op,monkeypatch,operation):
    o=op
    if operation!="authority":o.ops.execute_authority(o.a,confirmation=CONFIRM["authority"])
    if operation=="genesis":o.ops.execute_smi(o.signed,now=o.s.now,confirmation=CONFIRM["smi"])
    store=o.ops.authority if operation=="authority" else o.ops.smi if operation=="smi" else o.core
    method={"authority":"create_authority","smi":"persist_smi","genesis":"execute_new_genesis"}[operation]
    original=getattr(store,method);calls=[]
    def lost(*a,**kw):
        calls.append(1);original(*a,**kw)
        raise OperationalError("result lost",None,RuntimeError("SYNTHETIC_TEST_ONLY post-commit loss"))
    monkeypatch.setattr(store,method,lost)
    if operation=="authority":result=o.ops.execute_authority(o.a,confirmation=CONFIRM[operation]);read=lambda:o.ops.reconcile_authority(o.a)
    elif operation=="smi":result=o.ops.execute_smi(o.signed,now=o.s.now,confirmation=CONFIRM[operation]);read=lambda:o.ops.reconcile_smi(o.signed)
    else:
        evidence=owner(o);cap=o.ops.verify_owner(o.g,evidence)
        result=o.ops.execute_genesis(o.g,cap,now=o.s.now,confirmation=CONFIRM[operation]);read=lambda:o.ops.reconcile_genesis(o.g)
    assert calls==[1] and result["reconciliation_required"] and result["next_gate"]=="READ_ONLY_RECONCILIATION"
    for st in o.stores:st.engine.dispose()
    assert read()==operation.upper()+"_DURABLE_EXACT"
    assert calls==[1]
    record("unknown-outcome-"+operation,{"result":result,"readback":read(),"send_count":len(calls)})


def test_read_failure_is_unknown_not_absence(op,monkeypatch):
    o=op
    def unavailable(*a,**kw):raise CoreError("B2_ACTIVATION_DATABASE_ERROR")
    monkeypatch.setattr(o.ops.authority,"read_authority",unavailable)
    assert o.ops.reconcile_authority(o.a)=="AUTHORITY_STATE_UNKNOWN"
    assert o.ops.partial_state(o.a,o.sm)=="UNKNOWN_STATE"
    monkeypatch.setattr(o.ops.smi,"read_smi",unavailable)
    assert o.ops.reconcile_smi(o.sm)=="SMI_STATE_UNKNOWN"
    monkeypatch.setattr(o.core.control,"read_smi",unavailable)
    assert o.ops.reconcile_genesis(o.g)=="GENESIS_STATE_UNKNOWN"


@pytest.mark.parametrize("field",["database","mode","route","target_environment"])
def test_changed_runtime_configuration_no_mutation(op,field):
    o=op
    if field=="database":o.core.database="qingyu_prod"
    elif field=="mode":o.core.mode=AuthorityEnvironmentMode.REAL_PRODUCTION
    elif field=="route":o.core.route="LEGACY_V1_SQLITE"
    else:o.ops.authority.target=o.ops.authority.target.model_copy(update={"environment_identity":"PRODUCTION"})
    with pytest.raises(CoreError,match="MISMATCH"):o.ops.execute_authority(o.a,confirmation=CONFIRM["authority"])
    assert o.ops.partial_state(o.a,o.sm,o.g)=="UNKNOWN_STATE"
    assert not any(sql.lstrip().upper().startswith("INSERT") for sql in o.statements)


def test_probe_and_preflight_never_sign_or_write(op,monkeypatch):
    o=op;ready(o);e=owner(o);cap=o.ops.verify_owner(o.g,e)
    before=len(o.statements)
    def forbidden(*a,**kw):raise AssertionError("probe reached signer private operation")
    monkeypatch.setattr(o.ops,"sign_smi",forbidden)
    assert o.ops.authority_preflight(o.a)=="AUTHORITY_DURABLE_EXACT"
    o.ops.smi_preflight(o.signed,now=o.s.now)
    o.ops.genesis_preflight(o.g,cap,now=o.s.now)
    o.ops.owner_request_package(o.g)
    assert o.ops.partial_state(o.a,o.signed,o.g)=="AUTHORITY_AND_SMI_DURABLE_PRE_GENESIS"
    assert all(sql.lstrip().upper().startswith("SELECT") for sql in o.statements[before:])
    role_probe=o.access.probe_roles(o.s.admin_control,o.s.admin_core)
    assert not role_probe["mutation_attempted"]


def test_genesis_conflict_and_missing_schema_never_execute(op):
    o=op;ready(o);e=owner(o);cap=o.ops.verify_owner(o.g,e)
    o.ops.execute_genesis(o.g,cap,now=o.s.now,confirmation=CONFIRM["genesis"])
    changed=decode(o.g.wire)
    from app.r1_scoped_activation_core import encode_opening
    changed["opening_wire"]=encode_opening(resigned_proof(o.s,expires_at=int(o.s.now.timestamp())+7200)).hex()
    other=PreparedGenesis(c2(changed))
    assert o.ops.reconcile_genesis(other)=="GENESIS_DURABLE_CONFLICTING_STATE"
    with pytest.raises(CoreError):o.ops.execute_genesis(other,cap,now=o.s.now,confirmation=CONFIRM["genesis"])
    with o.s.admin_core.begin() as c:c.exec_driver_sql("DROP TABLE r1_core_v2.activation_migrations")
    with pytest.raises(CoreError):o.ops.execute_genesis(o.g,cap,now=o.s.now,confirmation=CONFIRM["genesis"])


def test_wrong_signer_and_missing_recovery_precede_mutations(op):
    o=op
    o.ops.recovery=replace(o.ops.recovery,anchors=())
    with pytest.raises(CoreError,match="RECOVERY"):o.ops.execute_authority(o.a,confirmation=CONFIRM["authority"])
    assert o.ops.authority.read_authority(o.s.target.authority_reference) is None


@pytest.mark.parametrize("change",["key","classification"])
def test_signer_identity_gate_before_signing(op,change):
    o=op;o.ops.execute_authority(o.a,confirmation=CONFIRM["authority"])
    from app.b2_signer_trust import SignerProviderClassification
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    o.ops.signer=replace(o.ops.signer,**({"private_key":Ed25519PrivateKey.generate()} if change=="key" else {"classification":SignerProviderClassification.PRODUCTION_ELIGIBLE}))
    with pytest.raises(CoreError,match="SIGNER"):o.ops.sign_smi(o.sm,confirmation=CONFIRM["smi"])
    assert o.ops.smi.read_smi(o.s.intent.intent_id) is None


def test_production_role_bootstrap_has_recovery_gate_before_connection():
    access=FixedAccess(AccessPolicy("REAL_PRODUCTION","qingyu_control","qingyu_prod"))
    for method in (access.provision,access.provision_object_acls):
        with pytest.raises(CoreError,match="RECOVERY"):method(None,None,confirmation=ROLE_CONFIRMATION)
        with pytest.raises(CoreError,match="CONFIRMATION"):method(None,None,confirmation="wrong")


def test_fixed_admin_peer_endpoint_is_not_a_runtime_endpoint_without_connection():
    access=FixedAccess(AccessPolicy("REAL_PRODUCTION","qingyu_control","qingyu_prod"))
    from sqlalchemy.engine import URL
    engine=SimpleNamespace(url=URL.create("postgresql+psycopg",username="postgres",host="/var/run/postgresql",port=5433,database="qingyu_control"))
    access.admin_endpoint(engine,"control")
    with pytest.raises(CoreError):access.endpoint(engine,"control")
    for host in ("/tmp/untrusted","other-host"):
        with pytest.raises(CoreError):access.admin_endpoint(SimpleNamespace(url=engine.url.set(host=host)),"control")


@pytest.mark.parametrize("field,value",[("control_database","qingyu_control"),("core_database","qingyu_prod"),("classification","PRODUCTION"),("endpoint_port",0)])
def test_target_contract_override_rejected_without_connection(field,value):
    policy=AccessPolicy(SYNTHETIC_TEST,"synthetic_ctl_"+"1"*10,"synthetic_core_"+"2"*10,"3"*10,12345)
    with pytest.raises(CoreError):replace(policy,**{field:value})


def test_real_policy_metadata_binds_existing_first_owner_and_source_namespace_without_connection():
    # Historical public evidence only; no real approval/capability/adapter exists.
    from ops.b2_activation_operations import (FOUNDATION_CHECKPOINT,GENESIS_AUTHORIZATION_CHECKPOINT,
        MIGRATION_CHECKPOINT,PREAPPROVAL_CHECKPOINT,SIGNER_KEY_ID)
    root=Path(__file__).resolve().parents[1]
    wire=(root/'docs/evidence/r1-acceptance-marathon/phase-b2-owner-approval-for-activation-01-20261005T032659Z/owner-decision.json').read_bytes()
    identity=json.loads(wire)["canonical_identity"]
    target={"environment_identity":"qingyu-production-primary","host_reference":"qingyu-prod-local-01",
        "database_reference":"qingyu_prod","target_reference":"prod-target-ref-001","signer_trust_reference":"qingyu-prod-trust-01"}
    policy=OperationalPolicy(AccessPolicy("REAL_PRODUCTION","qingyu_control","qingyu_prod"),c2(target),
        b"NOT_INSTALLED", "0"*64,b"NOT_INSTALLED",identity["trust_hash"],identity["admission_hash"],identity["binding_hash"],
        SIGNER_KEY_ID,FOUNDATION_CHECKPOINT,GENESIS_AUTHORIZATION_CHECKPOINT,MIGRATION_CHECKPOINT,PREAPPROVAL_CHECKPOINT,wire)
    assert policy.access.classification=="REAL_PRODUCTION"
    assert decode(policy.target_wire)["environment_identity"]=="qingyu-production-primary"
    for field,value in [("first_owner_decision_wire",None),("binding_hash","0"*64),("preapproval_amendment","0"*40)]:
        with pytest.raises(CoreError):replace(policy,**{field:value})
    with pytest.raises(CoreError):replace(policy,target_wire=c2({**target,"environment_identity":"PRODUCTION"}))


@pytest.mark.parametrize("returncode,raw",[(0,b'{"state":"OK"}'),(0,b'invalid'),(3,b'{"state":"OK"}'),(0,b'[]')])
def test_raw_capture_precedes_parse_even_failure(returncode,raw):
    records=[];result=subprocess.CompletedProcess(["fixed-executor"],returncode,raw,b"synthetic-stderr")
    if returncode==0 and raw.startswith(b'{'):
        assert capture_then_parse(result,records.append)=={"state":"OK"}
    else:
        with pytest.raises(CoreError,match="RECONCILIATION"):capture_then_parse(result,records.append)
    assert records==[{"stdout_hex":raw.hex(),"stderr_hex":b"synthetic-stderr".hex(),"exit_code":returncode,"RAW_CAPTURE_BEFORE_PARSE":True}]


@pytest.mark.parametrize("kind",["control","core"])
def test_migration_positive_negative_unknown_and_nonactivation(pg,tmp_path,monkeypatch,kind):
    dbs=["synthetic_migration_"+uuid.uuid4().hex[:10] for _ in range(2)]
    for db in dbs:pg.create_database(db)
    ac,ak=[create_engine(pg.url(db)) for db in dbs]
    s=SimpleNamespace(admin_control=ac,admin_core=ak,pg=pg)
    migrate_both(pg.url(dbs[0]),dbs[0]);apply_postgres_production_signer_admission_trust_binding_store_migration(pg.url(dbs[0]),expected_database_name=dbs[0])
    access=FixedAccess(AccessPolicy(SYNTHETIC_TEST,*dbs,uuid.uuid4().hex[:10],pg.port));access.provision(ac,ak,confirmation=ROLE_CONFIRMATION);enroll_test_logins(s,access)
    with ac.begin() as c:
        c.exec_driver_sql('ALTER SCHEMA governance OWNER TO "'+access.policy.owner("control")+'"')
        for name in c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname='governance'")).scalars():c.exec_driver_sql('ALTER TABLE governance."'+name+'" OWNER TO "'+access.policy.owner("control")+'"')
    role=access.policy.role(kind+"_migrator");db=access.policy.database(kind)
    engine=create_engine('postgresql+psycopg://'+role+':'+quote(pg.password)+'@127.0.0.1:'+str(pg.port)+'/'+db)
    @event.listens_for(engine,"connect")
    def owner_context(connection,record):
        with connection.cursor() as c:c.execute('SET ROLE "'+access.policy.owner(kind)+'"')
        connection.commit()
    plan=prepare_migration_plan(database=db,kind=kind,classification=SYNTHETIC_TEST,environment="NON_PRODUCTION",base_checkpoint="NON_PRODUCTION:base",amendment_checkpoint="NON_PRODUCTION:migration")
    evidence=ProductionMigrationAuthorizationEvidence(c2({"policy_id":POLICY_ID,"classification":SYNTHETIC_TEST,"base_checkpoint":"NON_PRODUCTION:base","amendment_checkpoint":"NON_PRODUCTION:migration","plan_hash":plan.plan_hash}))
    verifier=ProductionMigrationAuthorizationVerifier(SYNTHETIC_TEST,"NON_PRODUCTION:base","NON_PRODUCTION:migration",plan.plan_hash,sha(evidence.wire))
    cap=verifier.verify(evidence,plan);target=ProtectedMigrationTarget(engine,db,kind,"NON_PRODUCTION",verifier)
    recovery=RecoveryBoundary(SYNTHETIC_TEST,"synthetic-binding","NON_PRODUCTION:backup",(("schema",plan.plan_hash,"NON_PRODUCTION:recovery"),))
    executor=MigrationExecutor(target,access,recovery)
    try:
        assert executor.reconcile()=="NOT_APPLIED"
        for bad in (None,True,{},object.__new__(VerifiedProductionMigrationAuthorization)):
            with pytest.raises((CoreError,AttributeError)):executor.execute(plan,bad,confirmation=CONFIRM[kind+"_migration"])
        with pytest.raises(CoreError):executor.execute(plan,cap,confirmation="wrong")
        for field,value in [("database","wrong"),("environment","PRODUCTION"),("ordered_migrations",["wrong"]),("base_checkpoint","NON_PRODUCTION:wrong")]:
            wrong=replace(plan,wire=c2({**decode(plan.wire),field:value}))
            with pytest.raises(CoreError):executor.execute(wrong,cap,confirmation=CONFIRM[kind+"_migration"])
        import ops.b2_activation_operations as module
        original=module.apply_activation_migration;calls=[]
        def lost(*args,**kwargs):
            calls.append(1);original(*args,**kwargs)
            raise OperationalError("lost result",None,RuntimeError("SYNTHETIC_TEST_ONLY"))
        monkeypatch.setattr(module,"apply_activation_migration",lost)
        result=executor.execute(plan,cap,confirmation=CONFIRM[kind+"_migration"])
        assert calls==[1] and result["reconciliation_required"]
        engine.dispose(); assert executor.reconcile()=="APPLIED_EXACT"
        replay=executor.execute(plan,cap,confirmation=CONFIRM[kind+"_migration"])
        assert calls==[1] and not replay["mutation_attempted"]
        with engine.connect() as c:
            tables=("governance.activation_authorities","governance.activation_smis") if kind=="control" else TABLES["core"][1:]
            assert all(c.execute(text("SELECT count(*) FROM "+t)).scalar_one()==0 for t in tables)
        for sql in ("CREATE ROLE denied_escalation","CREATE DATABASE denied_database"):
            with pytest.raises(DBAPIError) as err:
                with engine.connect().execution_options(isolation_level="AUTOCOMMIT") as c:c.exec_driver_sql(sql)
            assert err.value.orig.sqlstate=="42501"
        bad=copy(cap)
        object.__setattr__(bad,"evidence",ProductionMigrationAuthorizationEvidence(evidence.wire+b'wrong'))
        with pytest.raises(CoreError):executor.execute(plan,bad,confirmation=CONFIRM[kind+"_migration"])
        # Existing ledger alone must not hide schema corruption.
        admin=ac if kind=="control" else ak
        table="governance.activation_smis" if kind=="control" else "r1_core_v2.lifecycle"
        with admin.begin() as c:c.exec_driver_sql("ALTER TABLE "+table+" ADD COLUMN unexpected text")
        assert executor.reconcile()=="CONFLICTING"
        with pytest.raises(CoreError):executor.execute(plan,cap,confirmation=CONFIRM[kind+"_migration"])
        record("migration-"+kind,{"unknown":result,"replay":replay,"nonactivation":True,"send_count":len(calls)})
    finally:engine.dispose();ac.dispose();ak.dispose()
