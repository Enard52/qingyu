"""Opt-in F3 SQL evidence on a NEW disposable cluster, never R1 acceptance.

R1_F3_TEST_ONLY=1 plus R1_F3_TEST_DATABASE_URL names the new harness database.
Each test creates its own labelled database on that same disposable cluster.
Synthetic fixture writes below are NOT supported production governance APIs.
The harness uses two newly labelled networks: an internal bridge and an isolated
host bridge publishing only loopback (Docker's internal bridge cannot publish it).
Local fixture SQL may use sslmode=disable; this is not production transport policy.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import os
import re
import threading
import socket
import tempfile
from pathlib import Path
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import psycopg
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict
from psycopg.types.json import Jsonb
import pytest

from app.control_plane.r1_candidate_schema import F3_SCHEMA_DIGEST, install_f3_test_schema
from app.control_plane.r1_commands import AbortAuthorization, AuthenticatedCaller, CommitAuthorization, MutationIntent
from app.control_plane.r1_postgres_store import R1PostgresStore, StoreError
from app.control_plane.r1_protocol import (
    AuthorityPin, ExpectedIntent, PREPARE_PREFIX, RECEIPT_PREFIX, canonical_bytes,
    decode_canonical_wire, genesis_head_seed, key_id, receipt_hash, request_envelope_hash,
    sha256_hex, sign_prepare_ack, sign_terminal_receipt, verify_prepare_ack,
    verify_terminal_receipt,
)
from app.control_plane.r1_schema_snapshot import schema_ddl_manifest
from r1_f3_helpers import authorization_value, mutation_envelope, uid
from r1_f3_target import verify_test_target


@pytest.fixture(scope="module")
def f3_cluster():
    value = os.environ.get("R1_F3_TEST_DATABASE_URL")
    if os.environ.get("R1_F3_TEST_ONLY") != "1" or not value:
        pytest.skip("requires explicit NEW R1_F3_TEST_ONLY disposable PostgreSQL cluster")
    params = conninfo_to_dict(value)
    base = params.get("dbname", "")
    if (params.get("host") not in {"127.0.0.1", "localhost", "::1"}
            or not re.fullmatch(r"r1_f3_test_[a-z0-9_]{8,42}", base)):
        pytest.fail("F3 test target must be an explicit loopback, uniquely named new database")
    password = uuid4().hex + uuid4().hex
    expected_system_id = verify_test_target(params)  # Read-only Docker inspection BEFORE DB mutation.
    with psycopg.connect(**params, autocommit=True) as admin:
        if admin.execute("SELECT current_database()").fetchone()[0] != base:
            pytest.fail("F3 target database mismatch")
        if str(admin.execute("SELECT system_identifier FROM pg_control_system()").fetchone()[0]) != expected_system_id:
            pytest.fail("F3 target cluster differs from independently observed harness identity")
        objects = admin.execute("""SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
          WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND c.relkind IN ('r','p','v','S')""").fetchone()[0]
        if objects:
            pytest.fail("F3 harness database must be empty; never adopt preexisting history")
        admin.execute(sql.SQL("COMMENT ON DATABASE {} IS {}").format(sql.Identifier(base),sql.Literal("R1_F3_TEST_ONLY:"+base)))
        for role in ("control_plane_owner", "control_plane_app", "control_plane_reader", "control_plane_migrator", "control_plane_operator"):
            old = admin.execute("SELECT rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=%s", (role,)).fetchone()
            if old is None:
                admin.execute(sql.SQL("CREATE ROLE {} NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS").format(sql.Identifier(role)))
            elif any(old[1:]) or (role == "control_plane_owner" and old[0]):
                pytest.fail("unexpected test role attributes; refusing privilege repair")
        admin.execute(sql.SQL("ALTER ROLE control_plane_app LOGIN PASSWORD {}").format(sql.Literal(password)))
    return params, password


def _insert(connection, table, values):
    """Explicit owner fixture setup only; table names are local test constants."""
    connection.execute(sql.SQL("INSERT INTO control_plane.{} ({}) VALUES ({})").format(
        sql.Identifier(table), sql.SQL(",").join(map(sql.Identifier, values)),
        sql.SQL(",").join(sql.Placeholder() for _ in values)), tuple(values.values()))


class F3Database:
    def __init__(self, params, password):
        self.params = params
        self.service_params = {**params, "user": "control_plane_app", "password": password}
        self.signer = Ed25519PrivateKey.generate()  # New synthetic test key only.
        self.pin = AuthorityPin(uid(1),uid(2),1,self.signer.public_key(),key_id(self.signer.public_key()),
                                1,"https://f3-test.invalid","1"*64,"2"*64)
        self.caller = AuthenticatedCaller(uid(1),uid(4),uid(5),uid(9),uid(6),"test-owner")
        from test_r1_tls_transport import _certificate_material
        from dataclasses import replace
        self._tls_temp = tempfile.TemporaryDirectory(prefix="r1-f3-synthetic-tls-")
        self.tls_material = _certificate_material(Path(self._tls_temp.name) / "certificate")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.pin = replace(self.pin, https_origin=f"https://127.0.0.1:{port}", server_spki_sha256=self.tls_material[3])

    def service(self):
        return psycopg.connect(**self.service_params)

    def store(self):
        return R1PostgresStore(self.service)

    def owner(self):
        return psycopg.connect(**self.params)

    def intent(self, **kwargs):
        from r1_runtime_helpers import initial_audit_record
        from app.canonical import sha256_hex as core_hash
        kwargs.setdefault("predecessor", core_hash(initial_audit_record()))
        return MutationIntent.from_envelope(mutation_envelope(**kwargs))

    def snapshot(self):
        with self.owner() as connection:
            state = connection.execute("SELECT state_version,core_audit_sequence,core_audit_head_hash FROM control_plane.cp_continuities").fetchone()
            head = connection.execute("SELECT authority_sequence,head_hash FROM control_plane.cp_generations").fetchone()
            ledger = connection.execute("SELECT operation_id,state,receipt_hash,prepare_wire,terminal_wire FROM control_plane.cp_operations ORDER BY operation_id").fetchall()
            return state, head, ledger

    def inject(self, statement, parameters=()):
        """Privileged synthetic failure setup, NOT a production transition API."""
        with self.owner() as connection:
            connection.execute(statement, parameters)

    def prepare(self, intent, *, store=None):
        with (store or self.store()).prepare(intent, self.caller) as tx:
            if tx.proposal.historical:
                result = tx.proposal.wire
            else:
                assert canonical_bytes(decode_canonical_wire(tx.proposal.wire)) == tx.proposal.wire
                signature = self.signer.sign(PREPARE_PREFIX + tx.proposal.wire)
                self.signer.public_key().verify(signature, PREPARE_PREFIX + tx.proposal.wire)
                result = tx.finalize(intent.operation_id, signature)
        value = decode_canonical_wire(result)
        if value.get("state") == "PREPARED":
            verify_prepare_ack(value, intent.envelope, self.pin, intent.expected_intent)
        return result

    def terminal(self, intent, decision="COMMIT", *, store=None):
        kind = CommitAuthorization if decision == "COMMIT" else AbortAuthorization
        authorization = kind.from_mapping(authorization_value(intent, decision))
        with (store or self.store()).terminal(intent, self.caller, authorization) as tx:
            if tx.proposal.historical:
                result = tx.proposal.wire
            else:
                signature = self.signer.sign(RECEIPT_PREFIX + tx.proposal.wire)
                self.signer.public_key().verify(signature, RECEIPT_PREFIX + tx.proposal.wire)
                result = tx.finalize(intent.operation_id, signature)
        return result


def _seed_synthetic_history(database):
    now = datetime.now(timezone.utc)
    from r1_runtime_helpers import setup_runtime_admission
    database.admission = setup_runtime_admission(database)
    pin = database.pin
    origin_hash = database.admission.public.origin.signed_provisioning_origin_digest
    seed = genesis_head_seed(authority_domain_id=uid(1),authority_instance_id=uid(2),
        provisioning_uuid=uid(12),signed_provisioning_origin_digest=origin_hash,
        receipt_key_id=pin.receipt_key_id,operator_root_key_id=pin.operator_root_key_id)
    envelope = {"schema_version":1,"authority_domain_id":uid(1),"authority_instance_id":uid(2),
        "authority_generation":1,"qingyu_identity_id":uid(3),"continuity_id":uid(4),
        "operation_id":uid(11),"operation_type":"AUTHORITY_GENESIS_ACTIVATION",
        "expected_continuity_epoch":0,"expected_state_version":0,"expected_owner_version":0,
        "actor_or_owner_identity":"test-owner","caller_runtime_id":uid(5),
        "storage_generation_id":uid(6),"payload":{"synthetic_test_genesis":True},"reason":"SYNTHETIC TEST ONLY"}
    request_hash = request_envelope_hash(envelope)
    stamp = now.isoformat().replace("+00:00","Z")
    from r1_runtime_helpers import initial_audit_record
    from app.canonical import sha256_hex as core_hash
    staged = core_hash(initial_audit_record())
    common = {name:envelope[name] for name in ("authority_domain_id","authority_instance_id","authority_generation",
        "qingyu_identity_id","continuity_id","operation_id","operation_type")}
    ack = sign_prepare_ack({"ack_version":1,**common,"request_envelope_hash":request_hash,
        "caller_runtime_id":uid(5),"storage_generation_id":uid(6),"expected_continuity_epoch":0,
        "expected_owner_version":0,"expected_state_version":0,"staged_result_hash":staged,
        "core_audit_predecessor_hash":"0"*64,"core_audit_candidate_hash":staged,"state":"PREPARED","prepared_at":stamp},database.signer)
    result_payload = {"synthetic_test_genesis":True}
    receipt = sign_terminal_receipt({"receipt_version":1,"schema_version":1,**common,
        "request_envelope_hash":request_hash,"result_state":"COMMITTED","result_code":"ACTIVATED",
        "actor_or_owner_identity":"test-owner","continuity_epoch":1,"storage_generation_id":uid(6),
        "control_plane_generation_id":uid(10),"owner_version":1,"lease_generation":None,
        "authority_sequence":1,"previous_receipt_hash":seed,"result_payload_hash":sha256_hex(canonical_bytes(result_payload)),
        "staged_result_hash":staged,"core_audit_predecessor_hash":"0"*64,"core_audit_candidate_hash":staged,
        "decided_at":stamp,"signed_provisioning_origin_digest":origin_hash,"previous_generation":None,
        "previous_generation_sequence":None,"previous_generation_head_hash":None,"signed_dr_artifact_digest":None},database.signer)
    with database.owner() as connection:
        system_id = str(connection.execute("SELECT system_identifier FROM pg_control_system()").fetchone()[0])
        _insert(connection,"cp_origin",dict(singleton_id=1,provisioning_uuid=UUID(uid(12)),authority_domain_id=UUID(uid(1)),
            authority_instance_id=UUID(uid(2)),initial_authority_generation=1,signed_provisioning_origin_digest=origin_hash,
            operator_root_key_id=pin.operator_root_key_id,cluster_system_identifier=system_id,
            cluster_binding_fingerprint=database.admission.public.origin.completion["cluster_binding_fingerprint"],
            database_name=database.params["dbname"],initial_revision="0001_control_plane_r1_initial",created_at=now))
        _insert(connection,"cp_receipt_keys",dict(authority_domain_id=UUID(uid(1)),receipt_key_id=pin.receipt_key_id,
            authority_instance_id=UUID(uid(2)),authority_generation=1,public_key=pin.receipt_public_key.public_bytes(
                serialization.Encoding.Raw,serialization.PublicFormat.Raw),signed_activation_digest="5"*64,activated_at=now))
        _insert(connection,"cp_generations",dict(authority_domain_id=UUID(uid(1)),authority_generation=1,
            authority_instance_id=UUID(uid(2)),receipt_key_id=pin.receipt_key_id,status="ACTIVE",authority_sequence=1,
            head_hash=receipt_hash(receipt),seed_hash=seed,signed_provisioning_origin_digest=origin_hash,opened_at=now))
        _insert(connection,"cp_operations",dict(authority_domain_id=UUID(uid(1)),operation_id=UUID(uid(11)),
            authority_generation=1,authority_instance_id=UUID(uid(2)),qingyu_identity_id=UUID(uid(3)),continuity_id=UUID(uid(4)),
            operation_type="AUTHORITY_GENESIS_ACTIVATION",request_envelope_hash=request_hash,request_envelope=Jsonb(envelope),
            caller_runtime_id=UUID(uid(5)),storage_generation_id=UUID(uid(6)),actor_or_owner_identity="test-owner",
            expected_continuity_epoch=0,expected_state_version=0,expected_owner_version=0,state="COMMITTED",prepared_at=now,
            prepare_ack=Jsonb(ack),staged_result_hash=staged,core_audit_predecessor_hash="0"*64,core_audit_candidate_hash=staged,
            result_code="ACTIVATED",result_payload_hash=receipt["result_payload_hash"],result_payload=Jsonb(result_payload),
            continuity_epoch=1,control_plane_generation_id=UUID(uid(10)),owner_version=1,receipt_key_id=pin.receipt_key_id,
            authority_sequence=1,previous_receipt_hash=seed,receipt_hash=receipt_hash(receipt),receipt_payload=Jsonb(receipt),
            receipt_signature=bytes.fromhex(receipt["receipt_signature"]),decided_at=now))
        _insert(connection,"cp_runtime_sessions",dict(authority_domain_id=UUID(uid(1)),caller_runtime_id=UUID(uid(5)),
            session_id=UUID(uid(9)),continuity_id=UUID(uid(4)),storage_generation_id=UUID(uid(6)),process_nonce_hash="6"*64,
            session_state="ACTIVE",claimed_at=now,last_heartbeat_at=now,expires_at=now+timedelta(hours=1)))
        _insert(connection,"cp_continuities",dict(authority_domain_id=UUID(uid(1)),continuity_id=UUID(uid(4)),qingyu_identity_id=UUID(uid(3)),
            continuity_epoch=1,state_version=1,active_storage_generation_id=UUID(uid(6)),control_plane_generation_id=UUID(uid(10)),
            owner_identity="test-owner",owner_key_id="7"*64,owner_record_hash="8"*64,owner_version=1,lease_generation=1,
            lease_runtime_id=UUID(uid(5)),lease_session_id=UUID(uid(9)),lease_storage_generation_id=UUID(uid(6)),lease_epoch=1,
            lease_acquired_at=now,lease_last_heartbeat_at=now,lease_expires_at=now+timedelta(hours=1),lease_status="ACTIVE",
            admission_state="OPEN",lease_id=UUID(uid(8)),recovery_state="ACTIVE",genesis_operation_id=UUID(uid(11)),
            core_audit_head_hash=staged,core_audit_sequence=1))


@pytest.fixture
def f3_db(f3_cluster):
    base, password = f3_cluster
    name = "r1_f3_test_" + uuid4().hex
    params = {**base,"dbname":name}
    with psycopg.connect(**base,autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {} OWNER control_plane_owner").format(sql.Identifier(name)))
        admin.execute(sql.SQL("COMMENT ON DATABASE {} IS {}").format(sql.Identifier(name),sql.Literal("R1_F3_TEST_ONLY:"+name)))
        admin.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(name)))
        admin.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO control_plane_app,control_plane_reader").format(sql.Identifier(name)))
    database = F3Database(params,password)
    try:
        with database.owner() as connection:
            connection.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
            manifest = schema_ddl_manifest()
            for statement in manifest["prefix_sql"] + manifest["table_sql"] + manifest["index_sql"]:
                connection.execute(statement)
            install_f3_test_schema(connection,test_database_name=name)
        _seed_synthetic_history(database)
        yield database
    finally:
        database._tls_temp.cleanup()
        # Exact generated database + persisted label are independently checked.
        with psycopg.connect(**base,autocommit=True) as admin:
            label = admin.execute("SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=%s",(name,)).fetchone()
            if label == ("R1_F3_TEST_ONLY:"+name,) and re.fullmatch(r"r1_f3_test_[0-9a-f]{32}",name):
                admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(name)))
            else:
                pytest.fail("test cleanup target/label mismatch; no database removed")


@pytest.mark.parametrize("value", [
    {"z":"测试😀","a":"quote\"\\\n\t\r\b\f","null_value":None,"integer":9007199254740991},
    {"a":"\u2028\u2029/","b":-9007199254740991,"c":0},
])
def test_actual_pg_flat_canonical_bytes_match_rfc8785(f3_db,value):
    with f3_db.owner() as connection:
        wire = connection.execute("SELECT control_plane.f3_flat_jcs(%s)",(Jsonb(value),)).fetchone()[0]
    assert bytes(wire) == canonical_bytes(value)


def test_service_uses_only_restricted_procedures_and_views(f3_db):
    assert f3_db.store().describe()["f3_contract_digest"] == F3_SCHEMA_DIGEST
    for statement in ("SELECT * FROM control_plane.cp_operations", "DELETE FROM control_plane.cp_operations",
                      "CREATE TABLE public.forbidden(id int)","CREATE TEMP TABLE forbidden(id int)",
                      "SET ROLE control_plane_owner", "SELECT control_plane.f3_flat_jcs('{}')"):
        with pytest.raises(psycopg.Error):
            with f3_db.service() as connection:
                connection.execute(statement)
    intent = f3_db.intent()
    f3_db.prepare(intent)  # Includes deferred guard running under service COMMIT.
    assert f3_db.store().lookup_intent(intent.operation_id,f3_db.caller).request_wire == intent.request_wire
    for statement in ("UPDATE control_plane.cp_operations SET operation_type='FORGED' WHERE state='PREPARED'",
                      "UPDATE control_plane.cp_operations SET continuity_id='00000000-0000-0000-0000-000000000099' WHERE state='PREPARED'"):
        with pytest.raises(psycopg.Error,match="IMMUTABLE_INTENT"):
            f3_db.inject(statement)


def test_prepare_signing_failure_and_unfinalized_commit_leave_no_row(f3_db):
    intent = f3_db.intent()
    before = f3_db.snapshot()
    with pytest.raises(RuntimeError,match="signer failed"):
        with f3_db.store().prepare(intent,f3_db.caller):
            raise RuntimeError("signer failed")
    assert f3_db.snapshot() == before
    with pytest.raises(psycopg.Error,match="UNFINALIZED_PROPOSAL"):
        with f3_db.service() as connection:
            connection.execute("SELECT * FROM control_plane.f3_propose_prepare(%s,%s,%s,%s)",
                (intent.request_wire,Jsonb(f3_db.caller.as_mapping()),canonical_bytes(intent.result_payload("COMMITTED")),
                 canonical_bytes(intent.result_payload("ABORTED")))).fetchone()
    assert f3_db.snapshot() == before


def test_atomic_terminal_receipt_and_immutable_historical_replay(f3_db):
    intent = f3_db.intent()
    before = f3_db.snapshot()
    ack = f3_db.prepare(intent)
    assert f3_db.snapshot()[1] == before[1]
    wire = f3_db.terminal(intent)
    receipt = decode_canonical_wire(wire)
    verify_terminal_receipt(receipt,intent.envelope,f3_db.pin,intent.expected_intent,
        expected_sequence=before[1][0]+1,expected_previous_hash=before[1][1],prepared_ack=decode_canonical_wire(ack))
    after = f3_db.snapshot()
    assert after[0] == (2,2,"b"*64)
    assert after[1] == (2,receipt_hash(receipt))
    for statement in ("UPDATE control_plane.cp_operations SET state='PREPARED' WHERE state='COMMITTED'",
                      "DELETE FROM control_plane.cp_operations WHERE state='COMMITTED'"):
        with pytest.raises(psycopg.Error,match="IMMUTABLE_HISTORY"):
            f3_db.inject(statement)
    f3_db.inject("UPDATE control_plane.cp_continuities SET recovery_state='QUARANTINED',lease_id=%s",(uuid4(),))
    frozen = f3_db.snapshot()
    assert f3_db.terminal(intent) == wire
    assert f3_db.store().query(intent.operation_id,f3_db.caller,intent.request_hash).wire == wire
    assert f3_db.prepare(intent) == wire
    assert f3_db.snapshot() == frozen


def test_sixteen_independent_prepares_have_one_barrier_winner(f3_db):
    barrier = threading.Barrier(16)
    intents = [f3_db.intent(mutation_id="concurrent-"+str(i)) for i in range(16)]
    def attempt(intent):
        barrier.wait(timeout=20)
        try:
            return intent,f3_db.prepare(intent,store=f3_db.store())
        except StoreError as error:
            return intent,error.code
    with ThreadPoolExecutor(max_workers=16) as workers:
        outcomes = list(workers.map(attempt,intents))
    winners = [(intent,result) for intent,result in outcomes if isinstance(result,bytes)]
    assert len(winners) == 1
    assert [result for _,result in outcomes if isinstance(result,str)] == ["PREPARED_CONFLICT"]*15
    f3_db.terminal(winners[0][0])
    assert f3_db.snapshot()[0] == (2,2,"b"*64)
    assert f3_db.snapshot()[1][0] == 2


def test_sixteen_independent_finalizers_return_one_identical_receipt(f3_db):
    intent = f3_db.intent()
    f3_db.prepare(intent)
    barrier = threading.Barrier(16)
    def attempt(_):
        barrier.wait(timeout=20)
        return f3_db.terminal(intent,store=f3_db.store())
    with ThreadPoolExecutor(max_workers=16) as workers:
        wires = list(workers.map(attempt,range(16)))
    assert len(set(wires)) == 1
    state,head,ledger = f3_db.snapshot()
    assert state == (2,2,"b"*64) and head[0] == 2
    assert sum(row[1] == "COMMITTED" for row in ledger) == 2  # Genesis + one mutation.


@pytest.mark.parametrize("drift,code", [
    ("UPDATE control_plane.cp_continuities SET lease_id='00000000-0000-0000-0000-000000000099'","LEASE_FENCED"),
    ("UPDATE control_plane.cp_continuities SET lease_generation=2","LEASE_FENCED"),
    ("UPDATE control_plane.cp_continuities SET continuity_epoch=2,lease_epoch=2","STATE_FENCED"),
    ("UPDATE control_plane.cp_continuities SET state_version=2","STATE_FENCED"),
    ("UPDATE control_plane.cp_continuities SET owner_version=2","STATE_FENCED"),
    ("UPDATE control_plane.cp_continuities SET control_plane_generation_id='00000000-0000-0000-0000-000000000099'","STATE_FENCED"),
    ("UPDATE control_plane.cp_continuities SET recovery_state='QUARANTINED'","ADMISSION_FENCED"),
    ("UPDATE control_plane.cp_continuities SET genesis_operation_id=NULL","GENESIS_FENCED"),
    ("UPDATE control_plane.cp_runtime_sessions SET session_state='REVOKED',revoked_at=clock_timestamp()","SESSION_FENCED"),
    ("UPDATE control_plane.cp_receipt_keys SET revoked_at=clock_timestamp(),revocation_reason='synthetic test'","KEY_FENCED"),
    ("UPDATE control_plane.cp_generations SET status='SEALED',sealed_at=clock_timestamp()","AUTHORITY_FENCED"),
    ("UPDATE control_plane.cp_continuities SET core_audit_head_hash=repeat('f',64)","AUDIT_FENCED"),
    ("UPDATE control_plane.cp_continuities SET lease_acquired_at=clock_timestamp()-interval '2 hours',lease_last_heartbeat_at=clock_timestamp()-interval '1 hour',lease_expires_at=clock_timestamp()-interval '1 second'","LEASE_EXPIRED"),
])
def test_final_commit_refreshes_current_pg_state_and_preserves_prepared(f3_db,drift,code):
    intent = f3_db.intent()
    ack = f3_db.prepare(intent)
    f3_db.inject(drift)
    before = f3_db.snapshot()
    with pytest.raises(StoreError,match=code):
        f3_db.terminal(intent)
    assert f3_db.snapshot() == before
    assert f3_db.store().query(intent.operation_id,f3_db.caller).wire == ack


def test_abort_is_permanent_and_advances_only_selected_audit(f3_db):
    intent = f3_db.intent()
    f3_db.prepare(intent)
    wire = f3_db.terminal(intent,"ABORT")
    receipt = decode_canonical_wire(wire)
    assert receipt["result_state"] == "ABORTED"
    assert receipt["core_audit_candidate_hash"] == intent.payload["core_audit_candidate_hash"]
    assert receipt["result_payload_hash"] == intent.result_hash("ABORTED")
    assert f3_db.snapshot()[0] == (1,2,"d"*64)
    before = f3_db.snapshot()
    with pytest.raises(StoreError,match="AUTHORIZATION_CONFLICT"):
        f3_db.terminal(intent,"COMMIT")
    assert f3_db.terminal(intent,"ABORT") == wire
    assert f3_db.store().query(intent.operation_id,f3_db.caller).wire == wire
    assert f3_db.snapshot() == before


def test_wrong_intent_scope_and_local_attestation_have_no_effect(f3_db):
    intent = f3_db.intent()
    f3_db.prepare(intent)
    before = f3_db.snapshot()
    other = f3_db.intent(operation_id=intent.operation_id,mutation_id="changed")
    with pytest.raises(StoreError,match="OPERATION_CONFLICT"):
        f3_db.prepare(other)
    forged = AuthenticatedCaller(uid(1),uid(4),uid(5),uid(99),uid(6),"test-owner")
    with pytest.raises(StoreError,match="OPERATION_CONFLICT"):
        f3_db.store().lookup_intent(intent.operation_id,forged)
    auth = authorization_value(intent)
    auth["local_commit_id"] = uid(99)
    with pytest.raises(psycopg.Error,match="ATTESTATION_MISMATCH"):
        with f3_db.service() as connection:
            connection.execute("SELECT * FROM control_plane.f3_propose_terminal(%s,%s,%s)",
                (intent.request_wire,Jsonb(f3_db.caller.as_mapping()),canonical_bytes(auth)))
    assert f3_db.snapshot() == before


def test_proposal_connection_loss_finalize_failure_and_response_loss(f3_db):
    intent = f3_db.intent()
    f3_db.prepare(intent)
    before = f3_db.snapshot()
    authorization = CommitAuthorization.from_mapping(authorization_value(intent))
    with pytest.raises(RuntimeError,match="signer failed"):
        with f3_db.store().terminal(intent,f3_db.caller,authorization):
            raise RuntimeError("signer failed")
    assert f3_db.snapshot() == before
    connection = f3_db.service()
    connection.execute("SELECT * FROM control_plane.f3_propose_terminal(%s,%s,%s)",
        (intent.request_wire,Jsonb(f3_db.caller.as_mapping()),authorization.wire)).fetchone()
    connection.close()  # Actual backend rollback, not a mocked connection.
    assert f3_db.snapshot() == before
    with pytest.raises(StoreError,match="PROPOSAL_MISMATCH"):
        with f3_db.store().terminal(intent,f3_db.caller,authorization) as tx:
            tx.finalize(uid(99),b"s"*64)
    assert f3_db.snapshot() == before
    wire = f3_db.terminal(intent)
    # Simulated response loss occurs AFTER actual SQL COMMIT; fresh instance queries same ID.
    new_store = f3_db.store()
    assert new_store.query(intent.operation_id,f3_db.caller,intent.request_hash).wire == wire
    after = f3_db.snapshot()
    assert f3_db.terminal(intent,store=new_store) == wire
    assert f3_db.snapshot() == after


def _wait_for_database_deadline(database, deadline):
    """Observe PostgreSQL's clock; expiry evidence is not a sleep-based race winner."""
    with database.owner() as connection:
        while not connection.execute("SELECT clock_timestamp() >= %s",(deadline,)).fetchone()[0]:
            pass


@pytest.mark.parametrize("after_finalize",[False,True])
def test_expiry_after_signing_or_before_commit_rolls_back_every_effect(f3_db,after_finalize):
    intent = f3_db.intent()
    f3_db.prepare(intent)
    f3_db.inject("UPDATE control_plane.cp_continuities SET lease_expires_at=clock_timestamp()+interval '1 second'")
    with f3_db.owner() as connection:
        deadline = connection.execute("SELECT lease_expires_at FROM control_plane.cp_continuities").fetchone()[0]
    before = f3_db.snapshot()
    auth = CommitAuthorization.from_mapping(authorization_value(intent))
    with pytest.raises(StoreError,match="COMMIT_EXPIRED|LEASE_EXPIRED"):
        with f3_db.store().terminal(intent,f3_db.caller,auth) as tx:
            signature = f3_db.signer.sign(RECEIPT_PREFIX+tx.proposal.wire)
            if after_finalize:
                tx.finalize(intent.operation_id,signature)
            _wait_for_database_deadline(f3_db,deadline)
            if not after_finalize:
                tx.finalize(intent.operation_id,signature)
    assert f3_db.snapshot() == before
