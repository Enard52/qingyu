"""Actual coordinator + TLS HTTP + durable Core evidence on isolated F3 PostgreSQL.

The fixture uses synthetic Root/receipt keys and production-shaped signatures;
these tests are not acceptance, formal migration or Windows custody evidence.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID
from urllib.parse import urlsplit

import pytest
import uvicorn
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.canonical import canonical_json, sha256_hex as core_hash
from app.control_plane.r1_admission import AdmissionError
from app.control_plane.r1_api import ScopedBearerAuthenticator, authority_server_config
from app.control_plane.r1_client import AuthorityClient, ReconciliationRequired
from app.control_plane.r1_commands import AbortAuthorization, CommitAuthorization
from app.control_plane.r1_commands import MutationIntent, AuthenticatedCaller
from app.control_plane.r1_postgres_store import StoreError
from app.control_plane.r1_coordinator import R1Coordinator
from app.control_plane.r1_protocol import ProtocolError, canonical_bytes, decode_canonical_wire
from app.control_plane.r1_server import AuthorityRuntimeDependencies, create_authority_runtime
from app.errors import CoreError
from app.r1_local_store import CoreRuntimeScope, R1AuditRow, R1Checkpoint, R1LocalBase, R1LocalOperation, R1LocalStore
from app.r1_service import R1CoreConsumer
from app.schemas import MutationRequest
from r1_f3_helpers import authorization_value, uid
from r1_runtime_helpers import SyntheticSigner, SyntheticRootSource, initial_audit_record
from test_r1_coordinator_postgres import f3_cluster, f3_db
from test_r1_coordinator_postgres import _insert


def coordinator(database, signer=None, store=None):
    return R1Coordinator(store=store or database.store(), admission=database.admission,
                         receipt_signer=signer or SyntheticSigner(database.signer))


@contextmanager
def running_api(database, coord=None):
    signer = SyntheticSigner(database.signer)
    app = create_authority_runtime(runtime=AuthorityRuntimeDependencies(database.admission, database.service,
        signer, ScopedBearerAuthenticator(lambda: "f3-synthetic-token", database.caller),
        root_trust_source=SyntheticRootSource(database.admission.public.root)))
    if coord is not None:
        # Rebuild through the same production API factory for fault injection.
        from app.control_plane.r1_api import create_authority_app
        app = create_authority_app(coordinator=coord,
            authenticator=ScopedBearerAuthenticator(lambda: "f3-synthetic-token", database.caller))
    port = urlsplit(database.pin.https_origin).port
    config = authority_server_config(app, host="127.0.0.1", port=port,
        certificate_file=database.tls_material[1], private_key_file=database.tls_material[2])
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not server.started and thread.is_alive() and time.monotonic() < deadline:
        threading.Event().wait(0.01)  # Only server startup, never a race winner.
    assert server.started
    try:
        yield app, signer
    finally:
        server.should_exit = True
        thread.join(10)
        assert not thread.is_alive()


def core_fixture(database, tmp_path):
    engine = create_engine("sqlite+pysqlite:///" + str(tmp_path / "core-only.db"))
    R1LocalBase.metadata.create_all(engine)  # Explicit isolated Core test installation only.
    factory = sessionmaker(engine, expire_on_commit=False)
    scope = CoreRuntimeScope(uid(1), uid(3), uid(4), uid(11), 1, 1, "test-owner", uid(6), uid(10), uid(8), 1, uid(5), uid(9))
    evidence = canonical_bytes(database.store().genesis_evidence(database.caller))
    record = initial_audit_record()
    with factory.begin() as session:
        session.add(R1AuditRow(audit_sequence=1, operation_id=uid(11), canonical_record=canonical_json(record),
                               projection=record, record_hash=core_hash(record)))
        session.add(R1Checkpoint(continuity_id=scope.continuity_id, scope_wire=scope.wire,
            origin_digest=database.admission.public.origin.signed_provisioning_origin_digest, state_version=1,
            audit_sequence=1, audit_head_hash=core_hash(record), next_authority_sequence=2,
            authority_head_hash=database.snapshot()[1][1], status="READY"))
    def local():
        return R1LocalStore(factory, admission=database.admission.public, scope=scope, genesis_evidence_wire=evidence)
    def client():
        return AuthorityClient(pin=database.pin, ca_file=database.tls_material[0],
                               credential_provider=lambda: "f3-synthetic-token")
    def consumer():
        return R1CoreConsumer(local_store=local(), client=client())
    return factory, local, client, consumer


def request(mid="runtime-1"):
    return MutationRequest(continuity_id=UUID(uid(4)), continuity_epoch=1, lease_id=UUID(uid(8)),
        mutation_id=mid, actor_principal_id="test-owner", capability="core_governance", payload={"text": "actual TLS 测试"})


def test_actual_coordinator_signed_commit_abort_and_16_terminal_retries(f3_db):
    coord = coordinator(f3_db)
    intent = f3_db.intent()
    ack = coord.prepare(intent.request_wire, f3_db.caller)
    auth = CommitAuthorization.from_mapping(authorization_value(intent))
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda _: coordinator(f3_db).decide(intent.operation_id, auth, f3_db.caller), range(16)))
    assert len(set(results)) == 1
    assert coord.query(intent.operation_id, f3_db.caller) == results[0]
    assert f3_db.snapshot()[0] == (2, 2, intent.payload["core_audit_candidate_hash"])
    assert f3_db.snapshot()[1][0] == 2


@pytest.mark.parametrize("failure", ["raise", "bad_signature"])
def test_actual_coordinator_signer_failure_leaves_no_prepare(f3_db, failure):
    signer = SyntheticSigner(f3_db.signer)
    def broken(_):
        if failure == "raise":
            raise RuntimeError("synthetic signer unavailable")
        return b"x" * 64
    signer.sign = broken
    coord = coordinator(f3_db, signer)
    before = f3_db.snapshot()
    with pytest.raises(Exception):
        coord.prepare(f3_db.intent().request_wire, f3_db.caller)
    assert f3_db.snapshot() == before


def test_admission_drift_fails_before_store_or_signer(f3_db):
    coord = coordinator(f3_db)
    class ForbiddenStore:
        def describe(self):
            pytest.fail("DB accessed after independent admission became unavailable")
    coord.store = ForbiddenStore()
    f3_db.admission.inspector.available = False
    with pytest.raises(RuntimeError, match="observations unavailable"):
        coord.prepare(f3_db.intent().request_wire, f3_db.caller)
    assert coord.signer.calls == []


def test_real_tls_core_two_mutations_and_historical_cursor(f3_db, tmp_path):
    factory, local, client, consumer = core_fixture(f3_db, tmp_path)
    with running_api(f3_db):
        first = consumer().governed_mutation(request("one"))
        second = consumer().governed_mutation(request("two"))
        before = f3_db.snapshot()
        for _ in range(16):
            assert consumer().governed_mutation(request("one")) == first
        assert f3_db.snapshot() == before
    assert first.state_version == 2 and second.state_version == 3
    assert local().inspect()["audit_sequence"] == 3


def test_real_tls_abort_publishes_abort_audit_then_next_mutation(f3_db, tmp_path):
    factory, local, client, consumer = core_fixture(f3_db, tmp_path)
    with running_api(f3_db):
        result = consumer().abort_mutation(request("abort"))
        assert result.status == "ABORTED" and result.state_version == 1
        assert f3_db.snapshot()[0] == (1, 2, result.audit_head_hash)
        later = consumer().governed_mutation(request("after-abort"))
        assert later.state_version == 2 and later.audit_seq == 3


def test_real_tls_crash_after_prepare_before_ack_save_uses_original_ack(f3_db, tmp_path):
    factory, local, client, consumer = core_fixture(f3_db, tmp_path)
    with running_api(f3_db) as (_, signer):
        durable = local().begin_intent(request())
        ack = client().prepare(durable.attempt, cursor=durable.cursor)
        assert len(signer.calls) == 1
        outcome = consumer().governed_mutation(request())
        assert outcome.status == "COMMITTED" and len(signer.calls) == 2
        with factory() as session:
            row = session.get(R1LocalOperation, durable.intent.operation_id)
            assert row.ack_wire == canonical_bytes(ack.message)


def test_real_tls_terminal_response_loss_restarts_with_same_authorization(f3_db, tmp_path):
    factory, local, client, consumer = core_fixture(f3_db, tmp_path)
    with running_api(f3_db):
        durable = local().begin_intent(request())
        phase = client().prepare(durable.attempt, cursor=durable.cursor)
        staged = local().stage(durable.intent.operation_id, phase)
        terminal = client().commit(staged.attempt, CommitAuthorization.from_wire(staged.authorization_wire), cursor=staged.cursor)
        before = f3_db.snapshot()
        # Process stops before local finalize. A new consumer resolves via GET.
        result = consumer().governed_mutation(request())
        assert result.status == "COMMITTED" and f3_db.snapshot() == before
        with factory() as session:
            row = session.get(R1LocalOperation, durable.intent.operation_id)
            assert row.authorization_wire == staged.authorization_wire
            assert row.terminal_wire == canonical_bytes(terminal.message)


@pytest.mark.parametrize("corrupt", ["projection", "hash", "head", "storage", "authority_hash", "authority_sequence"])
def test_new_consumer_local_corruption_fails_before_http(f3_db, tmp_path, corrupt):
    factory, local, client, consumer = core_fixture(f3_db, tmp_path)
    with factory.begin() as session:
        if corrupt in {"projection", "hash"}:
            row = session.get(R1AuditRow, 1)
            if corrupt == "projection":
                row.projection = {**row.projection, "state_version": 99}
            else:
                row.record_hash = "f" * 64
        else:
            row = session.get(R1Checkpoint, uid(4))
            if corrupt == "head":
                row.audit_head_hash = "f" * 64
            elif corrupt == "storage":
                row.scope_wire = row.scope_wire.replace(uid(6).encode(), uid(60).encode())
            elif corrupt == "authority_hash":
                row.authority_head_hash = "f" * 64
            else:
                row.next_authority_sequence += 1
    before = f3_db.snapshot()
    with pytest.raises(CoreError):
        consumer().governed_mutation(request())
    assert f3_db.snapshot() == before


def test_api_rejects_http_and_body_claimed_caller(f3_db):
    from app.control_plane.r1_api import create_authority_app
    app = create_authority_app(coordinator=coordinator(f3_db),
        authenticator=ScopedBearerAuthenticator(lambda: "secret", f3_db.caller))
    before = f3_db.snapshot()
    with TestClient(app, base_url="http://authority.invalid") as test:
        response = test.post("/v1/operations", content=f3_db.intent().request_wire,
            headers={"Authorization": "Bearer secret", "Content-Type": "application/json", "X-Forwarded-Proto": "https"})
        assert response.status_code == 403
    assert f3_db.snapshot() == before


def full_operations(database):
    with database.owner() as connection:
        return connection.execute("SELECT to_jsonb(o) FROM control_plane.cp_operations o ORDER BY operation_id").fetchall()


def wait_for_pg_blocker(database, blocked_pid=None, blocker_pid=None):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        with database.owner() as observer:
            rows = observer.execute("SELECT pid,pg_blocking_pids(pid) FROM pg_stat_activity WHERE datname=current_database()").fetchall()
        found = [(pid, blockers) for pid, blockers in rows if blockers
                 and (blocked_pid is None or pid == blocked_pid)
                 and (blocker_pid is None or blocker_pid in blockers)]
        if found:
            return found
        threading.Event().wait(0.01)  # Wait for observed PG locks, not a race outcome.
    pytest.fail("expected actual PostgreSQL blocking relation was not observed")


TRANSITIONS = {
    "quarantine": "UPDATE control_plane.cp_continuities SET recovery_state='QUARANTINED',admission_state='CLOSED'",
    "recovery_prepared": "UPDATE control_plane.cp_continuities SET recovery_state='PREPARED'",
    "active_storage": """UPDATE control_plane.cp_continuities
        SET active_storage_generation_id='00000000-0000-4000-8000-000000000078',
        lease_status='REVOKED',lease_runtime_id=NULL,lease_session_id=NULL,
        lease_storage_generation_id=NULL,lease_epoch=NULL,lease_acquired_at=NULL,
        lease_last_heartbeat_at=NULL,lease_expires_at=NULL""",
    "epoch": "UPDATE control_plane.cp_continuities SET continuity_epoch=continuity_epoch+1,lease_epoch=lease_epoch+1",
    "state": "UPDATE control_plane.cp_continuities SET state_version=state_version+1",
    "cp_generation": "UPDATE control_plane.cp_continuities SET control_plane_generation_id='00000000-0000-4000-8000-000000000077'",
    "authority_generation": "UPDATE control_plane.cp_generations SET status='SEALED',sealed_at=clock_timestamp()",
}


def lock_and_transition(connection, transition):
    connection.execute("SELECT 1 FROM control_plane.cp_generations FOR UPDATE")
    connection.execute("SELECT 1 FROM control_plane.cp_continuities FOR UPDATE")
    connection.execute(TRANSITIONS[transition])


@pytest.mark.parametrize("transition", list(TRANSITIONS))
@pytest.mark.parametrize("order", ["transition_first", "commit_first"])
def test_actual_coordinator_pg_lock_race_both_orders(f3_db, transition, order):
    intent = f3_db.intent()
    coordinator(f3_db).prepare(intent.request_wire, f3_db.caller)
    auth = CommitAuthorization.from_mapping(authorization_value(intent))
    before_head, before_ops = f3_db.snapshot()[1], full_operations(f3_db)
    if order == "transition_first":
        with ThreadPoolExecutor(max_workers=1) as pool, f3_db.owner() as owner:
            lock_and_transition(owner, transition)
            future = pool.submit(coordinator(f3_db).decide, intent.operation_id, auth, f3_db.caller)
            wait_for_pg_blocker(f3_db, blocker_pid=owner.info.backend_pid)
            owner.commit()
            with pytest.raises((StoreError, AdmissionError)):
                future.result(10)
        assert f3_db.snapshot()[1] == before_head
        assert full_operations(f3_db) == before_ops
    else:
        entered, release, owner_started = threading.Event(), threading.Event(), threading.Event()
        signer = SyntheticSigner(f3_db.signer)
        original = signer.sign
        def block(message):
            entered.set()
            assert release.wait(10)
            return original(message)
        signer.sign = block
        coord = coordinator(f3_db, signer)
        owner_pid = []
        def change():
            with f3_db.owner() as connection:
                owner_pid.append(connection.info.backend_pid)
                owner_started.set()
                lock_and_transition(connection, transition)
        with ThreadPoolExecutor(max_workers=2) as pool:
            final = pool.submit(coord.decide, intent.operation_id, auth, f3_db.caller)
            assert entered.wait(10)
            change_future = pool.submit(change)
            assert owner_started.wait(5)
            wait_for_pg_blocker(f3_db, blocked_pid=owner_pid[0])
            release.set()
            receipt = decode_canonical_wire(final.result(10))
            change_future.result(10)
        assert receipt["result_state"] == "COMMITTED"
        assert f3_db.snapshot()[1][0] == before_head[0] + 1
        assert len([row for (row,) in full_operations(f3_db) if row["operation_id"] == intent.operation_id
                    and row["state"] == "COMMITTED"]) == 1


def synthetic_takeover(database):
    """Privileged fixture changes only; NOT a production owner/recovery API."""
    now = datetime.now(timezone.utc)
    caller = AuthenticatedCaller(uid(1),uid(4),uid(50),uid(59),uid(6),"test-owner")
    with database.owner() as connection:
        connection.execute("SELECT 1 FROM control_plane.cp_generations FOR UPDATE")
        connection.execute("SELECT 1 FROM control_plane.cp_continuities FOR UPDATE")
        connection.execute("UPDATE control_plane.cp_runtime_sessions SET session_state='REVOKED',revoked_at=clock_timestamp()")
        _insert(connection, "cp_runtime_sessions", {"authority_domain_id":UUID(uid(1)),"caller_runtime_id":UUID(uid(50)),
            "session_id":UUID(uid(59)),"continuity_id":UUID(uid(4)),"storage_generation_id":UUID(uid(6)),
            "process_nonce_hash":"e"*64,"session_state":"ACTIVE","claimed_at":now,"last_heartbeat_at":now,
            "expires_at":now+timedelta(hours=1)})
        connection.execute("""UPDATE control_plane.cp_continuities SET lease_id=%s,lease_generation=2,
            lease_runtime_id=%s,lease_session_id=%s,lease_acquired_at=%s,lease_last_heartbeat_at=%s,lease_expires_at=%s""",
            (UUID(uid(58)),UUID(uid(50)),UUID(uid(59)),now,now,now+timedelta(hours=1)))
    return caller


def test_old_prepared_takeover_never_grants_new_caller_that_intent(f3_db):
    intent = f3_db.intent()
    coordinator(f3_db).prepare(intent.request_wire,f3_db.caller)
    caller_b = synthetic_takeover(f3_db)
    before, head = full_operations(f3_db), f3_db.snapshot()[1]
    barrier = threading.Barrier(2)
    auth = CommitAuthorization.from_mapping(authorization_value(intent))
    def attempt(caller):
        coord = coordinator(f3_db)
        barrier.wait(5)
        with pytest.raises((StoreError, ProtocolError)):
            coord.decide(intent.operation_id,auth,caller)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(attempt,[f3_db.caller,caller_b]))
    assert full_operations(f3_db) == before and f3_db.snapshot()[1] == head


def test_actual_stale_and_current_holder_compete_without_existing_prepare(f3_db):
    stale = f3_db.intent()
    caller_b = synthetic_takeover(f3_db)
    envelope = f3_db.intent(mutation_id="new-holder").envelope
    envelope["caller_runtime_id"] = caller_b.caller_runtime_id
    envelope["payload"].update(lease_id=uid(58),lease_generation=2,session_id=caller_b.session_id)
    current = MutationIntent.from_envelope(envelope)
    barrier = threading.Barrier(2)
    def attempt(pair):
        intent, caller = pair
        coord = coordinator(f3_db)
        barrier.wait(5)
        try:
            coord.prepare(intent.request_wire,caller)
            return coord.decide(intent.operation_id,CommitAuthorization.from_mapping(authorization_value(intent)),caller)
        except StoreError:
            return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt,[(stale,f3_db.caller),(current,caller_b)]))
    assert results[0] is None and decode_canonical_wire(results[1])["result_state"] == "COMMITTED"
    assert f3_db.snapshot()[1][0] == 2


def test_real_tls_16_identical_commit_requests_one_core_publication(f3_db,tmp_path):
    factory, local, client, consumer = core_fixture(f3_db,tmp_path)
    with running_api(f3_db):
        item = local().begin_intent(request())
        ack = client().prepare(item.attempt,cursor=item.cursor)
        staged = local().stage(item.intent.operation_id,ack)
        auth = CommitAuthorization.from_wire(staged.authorization_wire)
        barrier = threading.Barrier(16)
        def finish(_):
            with client() as http:
                barrier.wait(10)
                return http.commit(staged.attempt,auth,cursor=staged.cursor)
        with ThreadPoolExecutor(max_workers=16) as pool:
            phases = list(pool.map(finish,range(16)))
        assert len({canonical_bytes(p.message) for p in phases}) == 1
        consumer().governed_mutation(request())
    assert local().inspect()["audit_sequence"] == 2 and f3_db.snapshot()[1][0] == 2


@pytest.mark.parametrize("corrupt", ["cursor", "authorization", "audit_candidate", "scope"])
def test_staged_local_evidence_corruption_prevents_next_http(f3_db,tmp_path,corrupt):
    factory, local, client, consumer = core_fixture(f3_db,tmp_path)
    with running_api(f3_db):
        item = local().begin_intent(request())
        ack = client().prepare(item.attempt,cursor=item.cursor)
        staged = local().stage(item.intent.operation_id,ack)
    before = full_operations(f3_db)
    with factory.begin() as session:
        row = session.get(R1LocalOperation,item.intent.operation_id)
        if corrupt == "cursor":
            row.cursor_hash = "f"*64
        elif corrupt == "authorization":
            value = decode_canonical_wire(row.authorization_wire)
            value["transaction_evidence_hash"] = "f"*64
            row.authorization_wire = canonical_bytes(value)
        elif corrupt == "audit_candidate":
            row.commit_audit_wire += b" "
        else:
            row.continuity_id = uid(90)
    item_consumer = consumer()
    item_consumer.client.query = lambda *a,**k: pytest.fail("HTTP after corrupted durable staged proof")
    item_consumer.client.prepare = item_consumer.client.query
    with pytest.raises((CoreError,ProtocolError)):
        item_consumer.governed_mutation(request())
    assert full_operations(f3_db) == before
    assert local().inspect()["audit_sequence"] == 1


def test_actual_store_rejects_admin_role_before_mutation(f3_db):
    from app.control_plane.r1_postgres_store import R1PostgresStore
    before = full_operations(f3_db)
    with pytest.raises(StoreError,match="RUNTIME_ROLE_FORBIDDEN"):
        R1PostgresStore(f3_db.owner).describe()
    assert full_operations(f3_db) == before


def test_real_server_rejects_tls12(f3_db):
    import socket
    import ssl
    before = full_operations(f3_db)
    with running_api(f3_db) as (_,signer):
        context = ssl.create_default_context(cafile=f3_db.tls_material[0])
        context.maximum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(("127.0.0.1",urlsplit(f3_db.pin.https_origin).port)) as sock:
            with pytest.raises(ssl.SSLError):
                context.wrap_socket(sock,server_hostname="127.0.0.1")
        assert signer.calls == []
    assert full_operations(f3_db) == before


def test_coordinator_finalize_then_connection_loss_rolls_back_every_column(f3_db):
    from app.control_plane.r1_postgres_store import R1PostgresStore
    intent = f3_db.intent()
    coordinator(f3_db).prepare(intent.request_wire,f3_db.caller)
    before, head = full_operations(f3_db), f3_db.snapshot()[1]
    class LostAfterFinalize(R1PostgresStore):
        @contextmanager
        def terminal(self,*args,**kwargs):
            with super().terminal(*args,**kwargs) as tx:
                finalize = tx.finalize
                def lose(operation_id,signature):
                    result = finalize(operation_id,signature)
                    tx._connection.close()  # Synthetic connection fault before COMMIT.
                    return result
                tx.finalize = lose
                yield tx
    with pytest.raises(StoreError):
        coordinator(f3_db,store=LostAfterFinalize(f3_db.service)).decide(intent.operation_id,
            CommitAuthorization.from_mapping(authorization_value(intent)),f3_db.caller)
    assert full_operations(f3_db) == before and f3_db.snapshot()[1] == head


@pytest.mark.parametrize("fault", ["different_connection", "skip_sql_finalize"])
def test_coordinator_transaction_bound_finalizer_and_deferred_guard(f3_db, fault):
    from app.control_plane.r1_postgres_store import R1PostgresStore
    intent = f3_db.intent()
    coordinator(f3_db).prepare(intent.request_wire,f3_db.caller)
    before, head = full_operations(f3_db), f3_db.snapshot()[1]
    class InvalidFinalize(R1PostgresStore):
        @contextmanager
        def terminal(self,*args,**kwargs):
            with super().terminal(*args,**kwargs) as tx:
                def invalid(operation_id,signature):
                    if fault == "different_connection":
                        # A second actual service connection cannot finalize the
                        # first transaction's proposal, even with its signature.
                        with f3_db.service() as other:
                            other.execute("SELECT control_plane.f3_finalize_terminal(%s,%s)",
                                          (UUID(operation_id),signature)).fetchone()
                        pytest.fail("cross-connection finalizer was accepted")
                    # Synthetic adapter bug bypasses only the Python completion
                    # flag. PostgreSQL's deferred guard must reject COMMIT.
                    tx._finalized = True
                    return canonical_bytes({**decode_canonical_wire(tx.proposal.wire),
                                            "receipt_signature":signature.hex()})
                tx.finalize = invalid
                yield tx
    expected = "PROPOSAL_MISMATCH" if fault == "different_connection" else "UNFINALIZED_PROPOSAL"
    with pytest.raises(StoreError,match=expected):
        coordinator(f3_db,store=InvalidFinalize(f3_db.service)).decide(intent.operation_id,
            CommitAuthorization.from_mapping(authorization_value(intent)),f3_db.caller)
    assert full_operations(f3_db) == before and f3_db.snapshot()[1] == head


def test_supported_factory_checks_canonical_root_before_store(f3_db):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from app.control_plane.r1_protocol import key_id
    from app.control_plane.r1_root_pin import OperatorRootPin, PRODUCTION, RootPinError
    other = Ed25519PrivateKey.generate().public_key()
    wrong = OperatorRootPin(PRODUCTION,False,key_id(other),other)
    def forbidden():
        pytest.fail("store opened with absent or different canonical Root")
    runtime = AuthorityRuntimeDependencies(f3_db.admission,forbidden,SyntheticSigner(f3_db.signer),lambda _:f3_db.caller,
        root_trust_source=SyntheticRootSource(wrong))
    with pytest.raises(AdmissionError,match="canonical machine"):
        create_authority_runtime(runtime=runtime)
    class Missing:
        def read(self,profile):
            raise RootPinError("synthetic missing public pin")
    with pytest.raises(AdmissionError,match="unavailable"):
        create_authority_runtime(runtime=replace(runtime,root_trust_source=Missing()))


def test_supported_core_web_factory_uses_real_consumer_and_defers_token(f3_db,tmp_path,monkeypatch):
    import app.service_factory as composition
    from app.config import Settings
    from app.main import create_app
    from app.service_factory import CoreRuntimeDependencies
    factory, local, client, consumer = core_fixture(f3_db,tmp_path)
    source = local()
    token_calls = []
    def credential():
        token_calls.append(1)
        return "f3-synthetic-token"
    runtime = CoreRuntimeDependencies(f3_db.admission.public,source.scope,
        canonical_bytes(f3_db.store().genesis_evidence(f3_db.caller)),"secret://test/core",credential,
        root_trust_source=SyntheticRootSource(f3_db.admission.public.root))
    pin = f3_db.pin
    settings = Settings(app_env="production",CORE_DATABASE_URL="postgresql+psycopg://core@127.0.0.1/qingyu_core_test",
        CORE_CONTROL_PLANE_BACKEND="r1_https",CORE_CONTROL_PLANE_API_BASE_URL=pin.https_origin,
        CORE_CONTROL_PLANE_CA_FILE=f3_db.tls_material[0],CORE_CONTROL_PLANE_CREDENTIAL_REFERENCE="secret://test/core",
        CORE_CONTROL_PLANE_DOMAIN_ID=pin.authority_domain_id,CORE_CONTROL_PLANE_INSTANCE_ID=pin.authority_instance_id,
        CORE_CONTROL_PLANE_GENERATION=1,CORE_CONTROL_PLANE_SPKI_SHA256=pin.server_spki_sha256,
        CORE_CONTROL_PLANE_RECEIPT_KEY_ID=pin.receipt_key_id,CORE_CONTROL_PLANE_ROOT_KEY_ID=pin.operator_root_key_id,
        CORE_CONTROL_PLANE_TOKEN="inbound-capability")
    # Only the Core-local SQLite test connection is injected. Authority calls
    # still cross the real TLS/API/coordinator/PostgreSQL production path.
    monkeypatch.setattr(composition,"session_factory",lambda _:factory)
    with running_api(f3_db), TestClient(create_app(settings=settings,runtime=runtime)) as web:
        assert isinstance(web.app.state.service,R1CoreConsumer)
        assert token_calls == []
        response = web.post("/internal/v1/mutations",json=request().model_dump(mode="json"),
                            headers={"X-Core-Governance-Capability":"inbound-capability"})
        assert response.status_code == 200 and response.json()["status"] == "COMMITTED"
        assert len(token_calls) == 2
        unsupported = web.app.state.service
        with pytest.raises(CoreError,match="LIFECYCLE_NOT_IMPLEMENTED"):
            unsupported.acquire_owner_lease(UUID(uid(4)))


def test_abort_intent_crash_before_ack_save_never_changes_to_commit(f3_db,tmp_path):
    factory, local, client, consumer = core_fixture(f3_db,tmp_path)
    with running_api(f3_db):
        item = local().begin_intent(request("abort-crash"),decision="ABORT")
        client().prepare(item.attempt,cursor=item.cursor)
        consumer().reconcile_pending()
        result = consumer().abort_mutation(request("abort-crash"))
        assert result.status == "ABORTED" and result.state_version == 1
    assert f3_db.snapshot()[0][0] == 1
    assert local().inspect()["audit_sequence"] == 2


def test_core_intent_freezes_caller_input_before_database_wait(f3_db,tmp_path):
    factory, local, client, consumer = core_fixture(f3_db,tmp_path)
    original = request("snapshot")
    source = local()
    checkpoint = source._checkpoint
    def mutate_caller(*args,**kwargs):
        original.payload["text"] = "mutated after freeze"
        original.mutation_id = "different-id"
        return checkpoint(*args,**kwargs)
    source._checkpoint = mutate_caller
    item = source.begin_intent(original)
    assert item.intent.payload["mutation_id"] == "snapshot"
    assert item.intent.payload["staged_result"]["value"]["payload"] == request().payload
    # A fresh process validates the persisted snapshot and sends only those
    # frozen bytes through the actual production chain.
    with running_api(f3_db):
        result = consumer().governed_mutation(request("snapshot"))
    assert result.status == "COMMITTED" and local().inspect()["audit_sequence"] == 2


def test_core_signed_cursor_gap_stays_invisible(f3_db,tmp_path):
    from app.control_plane.r1_client import VerifiedPhase
    from app.control_plane.r1_protocol import sign_terminal_receipt
    factory, local, client, consumer = core_fixture(f3_db,tmp_path)
    with running_api(f3_db):
        item = local().begin_intent(request())
        ack = client().prepare(item.attempt,cursor=item.cursor)
        staged = local().stage(item.intent.operation_id,ack)
        terminal = client().commit(staged.attempt,CommitAuthorization.from_wire(staged.authorization_wire),cursor=staged.cursor)
    # Synthetic valid-key gap injection tests consumer chain policy, not a claim
    # that a second continuity/chain synchronization lifecycle was implemented.
    value = dict(terminal.message)
    value.pop("receipt_signature")
    value.pop("receipt_key_id")
    value["authority_sequence"] += 1
    value["previous_receipt_hash"] = "f"*64
    signed = sign_terminal_receipt(value,f3_db.signer)
    with pytest.raises(ProtocolError,match="chain gap"):
        local().finalize(item.intent.operation_id,VerifiedPhase("COMMITTED",signed))
    assert local().inspect()["audit_sequence"] == 1
    assert local().inspect()["next_authority_sequence"] == 2


@pytest.mark.parametrize("decision", ["COMMIT", "ABORT"])
@pytest.mark.parametrize("newer_pending", [False, True])
def test_late_retry_failure_does_not_demote_verified_terminal_or_clear_pending(f3_db,tmp_path,decision,newer_pending):
    factory, local, client, consumer = core_fixture(f3_db,tmp_path)
    terminal_received, fail_late = threading.Event(), threading.Event()
    delayed = consumer()
    method = "commit" if decision == "COMMIT" else "abort"
    original = getattr(delayed.client,method)
    def lose_after_delivery(*args,**kwargs):
        original(*args,**kwargs)  # Actual TLS/API/coordinator/PostgreSQL terminal.
        terminal_received.set()
        assert fail_late.wait(10)
        raise ReconciliationRequired("synthetic late response loss")
    setattr(delayed.client,method,lose_after_delivery)
    def mutate(service, mid):
        action = service.governed_mutation if decision == "COMMIT" else service.abort_mutation
        return action(request(mid))
    with running_api(f3_db), ThreadPoolExecutor(max_workers=1) as pool:
        late = pool.submit(mutate,delayed,"late-retry")
        assert terminal_received.wait(10)
        try:
            first = mutate(consumer(),"late-retry")
            assert first.status == ("COMMITTED" if decision == "COMMIT" else "ABORTED")
            assert local().inspect()["status"] == "READY"
            pending = local().begin_intent(request("newer")) if newer_pending else None
            before = local().inspect(), full_operations(f3_db)
        finally:
            fail_late.set()
        with pytest.raises(ReconciliationRequired):
            late.result(10)
        assert (local().inspect(),full_operations(f3_db)) == before
        if newer_pending:
            assert local().pending() == [pending.intent.operation_id]
            with pytest.raises(CoreError,match="R1_RECONCILIATION_REQUIRED"):
                consumer().governed_mutation(request("blocked-third"))
        restarted = consumer()
        restarted.reconcile_pending()
        assert local().inspect()["status"] == "READY" and local().pending() == []
        assert mutate(restarted,"late-retry") == first
        following = restarted.governed_mutation(request("following"))
        assert following.status == "COMMITTED"
    assert local().inspect()["audit_sequence"] == (4 if newer_pending else 3)


@pytest.mark.parametrize("corruption", ["signature", "projection", "orphan_terminal"])
def test_uncertainty_never_trusts_invalid_or_unpublished_terminal_history(f3_db,tmp_path,corruption):
    factory, local, client, consumer = core_fixture(f3_db,tmp_path)
    original = local().inspect()
    store = local()
    with running_api(f3_db):
        consumer().governed_mutation(request("invalid-history"))
    before = full_operations(f3_db)
    with factory.begin() as session:
        row = session.scalar(select(R1LocalOperation).where(R1LocalOperation.mutation_id == "invalid-history"))
        operation_id = row.operation_id
        if corruption == "signature":
            receipt = decode_canonical_wire(row.terminal_wire)
            receipt["receipt_signature"] = "f"*128
            row.terminal_wire = canonical_bytes(receipt)
        elif corruption == "projection":
            audit = session.get(R1AuditRow,2)
            audit.projection = {**audit.projection,"state_version":999}
        else:
            # A terminal flag/receipt without its published audit is not a
            # verified completion, even if the old checkpoint is self-consistent.
            session.delete(session.get(R1AuditRow,2))
            cp = session.get(R1Checkpoint,uid(4))
            for name,value in original.items():
                setattr(cp,name,value)
    with pytest.raises(Exception):
        store.uncertain(operation_id)
    with factory.begin() as session:
        assert session.get(R1Checkpoint,uid(4)).status == "RECONCILIATION_REQUIRED"
    with pytest.raises(Exception):
        consumer().governed_mutation(request("must-remain-closed"))
    assert full_operations(f3_db) == before
