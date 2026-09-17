"""Author checks on the explicitly owned Slice03 PostgreSQL instance only.

Set R1_SLICE03_PRIVATE_CONFIG to the current isolated test config. No default
database, environment DSN, prebuilt Ack/FIX/terminal or evidence import is used.
"""
import json
import os
from pathlib import Path
import unittest
import time
from copy import deepcopy
import subprocess
import sys
from dataclasses import asdict
from uuid import uuid4
from dataclasses import replace

import psycopg
from psycopg import sql
from cryptography.hazmat.primitives import serialization

from app.control_plane.r1_scoped_authority import ScopedAuthority, configuration_digest
from app.control_plane.r1_scoped_postgres import ScopedPostgresStore
from app.control_plane.r1_scoped_schema import install_scoped_test_schema
from app.control_plane.r1_scoped_messages import AuthorityCaller
from app.control_plane.r1_postgres_store import StoreError
from app.control_plane.r1_validation_codec import c2, decode, h2, obj, ContractError
from app.control_plane.r1_validation_crypto import verify_signed
from app.r1_scoped_coordinator import build_mutation_request
from tests.r1_roundtrip_provider import ControlledProvider, material, trust, boundary, now_ms, scope_wire, event


class ScopedAuthorityAuthorTests(unittest.TestCase):
    observations = []
    @classmethod
    def setUpClass(cls):
        path = os.environ.get("R1_SLICE03_PRIVATE_CONFIG")
        if not path:
            raise RuntimeError("explicit owned Slice03 config path required")
        cls.path = Path(path)
        cls.config = json.loads(cls.path.read_text())
        c = cls.config
        if c["container"] != "r1-s03-ca100502580e-pg" or c["host"] != "127.0.0.1" or c["port"] != 49995:
            raise RuntimeError("unexpected resource ownership")
        cls.database = "r1_slice03_test_ca100502580e_author_" + uuid4().hex[:8]
        with psycopg.connect(host=c["host"], port=c["port"], dbname=c["dbname"], user="postgres",
                             password=c["admin_password"], autocommit=True) as db:
            db.execute(sql.SQL("CREATE DATABASE {} OWNER control_plane_owner").format(sql.Identifier(cls.database)))
            db.execute(sql.SQL("COMMENT ON DATABASE {} IS {}").format(sql.Identifier(cls.database), sql.Literal("R1_SLICE03_TEST_ONLY:" + cls.database)))
            db.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(cls.database)))
            db.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO control_plane_migrator,control_plane_app").format(sql.Identifier(cls.database)))
        cls.public_trust, cls.deployment, cls.initial = trust(c), material(c), boundary(c)
        cls.digest = configuration_digest(cls.public_trust, (cls.deployment,), cls.initial)
        with cls.connect("control_plane_migrator") as db:
            db.execute("SET ROLE control_plane_owner")
            db.execute("CREATE SCHEMA control_plane AUTHORIZATION control_plane_owner")
            install_scoped_test_schema(db, test_database_name=cls.database, scope_id=str(uuid4()), configuration_digest=cls.digest)

    @classmethod
    def connect(cls, role="control_plane_app"):
        c = cls.config
        return psycopg.connect(host=c["host"], port=c["port"], dbname=cls.database, user=role,
                               password=c["app_password" if role == "control_plane_app" else "migrator_password"])

    def setUp(self):
        self.scope_id = str(uuid4())
        with self.connect("control_plane_migrator") as db:
            db.execute("SET ROLE control_plane_owner")
            db.execute("INSERT INTO control_plane.r1s_scopes(scope_id,configuration_digest) VALUES(%s,%s)", (self.scope_id, self.digest))
        key = serialization.load_pem_private_key((self.path.parent / "receipt.key").read_bytes(), None)
        self.sign_calls = []
        class Signer:
            key_id = self.public_trust.receipt_key_id
            def sign(inner, message):
                self.sign_calls.append(message)
                return key.sign(message)
        self.signer = Signer()
        self.store = ScopedPostgresStore(self.connect, scope_id=self.scope_id, configuration_digest=self.digest)
        self.authority = ScopedAuthority(store=self.store, trust=self.public_trust, deployments=(self.deployment,),
                                          boundary=self.initial, receipt_signer=self.signer)
        self.provider = ControlledProvider(self.path, self.authority)

    def request(self, decision="COMMIT"):
        c = self.config
        scope = obj("requested_scope", **{k: c["pin"][k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation")},
            trust_domain_id=c["trust_domain_id"], actor_identity=c["actor_identity"], owner_version=1, continuity_epoch=1,
            expected_state_version=4, storage_generation_id=c["storage_generation_id"], control_plane_generation_id=c["control_plane_generation_id"],
            lease_id=str(uuid4()), lease_generation=1, caller_runtime_id=str(uuid4()), session_id=str(uuid4()), capability="core_governance",
            expected_authority_ref=c["checkpoint"]["authority_ref"], expected_audit_ref=c["checkpoint"]["audit_ref"])
        wire = build_mutation_request(identity=c["identity"], scope=scope, payload={"author": "ordinary"},
                                      mutation_id=str(uuid4()), decision=decision, created_at=now_ms())
        source = self.provider.intake(wire)
        self.provider.ensure_execution(wire, source)
        return wire, source, self.provider.caller(decode(wire))

    def snapshot(self):
        return self.store.transact(lambda tx: (tx.revision, tx.raw_windows))

    def paused_core(self, stop):
        """Generate proposal/publication through the real durable Core entry.

        This focused layer test uses a direct client adapter. The separate root
        integration suite exercises the same operation with actual pinned TLS.
        """
        from app._r1_coordination_journal import CoordinationJournal
        from app._r1_scoped_sqlite import ScopedSQLiteStore
        from app.r1_atomic_finish import ScopedCoreFinisher
        from app.r1_scoped_coordinator import ScopedCoreCoordinator
        folder = self.path.parent / ("author-local-" + uuid4().hex)
        folder.mkdir()
        cfg = self.config
        journal = CoordinationJournal.create(folder / "coordination.sqlite", scope_wire=scope_wire(cfg), checkpoint_wire=c2(cfg["checkpoint"]))
        store = ScopedSQLiteStore.create(folder / "finish.sqlite", scope_wire=scope_wire(cfg), checkpoint_wire=c2(cfg["checkpoint"]), business_state_wire=c2({}))
        finisher = ScopedCoreFinisher(store, trust=self.public_trust, deployments=(self.deployment,),
            runtime_principal=cfg["runtime_principal"], source=self.provider)
        provider, authority = self.provider, self.authority
        class Client:
            def query(inner, op, wire, authority_after=0):
                return authority.query(op, wire, provider.caller(decode(wire)), authority_after=authority_after)
            def prepare(inner, wire, source, authority_after=0):
                return authority.prepare(wire, source, provider.caller(decode(wire)), authority_after=authority_after)
            def decide(inner, op, wire, auth, proposal, publication, core, authority_after=0):
                return authority.decide(op, wire, auth, proposal, publication, core, provider.caller(decode(wire)), authority_after=authority_after)
        def hook(stage):
            if stage == stop:
                raise RuntimeError("controlled product boundary " + stop)
        coordinator = ScopedCoreCoordinator(journal=journal, finisher=finisher, client=Client(), source=provider, checkpoint_hook=hook)
        wire, source, caller = self.request()
        with self.assertRaisesRegex(RuntimeError, "controlled product boundary"):
            coordinator.governed_mutation(wire, source)
        op = decode(wire)["intent"]["operation_id"]
        return coordinator, coordinator.journal.load(op), caller

    def changed_qualification_rejects(self, *, terminal, kind):
        coordinator, row, caller = self.paused_core("dispatch_saved" if terminal else "proposal_saved")
        self.provider._sync_authority()
        before_registry = self.provider.a
        registry = deepcopy(before_registry)
        from app.control_plane.r1_validation_codec import record
        from app.control_plane import _r1_validation_semantics as sem
        if kind == "LEASE_REVOKE":
            lease = next(v for v in registry["records"].values() if "lease_id" in v and "history_version" in v and "lease_generation" in v and "expires_at" in v)
            payload = record("revocation", history_version=2, object_digest=sem.rawhash(lease))
        else:
            payload = next(deepcopy(registry["records"][e["input_digest"]]) for e in registry["events"] if e["event_kind"] == "FENCES_SET")
            payload["fences"]["continuity_epoch"] += 1
        event(registry, kind, now_ms(), payload)
        self.provider._register(row["request_wire"], row["source_wire"], before_registry, registry)
        before = self.snapshot()
        signs = len(self.sign_calls)
        with self.assertRaises(ContractError) as caught:
            self.authority.decide(row["operation_id"], row["request_wire"], row["authorization_wire"], row["proposal_wire"],
                row["publication_wire"] if terminal else None, coordinator._local_history(), caller)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(signs, len(self.sign_calls))
        query = self.authority.query(row["operation_id"], row["request_wire"], caller)
        self.assertEqual(query.state, "FIX_ACCEPTED" if terminal else "PREPARED")
        self.assertIsNone(query.terminal_wire)
        self.observations.append({"case": kind, "phase": "TERMINAL" if terminal else "FIX", "operation_id": row["operation_id"],
                                  "new_action": "REJECT", "reason": str(caught.exception), "historical_query": query.state,
                                  "exact_journal_unchanged": True})

    def test_lease_revoked_after_prepare_rejects_original_fix_but_query_survives(self):
        self.changed_qualification_rejects(terminal=False, kind="LEASE_REVOKE")

    def test_epoch_changed_after_fix_rejects_original_terminal_but_query_survives(self):
        self.changed_qualification_rejects(terminal=True, kind="FENCES_SET")

    def test_independent_process_same_id_replay_and_changed_content_compete(self):
        wire, source, caller = self.request()
        request = decode(wire)
        bad = build_mutation_request(identity=request["intent"]["identity"], scope=request["intent"]["scope"],
            payload=request["intent"]["payload"], mutation_id=request["intent"]["mutation_id"], decision="COMMIT",
            created_at=request["intent"]["created_at"], reason="different content under original ID",
            operation_id=request["intent"]["operation_id"], local_commit_id=request["intent"]["local_commit_id"],
            source_authorization_id=request["source_decision"]["authorization_id"])
        root = self.path.parent
        token = "author-race-" + uuid4().hex
        cfg_path = root / (token + "-private.json")
        cfg_path.write_text(json.dumps({**self.config, "dbname": self.database, "scope_id": self.scope_id}))
        gate = root / (token + "-go")
        processes, results = [], []
        try:
            for index, raw in enumerate((wire, wire, bad)):
                inp = root / (token + "-" + str(index) + ".json")
                ready = root / (token + "-" + str(index) + ".ready")
                inp.write_text(json.dumps({"request": raw.hex(), "source": source.hex(), "caller": asdict(caller)}))
                process = subprocess.Popen([sys.executable, "-B", "-m", "tests.r1_scoped_authority_worker", str(cfg_path), str(inp), str(ready), str(gate)],
                    cwd=Path(__file__).resolve().parents[1], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
                processes.append((process, ready))
            deadline = time.monotonic() + 20
            while not all(ready.exists() for _, ready in processes):
                self.assertTrue(all(p.poll() is None for p, _ in processes), "owned worker exited before gate")
                self.assertLess(time.monotonic(), deadline)
                time.sleep(.01)
            gate.write_text("go")
            for process, _ in processes:
                output, _ = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, output.decode(errors="replace"))
                results.append(json.loads(output))
        finally:
            for process, _ in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=10)
        self.assertEqual([r["status"] for r in results], ["PREPARED", "PREPARED", "REJECT"])
        self.assertEqual(results[0]["ack_sha256"], results[1]["ack_sha256"])
        self.assertEqual(sum(r["sign_calls"] for r in results), 1)
        self.assertIn("content conflict", results[2]["reason"])
        self.assertEqual(len({r["pid"] for r in results}), 3)
        count = self.store.transact(lambda tx: sum(decode(e)["event_kind"] == "PREPARE" for w in tx.windows for e in w.authority.event_wires))
        self.assertEqual(count, 1)
        self.observations.append({"case": "independent_process_prepare", "processes": results, "durable_prepare_events": count})

    def retryable_database_error(self, code):
        wire, source, caller = self.request()
        live, attempts = [], []
        def connect():
            connection = self.connect()
            live.append(connection)
            return connection
        store = ScopedPostgresStore(connect, scope_id=self.scope_id, configuration_digest=self.digest)
        def hook(stage):
            if stage == "before_database_commit":
                attempts.append(live[-1].info.backend_pid)
                if len(attempts) == 1:
                    # Actual PostgreSQL transaction abort after product signing
                    # and append. This injects the SQLSTATE, not a real deadlock
                    # cycle or a claim of naturally arising serialization error.
                    live[-1].execute(sql.SQL("DO $$ BEGIN RAISE EXCEPTION USING ERRCODE={}, MESSAGE='controlled transaction retry'; END $$").format(sql.Literal(code)))
        authority = ScopedAuthority(store=store, trust=self.public_trust, deployments=(self.deployment,),
                                    boundary=self.initial, receipt_signer=self.signer, fault=hook)
        reply = authority.prepare(wire, source, caller)
        self.assertEqual(reply.state, "PREPARED")
        self.assertEqual(len(attempts), 2)
        self.assertEqual(len(set(attempts)), 2)
        self.assertEqual(len(self.sign_calls), 2)
        actual = self.store.transact(lambda tx: (tx.operation(decode(wire)["intent"]["operation_id"]).request_wire,
            sum(decode(e)["event_kind"] == "PREPARE" for w in tx.windows for e in w.authority.event_wires)))
        self.assertEqual(actual, (wire, 1))
        self.observations.append({"case": "injected_pg_sqlstate", "sqlstate": code, "backend_pids": attempts,
            "full_product_signing_attempts": len(self.sign_calls), "durable_prepare_events": 1, "original_request_unchanged": True})

    def test_sqlstate_40001_reexecutes_full_transaction_from_original_request(self):
        self.retryable_database_error("40001")

    def test_sqlstate_40p01_reexecutes_full_transaction_from_original_request(self):
        self.retryable_database_error("40P01")

    def test_prepare_real_signature_exact_replay_and_query(self):
        wire, source, caller = self.request()
        op = decode(wire)["intent"]["operation_id"]
        absent = self.authority.query(op, None, caller, request_digest=h2(decode(wire)))
        self.assertEqual(absent.state, "ABSENT")
        first = self.authority.prepare(wire, source, caller)
        verify_signed(first.ack_wire, self.public_trust)
        self.assertEqual(first.state, "PREPARED")
        original = self.snapshot()
        repeated = self.authority.prepare(wire, source, caller, authority_after=len(first.authority.event_wires))
        self.assertEqual(first.ack_wire, repeated.ack_wire)
        self.assertEqual(repeated.authority.event_wires, ())
        self.assertEqual(original, self.snapshot())
        self.assertEqual(len(self.sign_calls), 1)
        fresh = ScopedAuthority(store=self.store, trust=self.public_trust, deployments=(self.deployment,),
                                boundary=self.initial, receipt_signer=self.signer)
        self.assertEqual(fresh.query(op, wire, caller).ack_wire, first.ack_wire)

    def test_signer_failure_leaves_no_prepare_then_retry_succeeds(self):
        wire, source, caller = self.request("ABORT")
        before = self.snapshot()
        def fail(_message):
            raise RuntimeError("controlled test signer failure")
        original = self.signer.sign
        self.signer.sign = fail
        with self.assertRaisesRegex(RuntimeError, "signer failure"):
            self.authority.prepare(wire, source, caller)
        self.assertEqual(before, self.snapshot())
        self.signer.sign = original
        reply = self.authority.prepare(wire, source, caller)
        self.assertEqual(reply.state, "PREPARED")
        verify_signed(reply.ack_wire, self.public_trust)

    def test_authenticated_actor_scope_and_content_rejected_without_acceptance(self):
        wire, source, caller = self.request()
        before = self.snapshot()
        for bad in (replace(caller, runtime_principal="wrong-principal"), replace(caller, session_id=str(uuid4())),
                    replace(caller, inventory_digest="f"*64)):
            with self.assertRaises(ContractError):
                self.authority.prepare(wire, source, bad)
            self.assertEqual(before, self.snapshot())
        self.assertEqual(self.sign_calls, [])
        value = decode(wire)
        value["intent"]["reason"] = "mutated original bytes"
        with self.assertRaises(ContractError):
            self.authority.prepare(c2(value), source, caller)
        self.assertEqual(before, self.snapshot())

    def test_runtime_role_has_no_base_table_read_write_or_owner_membership(self):
        with self.connect() as db:
            row = db.execute("SELECT current_user,rolsuper,rolinherit,rolbypassrls,pg_has_role(current_user,'control_plane_owner','MEMBER') FROM pg_roles WHERE rolname=current_user").fetchone()
            self.assertEqual(row, ("control_plane_app", False, False, False, False))
        for query in ("SELECT * FROM control_plane.r1s_scopes", "DELETE FROM control_plane.r1s_journal", "SET ROLE control_plane_owner"):
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with self.connect() as db:
                    db.execute(query)

    def test_deferred_database_deadline_failure_does_not_publish_signed_ack(self):
        wire, source, caller = self.request()
        request = decode(wire)
        self.provider._sync_authority()
        before_registry = self.provider.a
        registry = deepcopy(before_registry)
        old = next(v for v in registry["records"].values() if v.get("type") == "execution_grant")
        body = {k: v for k, v in old.items() if k not in {"type", "version", "contract_revision", "issuance_digest", "receipt_signature"}}
        body.update(grant_id=str(uuid4()), grant_sequence=2, issued_at=now_ms(), expires_at=now_ms()+700)
        from app.control_plane import _r1_validation_semantics as sem
        self.provider._issue(registry, "execution_grant", body, sem.expected_fences(request))
        self.provider._register(wire, source, before_registry, registry)
        before = self.snapshot()
        def hook(stage):
            if stage == "before_database_commit":
                time.sleep(0.8)
        authority = ScopedAuthority(store=self.store, trust=self.public_trust, deployments=(self.deployment,),
                                    boundary=self.initial, receipt_signer=self.signer, fault=hook)
        with self.assertRaises(StoreError) as caught:
            authority.prepare(wire, source, caller)
        self.assertEqual(caught.exception.code, "COMMIT_EXPIRED")
        self.assertEqual(before, self.snapshot())
        self.assertEqual(len(self.sign_calls), 1)
        reply = self.authority.query(request["intent"]["operation_id"], wire, caller)
        self.assertEqual(reply.state, "ABSENT")


if __name__ == "__main__":
    unittest.main()
