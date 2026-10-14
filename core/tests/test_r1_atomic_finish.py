"""Actual file SQLite, independent connections, and spawned-process verification.

All files are exclusively created below this slice's authorized test directory.
Crash boundaries use os._exit in our own spawned workers; no journal is removed,
no completion row is patched, and recovery always uses the product entry point.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import replace
import hashlib
import multiprocessing
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest

from app._r1_scoped_sqlite import ScopedSQLiteStore, ScopedStoreError
from app.control_plane.r1_validation import CoreHistory
from app.control_plane.r1_validation_codec import c2, decode, h2, ContractError
from tests.r1_validation_fixtures import build_world, event, raw, registry
from tests.r1_atomic_finish_fixtures import (
    SyntheticSource, finish_input, open_finisher, public_case, public_chain, scope_wire,
)
from tests.r1_atomic_finish_worker import run_worker


TEST_ROOT = Path("<repo>/core-r1-implementation/.tmp/r1-slice-02-completion-20260916T193823Z")
OBSERVATIONS = []


class AtomicFinishTests(unittest.TestCase):
    def setUp(self):
        expected = Path("<repo>/core-r1-implementation/.tmp").resolve()
        if TEST_ROOT.parent.resolve() != expected or not TEST_ROOT.name.startswith("r1-slice-02-"):
            raise AssertionError("test database ownership root differs")
        TEST_ROOT.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix=self._testMethodName + "-", dir=TEST_ROOT))
        self.path = self.directory / "local.sqlite3"

    def service(self, case, **kwargs):
        return open_finisher(self.path, case, create=not self.path.exists(), **kwargs)

    def observe(self, label, value):
        OBSERVATIONS.append({"test": self._testMethodName, "label": label, "value": value})

    def rows(self, service, table):
        if table not in {"operations", "completions", "permit_consumptions", "business_records"}:
            raise AssertionError("unknown test table")
        with service.store.transaction(write=False) as connection:
            return [dict(row) for row in connection.execute("SELECT * FROM " + table)]

    def assert_pending(self, service, case):
        state = service.store.inspect()
        self.assertEqual(state["checkpoint_wire"], case.before_wire)
        self.assertEqual(state["business_state_wire"], c2({}))
        self.assertEqual(len(self.rows(service, "operations")), 1)
        self.assertEqual(self.rows(service, "operations")[0]["status"], "PENDING")
        self.assertEqual(self.rows(service, "operations")[0]["request_wire"], case.request_wire)
        self.assertTrue(self.rows(service, "operations")[0]["original_wire"])
        self.assertTrue(self.rows(service, "operations")[0]["evidence_wire"])
        for table in ("completions", "permit_consumptions", "business_records"):
            self.assertEqual(self.rows(service, table), [])

    def assert_finished(self, service, case, result, *, commit=True):
        self.assertEqual(result.result_wire, case.result_wire)
        self.assertEqual(result.audit_wire, case.audit_wire)
        self.assertEqual(result.terminal_wire, case.terminal_wire)
        self.assertEqual(result.checkpoint_wire, case.after_wire)
        state = service.store.inspect()
        self.assertEqual(state["checkpoint_wire"], case.after_wire)
        for table in ("completions", "permit_consumptions"):
            self.assertEqual(len(self.rows(service, table)), 1)
        self.assertEqual(self.rows(service, "operations")[0]["status"], "FINALIZED")
        row = self.rows(service, "completions")[0]
        for key in ("result_wire", "audit_wire", "terminal_wire", "effect_wire", "checkpoint_wire"):
            self.assertEqual(row[key], getattr(case, "after_wire" if key == "checkpoint_wire" else key))
        self.assertEqual(row["completion_wire"], result.completion_wire)
        self.assertEqual(decode(row["completion_wire"])["permit_digest"], h2(decode(case.permit_wire)))
        self.assertEqual(len(self.rows(service, "business_records")), int(commit))
        expected = decode(case.effect_wire)["entries"][0]["value"] if commit else {}
        self.assertEqual(state["business_state_wire"], c2(expected))

    def spawn(self, case, action, **kwargs):
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=False)
        transport = replace(case, trust=(case.trust.pin_wire, case.trust.root_public_key))
        process = context.Process(target=run_worker, args=(str(self.path), transport, action, send), kwargs=kwargs)
        process.start()
        send.close()
        return process, receive

    def collect(self, process, receive, *, exitcode=0):
        self.assertTrue(receive.poll(90), "owned test child failed to produce boundary/result")
        message = receive.recv()
        process.join(30)
        self.assertFalse(process.is_alive(), "owned test child did not exit")
        self.assertEqual(process.exitcode, exitcode, message)
        receive.close()
        self.observe("worker", {**{key: value for key, value in message.items() if key != "result"},
                                "actual_exitcode": process.exitcode, "expected_exitcode": exitcode})
        return message

    def test_commit_exact_bytes_transaction_settings_and_replay(self):
        case = public_case()
        service = self.service(case)
        result = service.finish(finish_input(case))
        self.assertTrue(result.applied)
        self.assert_finished(service, case, result)
        replay = self.service(case).finish(finish_input(case))
        self.assertFalse(replay.applied)
        self.assertEqual(replay.completion_wire, result.completion_wire)
        self.assert_finished(service, case, replay)
        state = service.store.inspect()
        self.assertEqual(state["settings"]["journal_mode"], "wal")
        self.assertEqual(state["settings"]["synchronous"], 2)
        self.assertEqual(state["settings"]["foreign_keys"], 1)
        self.observe("sqlite", {key: state[key] for key in ("sqlite_version", "settings", "write_transaction")})

    def test_abort_preserves_business_state_but_advances_both_heads(self):
        case = public_case(decision="ABORT")
        service = self.service(case)
        result = service.finish(finish_input(case))
        self.assert_finished(service, case, result, commit=False)
        before, after = decode(case.before_wire), decode(case.after_wire)
        self.assertEqual(before["state_version"], after["state_version"])
        self.assertEqual(before["authority_ref"]["authority_sequence"] + 1, after["authority_ref"]["authority_sequence"])
        self.assertEqual(before["audit_ref"]["audit_sequence"] + 1, after["audit_ref"]["audit_sequence"])

    def test_operator_override_applies_only_authorized_abort(self):
        case = public_case(override=True)
        self.assertEqual(decode(case.request_wire)["intent"]["requested_decision"], "COMMIT")
        self.assertEqual(decode(case.terminal_wire)["decision"], "ABORT")
        service = self.service(case)
        self.assert_finished(service, case, service.finish(finish_input(case)), commit=False)

    def test_restore_existing_terminal_applies_with_complete_source_proof(self):
        case = public_case(restore=True)
        service = self.service(case)
        with self.assertRaises(ContractError):
            service.finish(replace(finish_input(case), restore_evidence=()))
        self.assertEqual(self.rows(service, "completions"), [])
        original = service.finish(finish_input(case))
        self.assert_finished(service, case, original)
        queried = self.service(case).query(case.operation_id, case.request_wire)
        self.assertEqual(queried.completion_wire, original.completion_wire)
        self.assertFalse(queried.applied)
        policy_digest = decode(case.permit_wire)["policy_digest"]
        policy = decode(case.authority_history)["records"][policy_digest]
        self.assertNotIn("TERMINATE_ORIGINAL", policy["capabilities"])
        self.assertNotIn("FIX_ORIGINAL_DISPATCH", policy["capabilities"])

    def test_same_id_changed_original_request_never_replays_success(self):
        case = public_case()
        service = self.service(case)
        original = service.finish(finish_input(case))
        request = decode(case.request_wire)
        request["intent"]["reason"] = "conflicting same operation identity"
        bad = replace(finish_input(case), evidence=replace(case.evidence, request_wires=(c2(request),)))
        with self.assertRaises(ContractError):
            service.finish(bad)
        with self.assertRaises(ContractError):
            service.query(case.operation_id, c2(request))
        self.assert_finished(service, case, original)

    def test_wrong_signature_candidate_result_and_permit_are_rejected(self):
        case = public_case()
        service = self.service(case)
        authority = decode(case.evidence.authority_history)
        receipt = next(value for value in authority["records"].values() if value.get("type") == "terminal_receipt")
        receipt["receipt_signature"] = "00" * 64
        inputs = [replace(finish_input(case), evidence=replace(case.evidence, authority_history=c2(authority))),
                  replace(finish_input(case), permit_digest="f" * 64)]
        for branch, field, value in [("commit", "effect", {"entries": []}), ("commit", "result", {"value": None})]:
            request = decode(case.request_wire)
            request[branch][field].update(value)
            inputs.append(replace(finish_input(case), evidence=replace(case.evidence, request_wires=(c2(request),))))
        for index, bad in enumerate(inputs):
            with self.subTest(index=index), self.assertRaises(ContractError):
                service.finish(bad)
        self.assertEqual(service.store.inspect()["checkpoint_wire"], case.before_wire)
        self.assertEqual(self.rows(service, "completions"), [])

    def test_wrong_target_session_and_missing_external_source_refuse_new_write(self):
        from app.r1_atomic_finish import ScopedCoreFinisher
        case = public_case()
        service = self.service(case)
        for source in (None, SyntheticSource(case, session_id="00000000-0000-0000-0000-000000009999"),
                       SyntheticSource(case, runtime_principal="different-authenticated-component")):
            other = ScopedCoreFinisher(service.store, trust=case.trust, deployments=case.deployments,
                runtime_principal=case.deployment.runtime_principal, source=source)
            with self.subTest(source=type(source).__name__), self.assertRaises(ContractError):
                other.finish(finish_input(case))
        wrong = decode(scope_wire(case)); wrong["storage_generation_id"] = "00000000-0000-0000-0000-000000009998"
        with self.assertRaises(ScopedStoreError):
            ScopedSQLiteStore.open(self.path, expected_scope_wire=c2(wrong))
        self.assertEqual(self.rows(service, "completions"), [])

    def test_expired_permit_refuses_first_apply_but_allows_completed_query(self):
        case = public_case()
        source = SyntheticSource(case, now=20000)
        service = self.service(case, source=source)
        with self.assertRaises(ContractError):
            service.finish(finish_input(case))
        self.assertEqual(self.rows(service, "completions"), [])
        source.clock = case.now
        original = service.finish(finish_input(case))
        source.clock = 20000
        queried = service.query(case.operation_id, case.request_wire)
        self.assertFalse(queried.applied)
        self.assertEqual(queried.completion_wire, original.completion_wire)
        self.assert_finished(service, case, queried)

    def test_local_revocation_and_final_clock_change_block_first_consumption(self):
        case = public_case()
        source = SyntheticSource(case)
        core = decode(case.core_history)
        session = next(value for value in decode(case.authority_history)["records"].values()
                       if value.get("session_id") == case.session_id and "enrollment" in value)
        event(core, "LOCAL_SESSION_REVOKE", 1490, {"history_version": 2, "object_digest": raw(session)})
        source.core_history = c2(core)
        service = self.service(case, source=source)
        with self.assertRaises(ContractError):
            service.finish(finish_input(case))
        source.core_history = case.core_history
        self.path = self.directory / "fresh-final-clock.sqlite3"
        def expire_at_commit(label):
            if label == "before_commit":
                source.clock = 20000
        service = self.service(case, source=source, hook=expire_at_commit)
        with self.assertRaises(ContractError):
            service.finish(finish_input(case))
        self.assertEqual(self.rows(service, "completions"), [])
        self.assertEqual(self.rows(service, "business_records"), [])

    def test_two_connections_same_operation_apply_once(self):
        case = public_case()
        self.service(case)
        barrier = threading.Barrier(2)
        def contender():
            seen = False
            def hook(label):
                nonlocal seen
                if label == "validated" and not seen:
                    seen = True
                    barrier.wait(20)
            return self.service(case, hook=hook).finish(finish_input(case))
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: contender(), range(2)))
        self.assertEqual(sum(result.applied for result in results), 1)
        self.assertEqual(results[0].completion_wire, results[1].completion_wire)
        self.assert_finished(self.service(case), case, results[0])

    def test_two_independent_processes_same_operation_apply_once(self):
        case = public_case()
        self.service(case)
        context = multiprocessing.get_context("spawn")
        release, ready1, ready2 = context.Event(), context.Event(), context.Event()
        first = self.spawn(case, "finish", barrier_at="validated", ready=ready1, release=release)
        second = self.spawn(case, "finish", barrier_at="validated", ready=ready2, release=release)
        self.assertTrue(ready1.wait(30)); self.assertTrue(ready2.wait(30)); release.set()
        messages = [self.collect(*first), self.collect(*second)]
        self.assertTrue(all(message["ok"] for message in messages), messages)
        self.assertNotEqual(messages[0]["pid"], messages[1]["pid"])
        results = [message["result"] for message in messages]
        self.assertEqual(sum(result.applied for result in results), 1)
        self.assert_finished(self.service(case), case, results[0])

    def test_chain_wrong_order_then_correct_order_and_old_result_query(self):
        first, second = public_chain()
        service = self.service(first)
        with self.assertRaises(ContractError):
            self.service(second).finish(finish_input(second))
        one = service.finish(finish_input(first))
        two = self.service(second).finish(finish_input(second))
        self.assertTrue(one.applied); self.assertTrue(two.applied)
        self.assertEqual(service.store.inspect()["checkpoint_wire"], second.after_wire)
        self.assertEqual(len(self.rows(service, "completions")), 2)
        queried = self.service(first, source=SyntheticSource(first, now=4000)).query(first.operation_id, first.request_wire)
        self.assertEqual(queried.result_wire, first.result_wire)
        self.assertFalse(queried.applied)

    def test_different_operations_competing_predecessor_and_toctou(self):
        world = build_world()
        first = public_case(world)
        seed = replace(world, authority=registry(world.pin), core=registry(world.pin, world.deployment),
            objects={**world.objects, "after": world.objects["before"]})
        competing = build_world(parent=seed, initial_checkpoint=world.objects["before"], id_offset=100)
        other = public_case(competing)
        from app.control_plane.r1_validation import validate_evidence
        for case in (first, other):
            validate_evidence("TERMINAL_HISTORY", case.evidence, case.trust, case.deployments, chain_boundary=case.boundary)
        service = self.service(first)
        fired = False
        def hook(label):
            nonlocal fired
            if label == "validated" and not fired:
                fired = True
                self.service(other).finish(finish_input(other))
        class StaleSource(SyntheticSource):
            @staticmethod
            def _extend(configured, persisted):
                try:
                    return SyntheticSource._extend(configured, persisted)
                except ValueError:
                    # Return the authentic but stale/forked observed bytes so
                    # the product, rather than this helper, rejects the race.
                    return configured
        with self.assertRaises(ContractError):
            self.service(first, source=StaleSource(first), hook=hook).finish(finish_input(first))
        self.assertTrue(fired)
        result = self.service(other).query(other.operation_id, other.request_wire)
        self.assert_finished(service, other, result)

    def test_ordinary_exception_rolls_back_entire_application(self):
        case = public_case()
        def hook(label):
            if label == "after_effect":
                raise RuntimeError("ordinary Python exception, distinct from process crash")
        service = self.service(case, hook=hook)
        with self.assertRaisesRegex(RuntimeError, "ordinary Python"):
            service.finish(finish_input(case))
        self.assert_pending(service, case)
        result = self.service(case).recover(case.operation_id)
        self.assert_finished(service, case, result)

    def test_crashes_at_saved_evidence_and_each_atomic_write_boundary(self):
        for boundary in ("evidence_saved", "after_effect", "after_audit", "after_head", "after_completion", "before_commit"):
            with self.subTest(boundary=boundary):
                self.path = self.directory / (boundary + ".sqlite3")
                case = public_case()
                service = self.service(case)
                message = self.collect(*self.spawn(case, "finish", crash_at=boundary), exitcode=83)
                self.assertEqual(message["crash_boundary"], boundary)
                self.assert_pending(service, case)
                recovery = self.collect(*self.spawn(case, "recover"))
                self.assertTrue(recovery["ok"], recovery)
                self.assertTrue(recovery["result"].applied)
                self.assert_finished(service, case, recovery["result"])

    def test_commit_succeeded_response_lost_then_new_process_recovers_and_queries(self):
        case = public_case()
        service = self.service(case)
        self.collect(*self.spawn(case, "finish", crash_at="after_commit"), exitcode=83)
        recovery = self.collect(*self.spawn(case, "recover", now=20000))
        self.assertTrue(recovery["ok"], recovery)
        self.assertFalse(recovery["result"].applied)
        self.assert_finished(service, case, recovery["result"])
        queried = self.collect(*self.spawn(case, "query", now=20000))
        self.assertTrue(queried["ok"], queried)
        self.assertEqual(queried["result"].completion_wire, recovery["result"].completion_wire)

    def test_database_busy_is_neither_success_nor_abort_and_retry_rechecks(self):
        case = public_case()
        service = self.service(case)
        contender = self.service(case, busy_timeout_ms=0)
        with service.store.transaction(write=True):
            with self.assertRaises(sqlite3.OperationalError):
                contender.finish(finish_input(case))
        self.assertEqual(self.rows(service, "operations"), [])
        self.assert_finished(service, case, contender.finish(finish_input(case)))

    def test_new_schema_only_duplicate_create_readonly_and_unsupported_db(self):
        case = public_case()
        service = self.service(case)
        with self.assertRaises(FileExistsError):
            open_finisher(self.path, case, create=True)
        with self.assertRaises(sqlite3.OperationalError), service.store.transaction(write=False) as connection:
            connection.execute("UPDATE metadata SET business_state_wire=? WHERE id=1", (b"changed",))
        with self.assertRaises(ScopedStoreError):
            ScopedSQLiteStore.open(":memory:", expected_scope_wire=scope_wire(case))
        unsupported = self.directory / "owned-unsupported.sqlite3"
        connection = sqlite3.connect(unsupported)
        connection.execute("CREATE TABLE old_schema (value TEXT)"); connection.commit(); connection.close()
        before = hashlib.sha256(unsupported.read_bytes()).hexdigest()
        with self.assertRaises(ScopedStoreError):
            ScopedSQLiteStore.open(unsupported, expected_scope_wire=scope_wire(case))
        self.assertEqual(hashlib.sha256(unsupported.read_bytes()).hexdigest(), before)

    def test_independent_owner_epoch_seed_cannot_be_overridden_by_request(self):
        from app.r1_atomic_finish import ScopedCoreFinisher
        case = public_case()
        for field, value in (("owner_identity", "different-local-owner"), ("owner_version", 2), ("continuity_epoch", 2)):
            with self.subTest(field=field):
                changed = decode(scope_wire(case)); changed[field] = value
                store = ScopedSQLiteStore.create(self.directory / (field + ".sqlite3"), scope_wire=c2(changed),
                    checkpoint_wire=case.before_wire, business_state_wire=c2({}))
                service = ScopedCoreFinisher(store, trust=case.trust, deployments=case.deployments,
                    runtime_principal=case.deployment.runtime_principal, source=SyntheticSource(case))
                with self.assertRaises(ContractError):
                    service.finish(finish_input(case))
                self.assertEqual(store.inspect()["checkpoint_wire"], case.before_wire)
                self.assertEqual(self.rows(service, "completions"), [])


if __name__ == "__main__":
    unittest.main()
