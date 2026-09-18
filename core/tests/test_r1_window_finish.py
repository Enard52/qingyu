"""Bounded validation and real same-file continuous completion beyond 128 ops."""
from dataclasses import replace
import json
import multiprocessing
from pathlib import Path
import tempfile
import time
import unittest

from app.control_plane.r1_validation import FixedTrust
from app.control_plane.r1_validation_codec import ContractError, c2, decode
from tests.r1_window_fixtures import (generate_sequence, window_evidence, boundary_for, input_for,
    open_window_service, WindowSource)
from tests.r1_window_worker import run_window_worker


TEST_ROOT = Path("<repo>/core-r1-implementation/.tmp/r1-slice-02-completion-20260916T193823Z")
OBSERVATIONS = []


class WindowFinishTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        started_at = time.monotonic()
        print("window-finish fixture start generate_sequence=129", flush=True)
        cls.sequence = generate_sequence(129)
        print(f"window-finish fixture complete elapsed={time.monotonic()-started_at:.3f}", flush=True)

    def setUp(self):
        from tests.r1_window_observation import observe_calls
        self.actual_validation_calls, self.restore_observer = observe_calls()
        if TEST_ROOT.parent.resolve() != Path("<repo>/core-r1-implementation/.tmp").resolve():
            raise AssertionError("owned temporary root differs")
        TEST_ROOT.mkdir(parents=True, exist_ok=True)
        self.directory = Path(tempfile.mkdtemp(prefix=self._testMethodName+"-", dir=TEST_ROOT))
        self.path = self.directory / "one-continuous-database.sqlite3"

    def tearDown(self):
        self.restore_observer()
        OBSERVATIONS.append({"kind": "main_process_actual_validation_calls", "test": self._testMethodName,
                             "calls": self.actual_validation_calls})

    def engine(self, operations):
        from app.control_plane._r1_validation_stream import BoundedHistory
        s = self.sequence
        return BoundedHistory(FixedTrust(s.pin_wire, s.root_public_key), (s.deployment,), boundary_for(s, operations))

    def test_original_limit_64_accepts_and_65_rejects_without_truncation(self):
        operations = self.sequence.operations
        engine = self.engine(operations[:64])
        stats = engine.append(window_evidence(self.sequence, operations[:64], completed=True), operation="COMPLETION_HISTORY")
        self.assertEqual(len(engine.requests), 64)
        OBSERVATIONS.append({"kind": "legal_single_window_64", "stats": stats})
        oversized = self.engine(operations[:65])
        with self.assertRaises(ContractError):
            oversized.append(window_evidence(self.sequence, operations[:65], completed=True), operation="COMPLETION_HISTORY")
        stats = engine.append(window_evidence(self.sequence, operations[64:65], completed=True), operation="COMPLETION_HISTORY")
        self.assertEqual(len(engine.requests), 65)
        OBSERVATIONS.append({"kind": "direct_engine_continuation_65", "stats": stats})

    def test_cross_window_conflicts_and_self_consistent_wrong_predecessors(self):
        sequence = self.sequence
        engine = self.engine(sequence.operations[:64])
        engine.append(window_evidence(sequence, sequence.operations[:64], completed=True), operation="COMPLETION_HISTORY")
        for ordinal, label, alternate in sequence.alternatives:
            if ordinal != 65 or label == "competing_successor":
                continue
            with self.subTest(label=label), self.assertRaises(ContractError):
                engine.fork().append(window_evidence(sequence, (alternate,), completed=True), operation="COMPLETION_HISTORY")
        exact = engine.fork().append(window_evidence(sequence, (sequence.operations[0],), completed=True), operation="COMPLETION_HISTORY")
        OBSERVATIONS.append({"kind": "exact_overlap_old_first_operation", "stats": exact})
        good = window_evidence(sequence, sequence.operations[64:65], completed=True)
        missing = replace(good, authority=replace(good.authority, event_wires=good.authority.event_wires[1:]))
        with self.assertRaises(ContractError):
            engine.fork().append(missing, operation="COMPLETION_HISTORY")
        with self.assertRaises(ContractError):
            engine.fork().append(replace(good, request_wires=()), operation="COMPLETION_HISTORY")
        # A later segment cannot promote its claimed starting checkpoint into
        # a genesis qualification prefix: the original event positions remain.
        with self.assertRaises(ContractError):
            self.engine(sequence.operations[64:65]).append(good, operation="COMPLETION_HISTORY")

    def test_authorized_restore_history_finishes_across_two_actual_windows(self):
        from tests.r1_validation_completion_independent_fixtures import IndependentHistory, establish_genesis, restore_case
        from tests.r1_atomic_finish_fixtures import PublicCase, SyntheticSource, open_finisher, finish_input
        from app.control_plane.r1_validation import CoreHistory
        world = IndependentHistory(seed=931000)
        establish_genesis(world)
        world.add_operation("COMMIT")
        world.add_operation("ABORT")
        restored = restore_case(world)
        target = restored["deployments"][-1]
        cases = []
        for index, original in enumerate(world.operations):
            rec = restored["restored"][index]
            # Retain the exact previous APPLY, and omit the current/future APPLY.
            local = {**restored["local"], "events": restored["local"]["events"][:index*6+5]}
            evidence = replace(restored["evidence"], core_histories=(*restored["evidence"].core_histories[:-1],
                CoreHistory(target.runtime_principal, c2(local))))
            selected = original["request"][original["receipt"]["decision"].lower()]
            cases.append(PublicCase(original["request"]["intent"]["operation_id"], c2(original["request"]), evidence,
                restored["trust"], restored["deployments"], target, restored["chain_boundary"], restored["restore_evidence"],
                c2(local), evidence.authority_history, rec["permit"]["session_id"], rec["completion"]["completed_at"],
                c2(rec["permit"]), c2(original["receipt"]), c2(rec["target"]), c2(original["before"]), c2(original["after"]),
                c2(selected["effect"]), c2(selected["result"]), c2(original["audit"]), c2(rec["completion"])))
        service = open_finisher(self.path, cases[0], create=True)
        first = service.finish(finish_input(cases[0]))
        self.assertTrue(first.applied)
        service.source = SyntheticSource(cases[1])
        second = service.finish(finish_input(cases[1]))
        self.assertTrue(second.applied)
        self.assertEqual(service.store.inspect()["checkpoint_wire"], cases[1].after_wire)
        service.source = SyntheticSource(cases[0], now=cases[1].now+11000)
        queried = service.query(cases[0].operation_id, cases[0].request_wire)
        self.assertFalse(queried.applied)
        self.assertEqual(queried.result_wire, first.result_wire)
        with service.store.transaction(write=False) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM completions").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT count(*) FROM business_records").fetchone()[0], 1)
            windows = db.execute("SELECT count(*) FROM history_windows").fetchone()[0]
        OBSERVATIONS.append({"kind": "authorized_restore_two_operations", "actual_stored_windows": windows,
            "fixture_provenance": "prior independent generator reused by author; this run is author verification"})

    def spawn(self, operation, action, **kwargs):
        context = multiprocessing.get_context("spawn")
        receive, send = context.Pipe(duplex=False)
        public = replace(self.sequence, operations=(self.sequence.operations[0],), alternatives=())
        process = context.Process(target=run_window_worker,
            args=(str(self.path), public, operation, action, send), kwargs=kwargs)
        process.start(); send.close()
        return process, receive

    def collect(self, process, receive, expected_exit=0):
        self.assertTrue(receive.poll(600), "owned window worker did not report result")
        message = receive.recv()
        process.join(30)
        self.assertFalse(process.is_alive())
        self.assertEqual(process.exitcode, expected_exit, message)
        receive.close()
        OBSERVATIONS.append({"kind": "window_worker", "actual_exitcode": process.exitcode,
            **{key: value for key, value in message.items() if key != "result"}})
        return message

    def assert_operation(self, service, op, result, completed):
        self.assertEqual(result.operation_id, op.operation_id)
        self.assertEqual(result.result_wire, op.result_wire)
        self.assertEqual(result.audit_wire, op.audit_wire)
        self.assertEqual(result.terminal_wire, op.terminal_wire)
        self.assertEqual(result.checkpoint_wire, op.after_wire)
        with service.store.transaction(write=False) as db:
            row = db.execute("SELECT * FROM completions WHERE operation_id=?", (op.operation_id,)).fetchone()
            self.assertIsNotNone(row)
            for key in ("result_wire", "audit_wire", "terminal_wire", "effect_wire"):
                self.assertEqual(row[key], getattr(op, key))
            self.assertEqual(db.execute("SELECT count(*) FROM completions").fetchone()[0], completed)
            self.assertEqual(db.execute("SELECT count(*) FROM permit_consumptions").fetchone()[0], completed)
            self.assertEqual(db.execute("SELECT checkpoint_wire FROM metadata WHERE id=1").fetchone()[0], op.after_wire)
        OBSERVATIONS.append({"kind": "completed_operation", "ordinal": completed, "operation_id": op.operation_id,
            "decision": decode(op.terminal_wire)["decision"], "before": decode(op.before_wire), "after": decode(op.after_wire),
            "database": str(self.path)})
        print("actual completed operation", completed, flush=True)

    def test_same_database_129_operations_with_boundary_processes_and_queries(self):
        started_at = time.monotonic()
        print("window-finish start operations=129", flush=True)
        s = self.sequence
        service = open_window_service(self.path, s, s.operations[0], create=True)
        completed_ops = []
        for op in s.operations:
            if op.ordinal == 1 or op.ordinal % 16 == 0 or op.ordinal in (65, 66, 67, 127, 128, 129):
                print(f"window-finish progress ordinal={op.ordinal} elapsed={time.monotonic()-started_at:.3f}", flush=True)
            service.source = WindowSource(s, op)
            if op.ordinal in (65, 67, 127, 128):
                stage = {65: "evidence_saved", 67: "after_effect", 127: "before_history_commit", 128: "after_commit"}[op.ordinal]
                failed = self.collect(*self.spawn(op, "finish", crash_at=stage), expected_exit=83)
                self.assertEqual(failed["crash_boundary"], stage)
                with service.store.transaction(write=False) as db:
                    expected = op.ordinal if stage == "after_commit" else op.ordinal-1
                    self.assertEqual(db.execute("SELECT count(*) FROM completions").fetchone()[0], expected)
                    self.assertEqual(db.execute("SELECT count(*) FROM permit_consumptions").fetchone()[0], expected)
                recovered = self.collect(*self.spawn(op, "recover"))
                self.assertTrue(recovered["ok"], recovered)
                result = recovered["result"]
                self.assertEqual(result.applied, stage != "after_commit")
            elif op.ordinal == 66:
                context = multiprocessing.get_context("spawn")
                release, ready1, ready2 = context.Event(), context.Event(), context.Event()
                workers = [self.spawn(op, "finish", barrier_at="validated", ready=ready, release=release)
                           for ready in (ready1, ready2)]
                self.assertTrue(ready1.wait(120)); self.assertTrue(ready2.wait(120)); release.set()
                messages = [self.collect(*worker) for worker in workers]
                self.assertTrue(all(m["ok"] for m in messages), messages)
                self.assertEqual(sum(m["result"].applied for m in messages), 1)
                result = messages[0]["result"]
            elif op.ordinal == 129:
                alternate = next(a for n, name, a in s.alternatives if n == 129 and name == "competing_successor")
                context = multiprocessing.get_context("spawn")
                release, ready1, ready2 = context.Event(), context.Event(), context.Event()
                workers = [self.spawn(candidate, "finish", barrier_at="validated", ready=ready, release=release)
                           for candidate, ready in ((op, ready1), (alternate, ready2))]
                self.assertTrue(ready1.wait(120)); self.assertTrue(ready2.wait(120)); release.set()
                messages = [self.collect(*worker) for worker in workers]
                winners = [index for index, message in enumerate(messages) if message["ok"]]
                self.assertEqual(len(winners), 1, messages)
                winner = winners[0]
                self.assertEqual(messages[1-winner]["error_type"], "ContractError")
                loser = (op, alternate)[1-winner]
                op = (op, alternate)[winner]
                service.source = WindowSource(s, op)
                result = messages[winner]["result"]
                before_retry = service.store.inspect()
                retried = self.collect(*self.spawn(loser, "finish"))
                self.assertFalse(retried["ok"], retried)
                self.assertEqual(retried["error_type"], "ContractError")
                self.assertEqual(service.store.inspect(), before_retry)
                OBSERVATIONS.append({"kind": "same_loser_original_input_retried", "original_pid": messages[1-winner]["pid"],
                    "retry_pid": retried["pid"], "operation_id": loser.operation_id, "outcome": "REJECT_UNCHANGED_STORE"})
            else:
                result = service.finish(input_for(s, op))
                self.assertTrue(result.applied)
            completed_ops.append(op)
            self.assert_operation(service, op, result, len(completed_ops))

        # Read first and both boundary pairs with current QUERY scope. Old
        # permit expiry is deliberately later than its original valid APPLY.
        current_time = completed_ops[-1].now + 20000
        for index in (0, 63, 64, 127, 128):
            op = completed_ops[index]
            service.source = WindowSource(s, op, now=current_time)
            historical = service
            result = historical.query(op.operation_id, op.request_wire)
            self.assertFalse(result.applied)
            self.assertEqual(result.result_wire, op.result_wire)
            replay = historical.finish(input_for(s, op))
            self.assertFalse(replay.applied)
            self.assertEqual(replay.completion_wire, result.completion_wire)
            bad = decode(op.request_wire); bad["intent"]["reason"] = "conflicting old operation content"
            with self.assertRaises(ContractError):
                historical.query(op.operation_id, c2(bad))

        self.collect(*self.spawn(completed_ops[0], "query", crash_at="history_rebuilt", now=current_time), expected_exit=83)
        final_query = self.collect(*self.spawn(completed_ops[0], "query", now=current_time))
        self.assertTrue(final_query["ok"], final_query)
        self.assertFalse(final_query["result"].applied)
        with service.store.transaction(write=False) as db:
            all_windows = [dict(row) for row in db.execute("SELECT * FROM history_windows ORDER BY sequence")]
            self.assertEqual(db.execute("SELECT count(*) FROM operations").fetchone()[0], 129)
            self.assertEqual(db.execute("SELECT count(*) FROM completions").fetchone()[0], 129)
            self.assertEqual(db.execute("SELECT count(*) FROM permit_consumptions").fetchone()[0], 129)
            expected_business = sum(decode(op.terminal_wire)["decision"] == "COMMIT" for op in completed_ops)
            self.assertEqual(db.execute("SELECT count(*) FROM business_records").fetchone()[0], expected_business)
        elapsed = round(time.monotonic() - started_at, 3)
        print(f"window-finish complete operations=129 elapsed={elapsed}", flush=True)
        OBSERVATIONS.append({"kind": "actual_persisted_validation_windows", "database": str(self.path),
            "business_operations": 129, "elapsed_seconds": elapsed, "windows": [{"sequence": row["sequence"], "verification": json.loads(row["verification_wire"])} for row in all_windows]})


if __name__ == "__main__":
    unittest.main()
