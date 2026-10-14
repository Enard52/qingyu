"""Nonauthor bounded-history checks using independently signed original bytes."""
from copy import deepcopy
from dataclasses import replace
import json
import unittest

from tests.r1_window_independent_fixtures import *
from tests.r1_atomic_finish_independent_fixtures import create_service, scope_wire
from app.control_plane.r1_validation_codec import ContractError
from app.control_plane._r1_validation_stream import BoundedHistory, WindowEvidence


OBSERVATIONS = []


class IndependentWindowTests(unittest.TestCase):
    def test_explicit_window_boundary_assertions_first_and_historical(self):
        chain = IndependentWindowChain(seed=940000)
        first = chain.next()
        source = IndependentWindowSource(first)
        service, store, _, _ = create_service(first, source=source)
        boundary = first["input"].chain_boundary
        wrong_start = deepcopy(first["row"]["before"])
        wrong_start["state_version"] += 1
        mutations = (
            {"expected_end_checkpoint_wire": wire(first["row"]["before"])},
            {"start_checkpoint_wire": wire(wrong_start)},
            {"owner_version": boundary.owner_version + 1},
            {"continuity_epoch": boundary.continuity_epoch + 1},
        )
        for values in mutations:
            with self.subTest(phase="initial", values=list(values)):
                bad = replace(first["input"], chain_boundary=replace(boundary, **values))
                with self.assertRaises(ContractError): service.finish(bad)
                self.assertEqual(store.inspect()["counts"]["completions"], 0)
        self.assertTrue(service.finish(first["input"]).applied)
        second = chain.next("ABORT"); source.set_case(second)
        self.assertTrue(service.finish(second["input"]).applied)
        before = store.inspect()["counts"]
        source.set_query(chain.query_context([first["row"], second["row"]]))
        for values in mutations:
            with self.subTest(phase="historical", values=list(values)):
                bad = replace(first["input"], chain_boundary=replace(boundary, **values))
                with self.assertRaises(ContractError): service.finish(bad)
                self.assertEqual(store.inspect()["counts"], before)
        self.assertFalse(service.finish(first["input"]).applied)
        self.assertFalse(service.query(first["input"].operation_id, wire(first["row"]["request"])).applied)
        self.assertEqual(store.inspect()["counts"], before)
        OBSERVATIONS.append({"event": "explicit_boundary_contract", "first_and_old_wrong_tail_start_scope_rejected": True,
                             "legal_historical_overlap_query_passed": True})

    def test_same_database_67_operations_old_query_and_global_conflicts(self):
        from app._r1_scoped_sqlite import ScopedSQLiteStore
        from app.r1_atomic_finish import ScopedCoreFinisher
        chain = IndependentWindowChain(seed=920000)
        first = chain.next()
        source = IndependentWindowSource(first)
        service, store, _, _ = create_service(first, source=source)
        cases = []
        for index in range(67):
            case = first if index == 0 else chain.next("ABORT" if index % 4 == 1 else "COMMIT")
            source.set_case(case)
            if index in (0, 63, 64):
                service.persist(case["input"])
            # finish itself always calls the actual product persist entry.
            result = service.finish(case["input"])
            self.assertTrue(result.applied)
            row = case["row"]
            self.assertEqual(result.terminal_wire, wire(row["receipt"]))
            self.assertEqual(result.audit_wire, wire(row["audit"]))
            self.assertEqual(result.result_wire, wire(row["request"][row["receipt"]["decision"].lower()]["result"]))
            self.assertEqual(result.completion_wire, wire(row["completion"]))
            self.assertEqual(result.checkpoint_wire, wire(row["after"]))
            cases.append(case)
            if index in (0, 62, 63, 64, 65, 66):
                OBSERVATIONS.append({"event": "independent_actual_finish", "ordinal": index + 1,
                                     "database": str(store.path), "counts": store.inspect()["counts"]})
                print("independent physical finish", index + 1, flush=True)
        counts = store.inspect()["counts"]
        self.assertEqual(counts["completions"], 67)
        self.assertEqual(counts["permit_consumptions"], 67)
        self.assertEqual(counts["business_records"], 50)
        with store.transaction(write=False) as db:
            windows = [json.loads(r[0]) for r in db.execute("SELECT verification_wire FROM history_windows ORDER BY sequence")]
        self.assertTrue(windows)
        self.assertTrue(all(w["actual_verification"]["distinct_operation_count"] <= 64 for w in windows))
        OBSERVATIONS.append({"event": "independent_journal_windows", "windows": windows})

        # Every invalid trial branches solely in our memory. No database is
        # copied, reset, or seeded with completion records.
        world_fields = ("authority", "core", "requests", "admissions", "operations", "cursor", "identity", "deployment")
        saved = {k: deepcopy(getattr(chain.world, k)) for k in world_fields}
        chain_fields = ("authority_count", "core_count", "authority_keys", "core_keys")
        saved_chain = {k: deepcopy(getattr(chain, k)) for k in chain_fields}
        original_uid = chain.world.uid
        for attack in ("policy", "inventory", "operation", "authority", "audit", "state", "identity", "generation", "gap", "conflicting_overlap"):
            with self.subTest(attack=attack):
                for k, value in saved.items(): setattr(chain.world, k, deepcopy(value))
                for k, value in saved_chain.items(): setattr(chain, k, deepcopy(value))
                faults, predecessor = None, None
                if attack == "identity": chain.world.identity["continuity_id"] = chain.world.uid(999990)
                if attack == "generation": chain.world.deployment["storage_generation_id"] = chain.world.uid(999991)
                if attack == "policy": faults = {"policy": {"policy_id": first["row"]["policy"]["policy_id"]}}
                if attack in ("inventory", "operation"):
                    offset = 9 if attack == "inventory" else 4
                    target = first["row"]["inventory"]["inventory_id"] if attack == "inventory" else first["input"].operation_id
                    chain.world.uid = lambda n, offset=offset, target=target: target if n == 100 + 67 * 100 + offset else original_uid(n)
                if attack in ("authority", "audit", "state"):
                    predecessor = deepcopy(saved["cursor"])
                    if attack == "state": predecessor["state_version"] += 1
                    else: predecessor[attack + "_ref"]["receipt_hash" if attack == "authority" else "audit_hash"] = "a" * 64
                case = chain.next(faults=faults, request_checkpoint=predecessor)
                chain.world.uid = original_uid
                if attack == "gap":
                    part = case["evidence"].authority
                    case["input"] = replace(case["input"], evidence=replace(case["evidence"], authority=replace(part, event_wires=part.event_wires[1:])))
                if attack == "conflicting_overlap":
                    event = deepcopy(saved["authority"]["events"][0]); event["recorded_at"] += 1
                    part = case["evidence"].authority
                    case["input"] = replace(case["input"], evidence=replace(case["evidence"], authority=replace(part, event_wires=(wire(event),) + part.event_wires)))
                source.set_case(case)
                with self.assertRaises(ContractError) as rejected: service.finish(case["input"])
                OBSERVATIONS.append({"event": "cross_window_rejection", "attack": attack, "error": str(rejected.exception)})
                self.assertEqual(store.inspect()["counts"], counts)
        for k, value in saved.items(): setattr(chain.world, k, deepcopy(value))
        for k, value in saved_chain.items(): setattr(chain, k, deepcopy(value))
        source.set_query(chain.query_context([cases[i]["row"] for i in (0, 63, 64, 66)]))
        reopened = ScopedSQLiteStore.open(store.path, expected_scope_wire=scope_wire(first))
        reader = ScopedCoreFinisher(reopened, trust=first["trust"], deployments=first["deployments"],
                                   runtime_principal=source.principal, source=source)
        for index in (0, 63, 64, 66):
            case = cases[index]
            result = reader.query(case["input"].operation_id, wire(case["row"]["request"]))
            self.assertFalse(result.applied)
            self.assertEqual(result.completion_wire, wire(case["row"]["completion"]))
            self.assertEqual(result.terminal_wire, wire(case["row"]["receipt"]))
        replay = reader.finish(first["input"])
        recovered = reader.recover(first["input"].operation_id)
        self.assertFalse(replay.applied)
        self.assertFalse(recovered.applied)
        self.assertEqual(replay.completion_wire, wire(first["row"]["completion"]))
        self.assertEqual(recovered.completion_wire, replay.completion_wire)
        self.assertEqual(reopened.inspect()["counts"], counts)
        OBSERVATIONS.append({"event": "fresh_service_old_query", "operations": [1,64,65,67], "after_permit_expiry": True,
                             "early_finish_and_recover_replay_applied": False})
        # Deliberately remove a raw evidence row only in this test-owned DB.
        # Neither a warm cache nor a fresh service may replace missing truth.
        with reopened.transaction() as db:
            db.execute("DELETE FROM history_windows WHERE sequence=2")
        fresh_reader = ScopedCoreFinisher(reopened, trust=first["trust"], deployments=first["deployments"],
                                         runtime_principal=source.principal, source=source)
        for candidate in (reader, fresh_reader):
            with self.assertRaisesRegex(ContractError, "missing original history window"):
                candidate.query(first["input"].operation_id, wire(first["row"]["request"]))
        self.assertEqual(reopened.inspect()["counts"], counts)
        OBSERVATIONS.append({"event": "missing_journal_fail_closed", "warm_cache": True, "fresh_service": True})

    def test_single_window_64_accepts_65_rejects_without_truncating(self):
        chain = IndependentWindowChain(seed=930000)
        cases = [chain.next("ABORT" if i % 3 == 0 else "COMMIT") for i in range(64)]
        world = chain.world
        window = WindowEvidence(tuple(wire(r) for r in world.requests), registry_slice(world.authority),
            ((world.deployment["runtime_principal"], registry_slice(world.core)),),
            tuple(wire(a) for a in world.admissions))
        engine = BoundedHistory(cases[0]["trust"], cases[0]["deployments"], world.boundary())
        result = engine.append(window, operation="COMPLETION_HISTORY")
        self.assertEqual(result["distinct_operation_count"], 64)
        chain.next()
        excessive = replace(window, request_wires=tuple(wire(r) for r in world.requests), authority=registry_slice(world.authority),
            cores=((world.deployment["runtime_principal"], registry_slice(world.core)),),
            source_admission_wires=tuple(wire(a) for a in world.admissions))
        fresh = BoundedHistory(cases[0]["trust"], cases[0]["deployments"], world.boundary())
        with self.assertRaisesRegex(ContractError, "resource limit"): fresh.append(excessive)
        with self.assertRaisesRegex(ContractError, "failed verification state"): fresh.append(window)
        OBSERVATIONS.append({"event": "independent_single_window", "accepted": 64, "rejected": 65,
                             "failed_state_reuse_rejected": True})


if __name__ == "__main__":
    unittest.main()
