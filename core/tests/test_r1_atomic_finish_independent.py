"""Non-author public-entry/file-SQLite checks with independently encoded inputs."""
from dataclasses import replace
import json
import unittest

from tests.r1_atomic_finish_independent_fixtures import (
    IndependentSource, create_service, h, new_case, scope_wire, wire,
)


class IndependentAtomicFinishTests(unittest.TestCase):
    def records(self, store):
        with store.transaction(write=False) as connection:
            return {
                "metadata": dict(connection.execute("SELECT * FROM metadata").fetchone()),
                "operations": [dict(r) for r in connection.execute("SELECT * FROM operations")],
                "completions": [dict(r) for r in connection.execute("SELECT * FROM completions")],
                "consumptions": [dict(r) for r in connection.execute("SELECT * FROM permit_consumptions")],
                "business": [dict(r) for r in connection.execute("SELECT * FROM business_records")],
            }

    def test_independent_commit_and_abort_exact_physical_records(self):
        for decision in ("COMMIT", "ABORT"):
            with self.subTest(decision=decision):
                case = new_case(decision, seed=811000 if decision == "COMMIT" else 812000)
                service, store, source, request = create_service(case)
                service.persist(request)
                before = self.records(store)
                self.assertEqual(before["completions"], [])
                self.assertEqual(before["metadata"]["checkpoint_wire"], wire(case["row"]["before"]))
                service.finish(request)
                result = self.records(store)
                self.assertEqual(len(result["operations"]), 1)
                self.assertEqual(result["operations"][0]["status"], "FINALIZED")
                self.assertEqual(len(result["completions"]), 1)
                self.assertEqual(len(result["consumptions"]), 1)
                completed = result["completions"][0]
                self.assertEqual(completed["terminal_wire"], case["expected_receipt_wire"])
                self.assertEqual(completed["audit_wire"], case["expected_audit_wire"])
                self.assertEqual(completed["result_wire"], case["expected_result_wire"])
                self.assertEqual(completed["completion_wire"], wire(case["expected_completion"]))
                self.assertEqual(result["metadata"]["checkpoint_wire"], wire(case["row"]["after"]))
                if decision == "ABORT":
                    self.assertEqual(result["metadata"]["business_state_wire"], before["metadata"]["business_state_wire"])
                    self.assertEqual(result["business"], [])
                else:
                    self.assertNotEqual(result["metadata"]["business_state_wire"], before["metadata"]["business_state_wire"])
                    self.assertEqual(len(result["business"]), 1)
                    self.assertEqual(result["business"][0]["value_wire"], wire(case["row"]["request"]["commit"]["effect"]["entries"][0]["value"]))
                self.assertEqual(store.inspect()["settings"]["journal_mode"], "wal")
                self.assertEqual(store.inspect()["settings"]["synchronous"], 2)

    def test_restart_exact_query_after_permit_expiry_is_read_only(self):
        from app._r1_scoped_sqlite import ScopedSQLiteStore
        from app.r1_atomic_finish import ScopedCoreFinisher
        case = new_case(seed=813000)
        service, store, source, request = create_service(case)
        service.persist(request)
        service.finish(request)
        original = self.records(store)
        source.clock = case["row"]["permit"]["expires_at"] + 1
        reopened = ScopedSQLiteStore.open(store.path, expected_scope_wire=scope_wire(case))
        reader = ScopedCoreFinisher(reopened, trust=case["trust"], deployments=case["deployments"],
                                   runtime_principal=source.principal, source=source)
        reader.query(request.operation_id, wire(case["row"]["request"]))
        reader.finish(request)
        self.assertEqual(self.records(reopened), original)

    def test_missing_source_and_wrong_authenticated_subject_fail_closed(self):
        from app.control_plane.r1_validation_codec import ContractError
        for invalid in ("missing", "principal", "session"):
            with self.subTest(invalid=invalid):
                case = new_case(seed=814000)
                source = None if invalid == "missing" else IndependentSource(case)
                if invalid == "principal": source.principal = "unrelated-current-caller"
                if invalid == "session": source.session_id = case["world"].uid(999)
                service, store, _, request = create_service(case, source=source)
                with self.assertRaises(ContractError): service.persist(request)
                self.assertEqual(store.inspect()["counts"]["completions"], 0)

    def test_current_deadline_denies_first_apply_without_laundering_abort(self):
        from app.control_plane.r1_validation_codec import ContractError
        case = new_case(seed=815000)
        service, store, source, request = create_service(case)
        service.persist(request)
        source.clock = case["row"]["permit"]["expires_at"] - 1000
        with self.assertRaises(ContractError): service.finish(request)
        rows = self.records(store)
        self.assertEqual(rows["operations"][0]["status"], "PENDING")
        self.assertEqual(rows["completions"], [])
        self.assertEqual(rows["metadata"]["checkpoint_wire"], wire(case["row"]["before"]))

    def test_revocation_then_reobserve_old_session_cannot_enable_apply(self):
        from app.control_plane.r1_validation_codec import ContractError
        case = new_case(seed=816000)
        service, store, source, request = create_service(case)
        service.persist(request)
        source.revoke = source.reobserve = True
        with self.assertRaises(ContractError): service.finish(request)
        self.assertEqual(store.inspect()["counts"]["completions"], 0)
        # An observed revocation must survive rejection of the business effect.
        # Later replay of old session evidence cannot erase that protected fact.
        source.revoke = source.reobserve = False
        with self.assertRaises(ContractError): service.finish(request)
        self.assertEqual(store.inspect()["counts"]["completions"], 0)

    def test_same_operation_changed_candidate_rejected_original_preserved(self):
        from app.control_plane.r1_validation_codec import ContractError
        case = new_case(seed=817000)
        service, store, source, request = create_service(case)
        service.persist(request); service.finish(request)
        original = self.records(store)
        changed = json.loads(wire(case["row"]["request"]))
        changed["commit"]["result"]["value"]["payload"]["value"] += 1
        bad = replace(request, evidence=replace(request.evidence, request_wires=(wire(changed),)))
        with self.assertRaises(ContractError): service.finish(bad)
        self.assertEqual(self.records(store), original)

    def test_completed_query_checks_actual_saved_result_bytes(self):
        from app.control_plane.r1_validation_codec import ContractError
        case = new_case(seed=818000)
        service, store, source, request = create_service(case)
        service.persist(request); service.finish(request)
        # Deliberate corruption is solely inside this case's owned new DB.
        with store.transaction() as connection:
            connection.execute("UPDATE completions SET result_wire=?", (wire({"corrupted": True}),))
        with self.assertRaises(ContractError): service.query(request.operation_id, wire(case["row"]["request"]))

    def test_other_connection_changes_same_version_head_before_finish(self):
        from app.control_plane.r1_validation_codec import ContractError
        case = new_case(seed=819000)
        service, store, source, request = create_service(case)
        service.persist(request)
        changed = json.loads(wire(case["row"]["before"]))
        changed["audit_ref"]["audit_hash"] = "f" * 64
        with store.transaction() as other_connection:
            other_connection.execute("UPDATE metadata SET checkpoint_wire=?", (wire(changed),))
        with self.assertRaises(ContractError): service.finish(request)
        after = self.records(store)
        self.assertEqual(after["completions"], [])
        self.assertEqual(after["business"], [])
        self.assertEqual(after["metadata"]["checkpoint_wire"], wire(changed))

    def test_read_path_rejects_changed_original_request(self):
        from app.control_plane.r1_validation_codec import ContractError
        case = new_case(seed=820000)
        service, store, source, request = create_service(case)
        service.persist(request); service.finish(request)
        before = self.records(store)
        altered = json.loads(wire(case["row"]["request"]))
        altered["intent"]["reason"] += " altered"
        with self.assertRaises(ContractError): service.query(request.operation_id, wire(altered))
        self.assertEqual(self.records(store), before)

    def test_current_business_bytes_changed_without_head_change_are_rejected(self):
        from app.control_plane.r1_validation_codec import ContractError
        case = new_case(seed=821000)
        service, store, source, request = create_service(case)
        service.persist(request)
        changed = wire({"changed_by_other_connection": True})
        with store.transaction() as other_connection:
            other_connection.execute("UPDATE metadata SET business_state_wire=?", (changed,))
        with self.assertRaises(ContractError): service.finish(request)
        after = self.records(store)
        self.assertEqual(after["business"], [])
        self.assertEqual(after["completions"], [])
        self.assertEqual(after["metadata"]["business_state_wire"], changed)

    def test_independent_owner_version_epoch_seed_must_match_request(self):
        from app.control_plane.r1_validation_codec import ContractError
        for field, value in (("owner_identity", "another-local-owner"), ("owner_version", 3), ("continuity_epoch", 4)):
            with self.subTest(field=field):
                case = new_case(seed=822000)
                scoped = json.loads(scope_wire(case)); scoped[field] = value
                service, store, source, request = create_service(case, store_scope=wire(scoped))
                with self.assertRaises(ContractError): service.finish(request)
                self.assertEqual(store.inspect()["counts"]["completions"], 0)

    def test_v1_bridge_source_storage_encoding_preserves_verified_public_proof(self):
        # This focused serialization check reuses prior author source builders.
        # It is NOT an independently constructed protocol oracle or a claim
        # that a V1-backed restoration has been applied to SQLite in this test.
        from app.r1_atomic_finish import FinishInput, _pack, _unpack
        from app.control_plane.r1_validation import validate_source_evidence
        from tests.r1_validation_legacy_fixtures import build_legacy_source
        from tests.r1_validation_restore_fixtures import lineage_source
        from tests.r1_validation_opening_chain_fixtures import append_mutation
        previous = build_legacy_source(("COMMIT", "ABORT"), offset=830000)
        current = append_mutation(lineage_source(previous, "V1_TO_V2", offset=10000))
        original = validate_source_evidence(current.source, current.trust, current.deployments)
        # A nonexecuted storage carrier exercises nested SourceEvidence types.
        # Its tuple is intentionally a source carrier, not RestoreEvidence and
        # is never passed to finish/validate_evidence as a restore authorization.
        carrier = FinishInput(current.mutation.request["intent"]["operation_id"],
                              current.source.history, h(current.mutation.objects["permit"]),
                              current.source.chain_boundary, (current.source,))
        encoded = _pack(carrier)
        decoded = _unpack(encoded)
        self.assertEqual(_pack(decoded), encoded)
        restored_source = decoded.restore_evidence[0]
        self.assertEqual(restored_source.opening.previous_source.legacy.expected_intent,
                         current.source.opening.previous_source.legacy.expected_intent)
        self.assertEqual(restored_source.opening.previous_source.observed_origin,
                         current.source.opening.previous_source.observed_origin)
        after = validate_source_evidence(restored_source, current.trust, current.deployments)
        self.assertEqual(after, original)


if __name__ == "__main__":
    unittest.main()
