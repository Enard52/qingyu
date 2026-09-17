"""Product chain tests; independent literal expectations for state and cursors."""
import unittest
from copy import deepcopy
from dataclasses import replace

from app.control_plane.r1_validation import (
    validate_evidence, ChainBoundary, HistoryEvidence, CoreHistory, MissingTrustedContext,
)
from app.control_plane.r1_validation_codec import ContractError, c2, h2, obj
from tests.r1_validation_fixtures import build_world


def chain_world(decisions=("COMMIT", "ABORT", "COMMIT"), *, initial_id=0, initial_checkpoint=None, faults=None, completed=None):
    worlds = []
    for index, decision in enumerate(decisions):
        worlds.append(build_world(decision, parent=worlds[-1] if worlds else None,
            complete=True if completed is None else completed[index],
            id_offset=initial_id + 100 * index, time_offset=2000 * index,
            initial_checkpoint=initial_checkpoint if index == 0 else None,
            faults=(faults or {}).get(index)))
    first, last = worlds[0], worlds[-1]
    scope = first.request["intent"]["scope"]
    boundary = ChainBoundary(c2(first.request["intent"]["identity"]), c2(first.objects["before"]), c2(last.objects["after"]),
        scope["actor_identity"], scope["owner_version"], scope["continuity_epoch"],
        scope["storage_generation_id"], scope["control_plane_generation_id"], scope["trust_domain_id"])
    evidence = HistoryEvidence(tuple(c2(w.request) for w in worlds), c2(last.authority),
        (CoreHistory(last.deployment.runtime_principal, c2(last.core)),),
        source_admission_wires=tuple(c2(w.objects["source_admission"]) for w in worlds))
    return worlds, evidence, boundary


class OperationChainTests(unittest.TestCase):
    def run_history(self, worlds, evidence, boundary, operation="COMPLETION_HISTORY"):
        return validate_evidence(operation, evidence, worlds[-1].trust, (worlds[-1].deployment,), chain_boundary=boundary)

    def test_commit_abort_commit_chain_and_different_ids(self):
        for decisions, offset in [(("COMMIT", "ABORT"), 0), (("ABORT", "COMMIT", "ABORT"), 3000)]:
            with self.subTest(decisions=decisions, offset=offset):
                worlds, evidence, boundary = chain_world(decisions, initial_id=offset)
                result = self.run_history(worlds, evidence, boundary)
                self.assertEqual(len(result.terminal_digests), len(decisions))
                self.assertEqual(worlds[-1].objects["after"]["state_version"], 4 + decisions.count("COMMIT"))
                self.assertEqual(worlds[-1].objects["after"]["audit_ref"]["audit_sequence"], 4 + len(decisions))
                self.assertEqual(result.history_origin, "UNVERIFIED")
                self.assertEqual(result.current_eligibility, "NOT_EVALUATED")

    def test_external_boundary_required_and_exact(self):
        worlds, evidence, boundary = chain_world(("COMMIT", "ABORT"))
        with self.assertRaises(MissingTrustedContext):
            self.run_history(worlds, evidence, None)
        for change in ({"owner_identity": "someone-else"}, {"owner_version": 2},
                       {"continuity_epoch": 2}, {"expected_end_checkpoint_wire": boundary.start_checkpoint_wire},
                       {"start_checkpoint_wire": boundary.expected_end_checkpoint_wire}):
            with self.subTest(change=change), self.assertRaises(ContractError):
                self.run_history(worlds, evidence, replace(boundary, **change))

    def test_duplicate_exact_request_is_not_second_operation(self):
        worlds, evidence, boundary = chain_world(("COMMIT", "ABORT"))
        repeated = replace(evidence, request_wires=evidence.request_wires + evidence.request_wires[:1])
        self.assertEqual(len(self.run_history(worlds, repeated, boundary).request_digests), 2)

    def test_validly_signed_second_operation_with_wrong_predecessor_is_rejected(self):
        first = build_world()
        bad_pre = deepcopy(first.objects["after"])
        bad_pre["authority_ref"]["receipt_hash"] = "c" * 64
        second = build_world("ABORT", parent=first, id_offset=100, time_offset=2000, initial_checkpoint=bad_pre)
        _, _, boundary = chain_world(("COMMIT", "ABORT"))
        scope = first.request["intent"]["scope"]
        boundary = replace(boundary, identity_wire=c2(first.request["intent"]["identity"]),
                           start_checkpoint_wire=c2(first.objects["before"]), expected_end_checkpoint_wire=c2(second.objects["after"]))
        evidence = HistoryEvidence((c2(first.request), c2(second.request)), c2(second.authority),
            (CoreHistory(second.deployment.runtime_principal, c2(second.core)),),
            source_admission_wires=(c2(first.objects["source_admission"]), c2(second.objects["source_admission"])))
        from app.control_plane.r1_validation_crypto import verify_signed
        verify_signed(second.objects["receipt"], second.trust)
        with self.assertRaisesRegex(ContractError, "chain missing predecessor"):
            self.run_history([first, second], evidence, boundary)

    def test_missing_middle_request_and_conflicting_same_id_rejected(self):
        worlds, evidence, boundary = chain_world()
        with self.assertRaises(ContractError):
            self.run_history(worlds, replace(evidence, request_wires=evidence.request_wires[::2]), boundary)
        bad = deepcopy(worlds[0].request)
        bad["intent"]["reason"] = "changed original content"
        with self.assertRaises(ContractError):
            self.run_history(worlds, replace(evidence, request_wires=evidence.request_wires + (c2(bad),)), boundary)

    def test_request_order_does_not_reorder_actual_terminal_history(self):
        worlds, evidence, boundary = chain_world(("COMMIT", "ABORT"))
        result = self.run_history(worlds, replace(evidence, request_wires=evidence.request_wires[::-1]), boundary)
        self.assertEqual(len(result.completion_digests), 2)

    def test_wire_resource_bound_is_explicit(self):
        worlds, evidence, boundary = chain_world(("COMMIT",))
        with self.assertRaisesRegex(ContractError, "resource limit"):
            self.run_history(worlds, replace(evidence, request_wires=evidence.request_wires * 129), boundary)

    def test_real_lagging_core_is_distinct_from_missing_intermediate_apply(self):
        worlds, evidence, boundary = chain_world(("COMMIT", "ABORT"), completed=(True, False))
        self.assertEqual(len(self.run_history(worlds, evidence, boundary, "TERMINAL_HISTORY").terminal_digests), 2)
        with self.assertRaisesRegex(ContractError, "completed local use"):
            self.run_history(worlds, evidence, boundary)
        worlds, evidence, boundary = chain_world(("COMMIT", "ABORT"), completed=(False, True))
        with self.assertRaisesRegex(ContractError, "Core local chain missing APPLY"):
            self.run_history(worlds, evidence, boundary, "TERMINAL_HISTORY")

    def test_authority_and_audit_predecessors_cannot_be_interchanged(self):
        worlds, evidence, boundary = chain_world(("COMMIT", "ABORT"))
        from app.control_plane.r1_validation_codec import decode
        start = decode(boundary.start_checkpoint_wire)
        start["authority_ref"]["receipt_hash"], start["audit_ref"]["audit_hash"] = (
            start["audit_ref"]["audit_hash"], start["authority_ref"]["receipt_hash"])
        with self.assertRaisesRegex(ContractError, "chain missing predecessor"):
            self.run_history(worlds, evidence, replace(boundary, start_checkpoint_wire=c2(start)))


if __name__ == "__main__":
    unittest.main()
