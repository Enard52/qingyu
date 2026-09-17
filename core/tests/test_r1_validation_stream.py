"""Author checks for bounded internal replay; original whole-history stays bounded."""
from dataclasses import replace
from copy import deepcopy
import unittest

from app.control_plane import _r1_validation_semantics as sem
from app.control_plane._r1_validation_stream import BoundedHistory, RegistrySlice, from_history
from app.control_plane.r1_validation_codec import ContractError, c2, decode
from tests.test_r1_validation_chain import chain_world


class BoundedReplayTests(unittest.TestCase):
    def make(self):
        worlds, evidence, boundary = chain_world(("COMMIT", "ABORT", "COMMIT"))
        return worlds, evidence, boundary, BoundedHistory(worlds[0].trust, (worlds[0].deployment,), boundary)

    def test_single_event_transitions_match_original_whole_replay(self):
        worlds, evidence, boundary, engine = self.make()
        counts = []
        for world in worlds:
            result = engine.append(from_history(world.evidence()), operation="COMPLETION_HISTORY")
            counts.append(result["distinct_operation_count"])
        self.assertEqual(counts, [1, 1, 1])
        material = worlds[0].deployment
        expected_a = sem.replay_authority(worlds[-1].authority, worlds[0].pin,
                                          engine.materials, engine.requests)
        expected_c = sem.replay_core(worlds[-1].core, worlds[-1].authority, worlds[0].pin,
                                     material, engine.materials, engine.requests)
        self.assertEqual(engine.authority_state, expected_a)
        self.assertEqual(engine.core_states[material.runtime_principal], expected_c)
        self.assertEqual(engine.core_checkpoints[material.runtime_principal], worlds[-1].objects["after"])

    def test_exact_overlap_replay_retains_revision_and_completion(self):
        worlds, _, _, engine = self.make()
        window = from_history(worlds[0].evidence())
        engine.append(window, operation="COMPLETION_HISTORY")
        state = deepcopy(engine.core_states)
        revision = engine.revision
        result = engine.append(window, operation="COMPLETION_HISTORY")
        self.assertEqual(result["revision"], revision)
        self.assertEqual(engine.core_states, state)

    def test_fork_changes_never_mutate_committed_parent(self):
        worlds, _, _, engine = self.make()
        engine.append(from_history(worlds[0].evidence()))
        child = engine.fork()
        child.append(from_history(worlds[1].evidence()))
        self.assertEqual(len(engine.requests), 1)
        self.assertEqual(len(child.requests), 2)
        self.assertEqual(len(engine.authority["events"]), 10)
        self.assertEqual(len(child.authority["events"]), 20)

    def test_missing_predecessor_is_not_a_new_trust_anchor(self):
        worlds, _, _, engine = self.make()
        second = from_history(worlds[1].evidence())
        part = replace(second.authority, event_wires=second.authority.event_wires[10:])
        with self.assertRaisesRegex(ContractError, "gap"):
            engine.append(replace(second, authority=part))
        with self.assertRaisesRegex(ContractError, "discarded"):
            engine.append(from_history(worlds[0].evidence()))

    def test_old_event_overlap_cannot_change_original_time(self):
        worlds, _, _, engine = self.make()
        window = from_history(worlds[0].evidence())
        engine.append(window)
        event = decode(window.authority.event_wires[0])
        event["recorded_at"] += 1
        part = replace(window.authority, event_wires=(c2(event),))
        with self.assertRaisesRegex(ContractError, "overlap conflict"):
            engine.fork().append(replace(window, authority=part))

    def test_missing_original_source_is_denied_before_continuation(self):
        worlds, _, _, engine = self.make()
        window = from_history(worlds[0].evidence())
        with self.assertRaisesRegex(ContractError, "admission required"):
            engine.append(replace(window, source_admission_wires=()))

    def test_registry_slice_preserves_original_wire_limit(self):
        worlds, _, _, engine = self.make()
        window = from_history(worlds[0].evidence())
        part = RegistrySlice(window.authority.header_wire, window.authority.event_wires,
                             (("0" * 64, b" " * (1024 * 1024 + 1)),))
        with self.assertRaises(ContractError):
            engine.append(replace(window, authority=part))


if __name__ == "__main__":
    unittest.main()
