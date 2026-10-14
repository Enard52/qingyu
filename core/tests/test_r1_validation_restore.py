"""Author integration tests using public validation APIs and ephemeral real keys."""
from dataclasses import replace
from copy import deepcopy
from types import SimpleNamespace
import unittest

from app.control_plane.r1_validation import (
    validate_evidence, validate_source_evidence, validate_restoration_evidence,
)
from app.control_plane.r1_validation_codec import ContractError, c2, decode, h2, sha
from app.control_plane._r1_validation_restore import ArchiveMember
from tests.r1_validation_restore_fixtures import (
    build_restore_world, genesis_only_source, lineage_source, manifest, replace_source_parts, restored_final_source, with_backup_at_tail,
)
from tests.r1_validation_fixtures import uid


class RestoreKernelTests(unittest.TestCase):
    def previous_v2(self, aligned=True):
        world = build_restore_world(aligned=aligned)
        return SimpleNamespace(source=world.proof.source, trust=world.world.trust, deployments=(world.world.deployment,),
                               pin=world.world.pin, root=world.world.root, receipt_key=world.world.receipt_key)

    def source(self, world, source=None):
        return validate_source_evidence(source or world.proof.source, world.world.trust, world.deployments)

    def restore(self, world, proof=None):
        return validate_restoration_evidence(proof or world.proof, world.world.trust, world.deployments)

    def replace_member(self, source, role, replacement):
        rows = [replace(row, raw=replacement) if row.role == role else row for row in source.members]
        return replace_source_parts(source, members=rows)

    def test_complete_restore_profiles_and_three_terminal_branches(self):
        for aligned in (False, True):
            for decision, override in (("COMMIT", False), ("ABORT", False), ("ABORT", True)):
                with self.subTest(aligned=aligned, decision=decision, override=override):
                    w = build_restore_world(decision, override, aligned)
                    original = (w.history, w.proof, w.boundary)
                    result = validate_evidence("COMPLETION_HISTORY", w.history, w.world.trust, w.deployments,
                                               chain_boundary=w.boundary, restore_evidence=(w.proof,))
                    self.assertEqual(result.history_origin, "UNVERIFIED")
                    self.assertEqual(result.environment_origin, "NOT_OBSERVED")
                    self.assertEqual(result.current_eligibility, "NOT_EVALUATED")
                    self.assertEqual(len(result.completion_digests), 2 if aligned else 1)
                    self.assertEqual(result.restoration_context_digests, (h2(decode(w.proof.context_wire)),))
                    self.assertEqual((w.history, w.proof, w.boundary), original)

    def test_source_actual_core_checkpoint_is_separate_from_terminal_tail(self):
        w = build_restore_world(aligned=False)
        result = self.source(w)
        self.assertEqual(result.profile, "HISTORY_ONLY_TAIL")
        self.assertEqual(result.verified_checkpoint_wire, w.boundary.start_checkpoint_wire)
        self.assertEqual(result.terminal_checkpoint_wire, w.boundary.expected_end_checkpoint_wire)
        self.assertNotEqual(result.verified_checkpoint_wire, result.terminal_checkpoint_wire)

    def test_aligned_source_and_backup_already_at_tail(self):
        w = build_restore_world(aligned=True)
        proof = with_backup_at_tail(w)
        result = self.restore(w, proof)
        self.assertEqual(result.profile, "RESTORATION_SCOPE")
        self.assertEqual(result.verified_checkpoint_wire, w.boundary.expected_end_checkpoint_wire)
        self.assertEqual(result.history_origin, "UNVERIFIED")

    def test_genesis_only_source_and_restore_backup(self):
        w = build_restore_world()
        source = genesis_only_source(w)
        result = self.source(w, source)
        self.assertEqual(result.profile, "ALIGNED_OPENING")
        self.assertEqual(result.verified_checkpoint_wire, result.terminal_checkpoint_wire)
        context = decode(w.proof.context_wire)
        context["source_snapshot"] = decode(source.snapshot_wire)
        w.world.sign(context)
        proof = replace(w.proof, source=source, context_wire=c2(context))
        self.assertEqual(self.restore(w, proof).verified_checkpoint_wire, source.chain_boundary.start_checkpoint_wire)

    def test_genesis_only_cannot_hide_nonempty_request_admission(self):
        w = build_restore_world()
        source = genesis_only_source(w)
        history = replace(source.history, source_admission_wires=w.proof.source.history.source_admission_wires)
        with self.assertRaises(ContractError):
            self.source(w, replace(source, history=history))

    def test_archive_member_raw_length_and_hash_are_exact(self):
        w = build_restore_world()
        for role in ("SOURCE_DEPLOYMENT", "SOURCE_FENCING", "SIGNED_ORIGIN", "REQUEST", "AUTHORITY_REGISTRY"):
            with self.subTest(role=role):
                rows = tuple(replace(row, raw=row.raw+b" ") if row.role == role else row for row in w.proof.source.members)
                with self.assertRaises(ContractError):
                    self.source(w, replace(w.proof.source, members=rows))

    def test_archive_missing_required_or_extra_unbound_member(self):
        w = build_restore_world()
        source = w.proof.source
        for role in ("SIGNED_ORIGIN", "GENESIS_ATTEMPT", "SOURCE_ADMISSION", "STAGED_EVIDENCE", "REGISTRY_EVENT"):
            with self.subTest(missing=role):
                changed = replace_source_parts(source, members=tuple(row for row in source.members if row.role != role))
                with self.assertRaises(ContractError):
                    self.source(w, changed)
        extra = ArchiveMember("REQUEST", 999, c2({"undeclared": "original operation"}))
        with self.assertRaises(ContractError):
            self.source(w, replace_source_parts(source, members=(*source.members, extra)))

    def test_unreferenced_registry_request_cannot_hide_outside_union(self):
        w = build_restore_world()
        source = w.proof.source
        registry = decode(source.history.authority_history)
        hidden = deepcopy(w.world.request)
        hidden["intent"]["operation_id"] = uid(5555)
        registry["records"][sha(c2(hidden))] = hidden
        wire = c2(registry)
        changed = self.replace_member(source, "AUTHORITY_REGISTRY", wire)
        changed = replace(changed, history=replace(source.history, authority_history=wire))
        with self.assertRaises(ContractError):
            self.source(w, changed)

    def test_source_deployment_requires_independent_scope_and_strict_types(self):
        w = build_restore_world()
        source = w.proof.source
        observation = source.source_deployment_observation
        for name, value in (("owner_version", True), ("continuity_epoch", True), ("state_version", False),
                            ("owner_identity", "different-owner"), ("core_installation_id", uid(9000)),
                            ("deployment_admission_digest", "e"*64), ("authority_tip_wire", source.chain_boundary.start_checkpoint_wire)):
            with self.subTest(field=name):
                with self.assertRaises(ContractError):
                    self.source(w, replace(source, source_deployment_observation=replace(observation, **{name: value})))
        with self.assertRaises(ContractError):
            self.source(w, replace(source, source_deployment_observation=None))

    def test_fencing_original_artifact_scope_time_and_quiescence(self):
        w = build_restore_world()
        source = w.proof.source
        observation = source.source_fencing_observation
        for name, value in (("source_deployment_digest", "e"*64), ("source_fencing_evidence_digest", "e"*64),
                            ("observed_at", 2001), ("observed_at", True), ("observed_by", ""),
                            ("authority_writer_state", "ACTIVE"), ("core_writer_state", "ACTIVE"),
                            ("pending_operation_ids", (uid(5000),)), ("uncommitted_proposal_ids", (uid(5001),)),
                            ("audit_tip_wire", source.chain_boundary.expected_end_checkpoint_wire)):
            with self.subTest(field=name, value=value):
                with self.assertRaises(ContractError):
                    self.source(w, replace(source, source_fencing_observation=replace(observation, **{name: value})))
        with self.assertRaises(ContractError):
            self.source(w, replace(source, source_fencing_observation=None))

    def test_original_origin_signature_and_independent_observation_required(self):
        w = build_restore_world()
        source = w.proof.source
        with self.assertRaises(ContractError):
            self.source(w, replace(source, observed_origin=None))
        origin = next(row.raw for row in source.members if row.role == "SIGNED_ORIGIN")
        damaged = origin.replace(b'"intent"', b'"Intent"', 1)
        with self.assertRaises(ContractError):
            self.source(w, self.replace_member(source, "SIGNED_ORIGIN", damaged))

    def test_profile_cannot_promote_derived_audit_to_actual_core(self):
        w = build_restore_world()
        source = w.proof.source
        profile = decode(next(row.raw for row in source.members if row.role == "SOURCE_PROFILE"))
        profile["profile"] = "ALIGNED_OPENING"
        with self.assertRaises(ContractError):
            self.source(w, self.replace_member(source, "SOURCE_PROFILE", c2(profile)))
        rows = [replace(row, role="CORE_AUDIT", index=900) if row.role == "DERIVED_AUDIT" else row for row in source.members]
        with self.assertRaises(ContractError):
            self.source(w, replace_source_parts(source, members=rows))

    def test_source_inventory_must_equal_original_history_union(self):
        w = build_restore_world()
        source = w.proof.source
        inv = decode(source.inventory_wire)
        inv["entries"].pop()
        changed = self.replace_member(source, "OPERATION_INVENTORY", c2(inv))
        snapshot = decode(changed.snapshot_wire); snapshot["operation_inventory_digest"] = h2(inv)
        changed = replace_source_parts(changed, snapshot=snapshot, inventory_wire=c2(inv))
        with self.assertRaises(ContractError):
            self.source(w, changed)

    def test_valid_root_signature_cannot_change_backup_original_prefix(self):
        w = build_restore_world(aligned=True)
        for field, value in (("receipt_wires", []), ("audit_wires", []), ("governed_results", [w.world.request["commit"]["result"]]), ("captured_at", 1)):
            with self.subTest(field=field):
                backup = decode(w.proof.backup_wire); backup[field] = value
                context = decode(w.proof.context_wire); context["restore_source_state_digest"] = sha(c2(backup)); w.world.sign(context)
                with self.assertRaises(ContractError):
                    self.restore(w, replace(w.proof, backup_wire=c2(backup), context_wire=c2(context)))

    def test_restore_independent_backup_checkpoint_and_target(self):
        w = build_restore_world()
        with self.assertRaises(ContractError):
            self.restore(w, replace(w.proof, expected_backup_checkpoint_wire=w.boundary.expected_end_checkpoint_wire))
        context = decode(w.proof.context_wire); context["target_core_installation_id"] = uid(7000); w.world.sign(context)
        with self.assertRaises(ContractError):
            self.restore(w, replace(w.proof, context_wire=c2(context)))

    def test_restore_root_signature_cannot_authorize_future_source(self):
        w = build_restore_world()
        context = decode(w.proof.context_wire)
        context["issued_at"] = decode(w.proof.source.snapshot_wire)["captured_at"]
        w.world.sign(context)
        with self.assertRaises(ContractError):
            self.restore(w, replace(w.proof, context_wire=c2(context)))

    def test_opening_attempt_and_distinct_origins_are_verified(self):
        w = build_restore_world()
        source = w.proof.source
        opening = source.opening
        for field, wire in (("receipt_wire", opening.prepare_wire), ("audit_wire", opening.receipt_wire)):
            with self.subTest(field=field):
                with self.assertRaises(ContractError):
                    self.source(w, replace(source, opening=replace(opening, **{field: wire})))
        with self.assertRaises(ContractError):
            self.source(w, replace(source, opening=replace(opening, attempt_event_wires=opening.attempt_event_wires[:1])))

    def test_failed_genesis_attempt_retained_without_consuming_receipt_or_audit_one(self):
        w = build_restore_world(failed_first=True)
        result = self.source(w)
        checkpoint = decode(w.boundary.start_checkpoint_wire)
        self.assertEqual(checkpoint["authority_ref"]["authority_sequence"], 1)
        self.assertEqual(checkpoint["audit_ref"]["audit_sequence"], 1)
        self.assertEqual(len(w.proof.source.opening.attempt_wires), 2)
        self.assertEqual(result.verified_checkpoint_wire, w.boundary.start_checkpoint_wire)
        source = w.proof.source
        opening = replace(source.opening, attempt_evidence_wires=(*source.opening.attempt_evidence_wires, c2({"unbound": "attempt fact"})))
        with self.assertRaises(ContractError):
            self.source(w, replace(source, opening=opening))

    def test_archive_resource_limit_fails_closed(self):
        w = build_restore_world()
        row = ArchiveMember("SOURCE_FENCING", 1, b"x" * (1_048_576+1))
        rows = [row if value.role == row.role else value for value in w.proof.source.members]
        with self.assertRaises(ContractError):
            self.source(w, replace_source_parts(w.proof.source, members=rows))

    def test_generation_restore_continues_audit_resets_authority_and_preserves_state(self):
        previous = self.previous_v2()
        for offset in (0, 100):
            current = lineage_source(previous, offset=offset)
            result = validate_source_evidence(current.source, current.trust, current.deployments)
            before = decode(previous.source.snapshot_wire)
            after = decode(result.verified_checkpoint_wire)
            self.assertEqual(after["authority_ref"]["authority_generation"], before["source_authority_generation"]+1)
            self.assertEqual(after["authority_ref"]["authority_sequence"], 1)
            self.assertEqual(after["audit_ref"]["audit_sequence"], before["audit_tip"]["audit_sequence"]+1)
            self.assertEqual(after["state_version"], before["state_version"])
            self.assertEqual(result.history_origin, "UNVERIFIED")
            previous = current

    def test_generation_restore_requires_actual_aligned_prior_source(self):
        current = lineage_source(self.previous_v2(aligned=False))
        with self.assertRaises(ContractError):
            validate_source_evidence(current.source, current.trust, current.deployments)

    def test_history_only_restore_completed_target_becomes_new_generation_source(self):
        world = build_restore_world(aligned=False)
        restored = restored_final_source(world)
        result = validate_source_evidence(restored.source, restored.trust, restored.deployments)
        self.assertEqual(result.profile, "ALIGNED_OPENING")
        self.assertEqual(result.verified_checkpoint_wire, world.boundary.expected_end_checkpoint_wire)
        current = lineage_source(restored)
        result = validate_source_evidence(current.source, current.trust, current.deployments)
        checkpoint = decode(result.verified_checkpoint_wire)
        self.assertEqual(checkpoint["authority_ref"]["authority_generation"], 2)
        self.assertEqual(checkpoint["authority_ref"]["authority_sequence"], 1)
        self.assertEqual(checkpoint["audit_ref"]["audit_sequence"], 3)
        self.assertEqual(checkpoint["state_version"], 1)

    def test_restored_final_source_requires_complete_original_proof_members(self):
        restored = restored_final_source(build_restore_world())
        for role in ("RESTORATION_CONTEXT", "RESTORE_SOURCE_STATE", "ARCHIVE_MANIFEST"):
            with self.subTest(role=role):
                source = replace_source_parts(restored.source, members=[row for row in restored.source.members if row.role != role])
                with self.assertRaises(ContractError):
                    validate_source_evidence(source, restored.trust, restored.deployments)
        with self.assertRaises(ContractError):
            validate_source_evidence(replace(restored.source, restoration_evidence=()), restored.trust, restored.deployments)

    def test_partial_restored_source_remains_history_only_and_cannot_open_generation(self):
        restored = restored_final_source(build_restore_world(), completed=False)
        result = validate_source_evidence(restored.source, restored.trust, restored.deployments)
        self.assertEqual(result.profile, "HISTORY_ONLY_TAIL")
        self.assertNotEqual(result.verified_checkpoint_wire, result.terminal_checkpoint_wire)
        current = lineage_source(restored)
        with self.assertRaises(ContractError):
            validate_source_evidence(current.source, current.trust, current.deployments)

    def test_original_core_actual_audit_does_not_promote_lagging_restored_core(self):
        restored = restored_final_source(build_restore_world(aligned=True), completed=False)
        result = validate_source_evidence(restored.source, restored.trust, restored.deployments)
        self.assertEqual(result.profile, "HISTORY_ONLY_TAIL")
        self.assertNotEqual(result.verified_checkpoint_wire, result.terminal_checkpoint_wire)

    def test_source_recursive_proof_cycle_fails_and_next_call_recovers(self):
        world = build_restore_world()
        restored = restored_final_source(world)
        source = replace(restored.source)
        cyclic_proof = replace(world.proof, source=source)
        object.__setattr__(source, "restoration_evidence", (cyclic_proof,))
        with self.assertRaises(ContractError):
            validate_source_evidence(source, restored.trust, restored.deployments)
        self.assertEqual(self.source(world).profile, "HISTORY_ONLY_TAIL")

    def test_lineage_depth_eight_accepts_and_nine_rejects(self):
        world = build_restore_world()
        previous = SimpleNamespace(source=genesis_only_source(world), trust=world.world.trust, deployments=(world.world.deployment,),
                                   pin=world.world.pin, root=world.world.root, receipt_key=world.world.receipt_key)
        for depth in range(8):
            previous = lineage_source(previous, offset=1000+depth*100)
        self.assertEqual(validate_source_evidence(previous.source, previous.trust, previous.deployments).profile, "ALIGNED_OPENING")
        over = lineage_source(previous, offset=2000)
        with self.assertRaises(ContractError):
            validate_source_evidence(over.source, over.trust, over.deployments)

    def test_source_graph_node_and_proof_count_bounds(self):
        world = build_restore_world()
        many = replace(world.proof.source, restoration_evidence=tuple(world.proof for _ in range(33)))
        with self.assertRaises(ContractError):
            self.source(world, many)
        branch = replace(world.proof.source, restoration_evidence=tuple(world.proof for _ in range(32)))
        proof = replace(world.proof, source=branch)
        graph = replace(world.proof.source, restoration_evidence=(proof, proof))
        with self.assertRaises(ContractError):
            self.source(world, graph)
        with self.assertRaises(ContractError):
            self.source(world, replace(world.proof.source, legacy=object()))

    def test_valid_signed_generation_opening_cannot_change_owner_or_reset_audit(self):
        previous = self.previous_v2()
        for fault in ("owner", "audit_reset"):
            with self.subTest(fault=fault):
                current = lineage_source(previous, fault=fault)
                with self.assertRaises(ContractError):
                    validate_source_evidence(current.source, current.trust, current.deployments)

    def test_real_v1_to_v2_opening_preserves_original_dual_predecessors(self):
        from tests.r1_validation_legacy_fixtures import build_legacy_source
        previous = build_legacy_source(("COMMIT", "ABORT", "COMMIT"))
        current = lineage_source(previous, "V1_TO_V2")
        result = validate_source_evidence(current.source, current.trust, current.deployments)
        before = decode(previous.source.snapshot_wire)
        receipt = decode(current.source.opening.receipt_wire)
        audit = decode(current.source.opening.audit_wire)
        self.assertEqual(receipt["previous_authority_ref"], before["authority_tip"])
        self.assertEqual(audit["candidate"]["previous_audit_ref"], before["audit_tip"])
        self.assertEqual(receipt["authority_sequence"], before["authority_tip"]["authority_sequence"]+1)
        self.assertEqual(audit["candidate"]["audit_sequence"], before["audit_tip"]["audit_sequence"]+1)
        self.assertEqual(result.history_origin, "UNVERIFIED")
        self.assertEqual(decode(current.source.snapshot_wire)["state_version"], before["state_version"])

    def test_signed_v1_bridge_cannot_change_owner_or_reset_audit(self):
        from tests.r1_validation_legacy_fixtures import build_legacy_source
        previous = build_legacy_source(("COMMIT", "ABORT"))
        for fault in ("owner", "audit_reset"):
            with self.subTest(fault=fault):
                current = lineage_source(previous, "V1_TO_V2", fault=fault)
                with self.assertRaises(ContractError):
                    validate_source_evidence(current.source, current.trust, current.deployments)


if __name__ == "__main__":
    unittest.main()
