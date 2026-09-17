"""Actual product integration tests; no DB, services, old executable or secrets.

The fixture builds signed objects; the expected outcomes below come from the
contract's original-source, role, temporal and exact-content relationships.
Every semantic mutation is created before all downstream hashes/signatures.
"""
from copy import deepcopy
from dataclasses import replace
import unittest
from unittest.mock import patch

from app.control_plane.r1_validation import (
    CoreHistory, HistoryEvidence, MissingTrustedContext, UnsupportedOperation, validate_evidence,
)
from app.control_plane.r1_validation_codec import ContractError, c2, h2, obj, record
from app.control_plane.r1_validation_crypto import verify_signed
from tests.r1_validation_fixtures import build_world, event, position, put, raw, uid


class ValidationKernelTests(unittest.TestCase):
    def validate_world(self, world, operation="COMPLETION_HISTORY", evidence=None):
        return validate_evidence(operation, evidence or world.evidence(), world.trust, (world.deployment,))

    def all_signatures_valid(self, world):
        seen = set()
        for reg in (world.authority, world.core):
            for value in reg["records"].values():
                if "root_signature" in value or "receipt_signature" in value:
                    digest = h2(value)
                    if digest not in seen:
                        result = verify_signed(c2(value), world.trust)
                        self.assertEqual(result.object_digest, digest)
                        seen.add(digest)
        self.assertGreaterEqual(len(seen), 4)

    def reject_fault(self, phase, field, value, reason, **options):
        world = build_world(faults={phase: {field: value}}, **options)
        self.all_signatures_valid(world)
        with self.assertRaisesRegex(ContractError, reason):
            self.validate_world(world)

    def test_legal_normal_commit_abort_override_and_all_entries(self):
        for decision, override in (("COMMIT", False), ("ABORT", False), ("COMMIT", True)):
            with self.subTest(decision=decision, override=override):
                world = build_world(decision=decision, override=override)
                self.all_signatures_valid(world)
                receipt = world.objects["receipt"]
                expected_decision = "ABORT" if override else decision
                expected_state = 5 if expected_decision == "COMMIT" else 4
                self.assertEqual(receipt["decision"], expected_decision)
                self.assertEqual(receipt["state_after"], expected_state)
                self.assertEqual(receipt["authority_sequence"], 5)
                self.assertEqual(world.objects["completion"]["after_checkpoint"]["state_version"], expected_state)
                self.assertEqual(world.objects["ack"]["request_digest"], h2(world.request))
                self.assertEqual(world.objects["ack"]["identity_digest"], h2(world.request["intent"]["identity"]))
                for operation in ("REGISTRY_RELATIONS", "TERMINAL_HISTORY", "COMPLETION_HISTORY"):
                    result = self.validate_world(world, operation)
                    self.assertEqual(result.protocol, "VALID_SCOPED_V2")
                    self.assertEqual(result.signatures, "VALID_UNDER_EXPLICIT_PIN")
                    self.assertEqual(result.semantics, "CONSISTENT_WITH_SUPPLIED_HISTORY")
                    self.assertEqual(result.history_origin, "UNVERIFIED")
                    self.assertEqual(result.current_eligibility, "NOT_EVALUATED")
                    self.assertEqual(result.terminal_digests, (h2(receipt),))
                    self.assertEqual(result.completion_digests, (raw(world.objects["completion"]),))
                    self.assertEqual(result.verified_signature_count, 6 if override else 5)

    def test_valid_prefix_is_not_complete_terminal_or_completion(self):
        world = build_world(complete=False)
        self.validate_world(world, "TERMINAL_HISTORY")
        with self.assertRaisesRegex(ContractError, "completed local use"):
            self.validate_world(world)
        prefix = deepcopy(world.authority)
        prefix["events"] = prefix["events"][:7]  # Through accepted PREPARE, no terminal.
        empty_core = deepcopy(world.core)
        empty_core["events"] = []
        evidence = replace(world.evidence(), authority_history=c2(prefix),
                           core_histories=(CoreHistory(world.deployment.runtime_principal, c2(empty_core)),))
        self.validate_world(world, "REGISTRY_RELATIONS", evidence)
        with self.assertRaisesRegex(ContractError, "complete terminal history"):
            self.validate_world(world, "TERMINAL_HISTORY", evidence)

    def test_complete_history_requires_original_source_admission_bytes(self):
        world = build_world()
        evidence = replace(world.evidence(), source_admission_wires=())
        for operation in ("TERMINAL_HISTORY", "COMPLETION_HISTORY"):
            with self.subTest(operation=operation), self.assertRaisesRegex(ContractError, "source|admission"):
                self.validate_world(world, operation, evidence)

    def test_original_source_admission_exact_caller_content_and_deployment(self):
        cases = (("operation_id", uid(999)), ("intent_digest", "1"*64), ("source_decision_digest", "2"*64),
                 ("identity_digest", "3"*64), ("scope_digest", "4"*64), ("actor_identity", "other-caller"),
                 ("caller_runtime_id", uid(998)), ("session_id", uid(997)), ("lease_id", uid(996)),
                 ("lease_generation", 2), ("core_installation_id", uid(995)),
                 ("deployment_admission_digest", "5"*64), ("component_artifact_digest", "6"*64),
                 ("trust_config_digest", "7"*64), ("normal_business_admission", False))
        for field, value in cases:
            with self.subTest(field=field):
                self.reject_fault("source_admission", field, value, "source|admission")

    def test_original_source_session_lease_and_admission_time(self):
        for field, value in (("session_expires_at", 900), ("session_issued_at", 901),
                             ("lease_expires_at", 900), ("lease_issued_at", 901), ("admitted_at", 901)):
            with self.subTest(field=field):
                self.reject_fault("source_admission", field, value, "source|admission")
        world = build_world()
        # Source credentials expired at 950; recovery began at 1000. That does
        # not invalidate the caller's source admission at 900 or later recovery.
        self.assertLess(world.objects["source_admission"]["session_expires_at"], world.objects["grant"]["issued_at"])
        self.validate_world(world)

    def test_valid_signature_ack_wrong_original_identity_request_and_candidates(self):
        for decision, override in (("COMMIT", False), ("ABORT", False), ("COMMIT", True)):
            for field, value in (("identity_digest", "1"*64), ("request_digest", "2"*64),
                                 ("source_decision_digest", "3"*64), ("commit_candidate_digest", "4"*64),
                                 ("abort_candidate_digest", "5"*64), ("operation_id", uid(999))):
                with self.subTest(decision=decision, override=override, field=field):
                    self.reject_fault("ack", field, value, "original Ack request/candidate/pin binding", decision=decision, override=override)

    def test_normal_authorization_exact_original_relations(self):
        cases = (("operation_id", uid(999)), ("local_commit_id", uid(998)), ("request_digest", "1"*64),
                 ("source_decision_digest", "2"*64), ("ack_digest", "3"*64), ("candidate_digest", "4"*64),
                 ("staging_evidence_digest", "5"*64), ("no_local_business_commit", True),
                 ("decision", "ABORT"))
        for field, value in cases:
            with self.subTest(field=field):
                self.reject_fault("authorization", field, value, "normal authorization original binding")
        self.reject_fault("authorization", "authorization_id", uid(15), "reuses source ID")
        self.reject_fault("authorization", "created_at", 1000, "precedes original Ack")

    def test_normal_proposal_exact_original_relations(self):
        for field, value in (("operation_id", uid(999)), ("local_commit_id", uid(998)),
                             ("source_decision_digest", "2"*64), ("staging_evidence_digest", "5"*64),
                             ("no_local_business_commit", True), ("created_at", 1201)):
            with self.subTest(field=field):
                self.reject_fault("proposal", field, value, "proposal original binding|proposal authorization time")

    def test_override_exact_scope_and_auth_content(self):
        cases = (("operation_id", uid(999)), ("request_digest", "1"*64), ("source_decision_digest", "2"*64),
                 ("supersedes_authorization_id", uid(998)), ("previous_authorization_digest", "3"*64),
                 ("identity_digest", "4"*64), ("scope_digest", "5"*64), ("abort_candidate_digest", "6"*64))
        for field, value in cases:
            with self.subTest(field=field):
                self.reject_fault("authorization", field, value, "operator ABORT scope mismatch", override=True)

    def test_override_expiry_at_original_proposal_fix_and_terminal(self):
        cases = ({"override_expires": 1200},
                 {"override_expires": 1250, "fix": 1250, "publication": 1260},
                 {"override_expires": 1300})
        for times in cases:
            with self.subTest(times=times):
                world = build_world(override=True, times=times)
                self.all_signatures_valid(world)
                with self.assertRaisesRegex(ContractError, "override interval at original"):
                    self.validate_world(world)

    def test_publication_input_original_three_fields_and_linked_hashes(self):
        for field, value in (("operation_id", uid(999)), ("request_digest", "1"*64), ("source_decision_digest", "2"*64)):
            for decision, override in (("COMMIT", False), ("ABORT", False), ("COMMIT", True)):
                with self.subTest(field=field, decision=decision, override=override):
                    world = build_world(decision=decision, override=override, faults={"publication_input": {field: value}})
                    self.all_signatures_valid(world)
                    snap = world.objects["publication_snapshot"]
                    self.assertEqual(snap["action_input_digest"], raw(world.objects["publication_input"]))
                    with self.assertRaisesRegex(ContractError, "publication action original source"):
                        self.validate_world(world)

    def test_historical_target_identity_operation_and_pin(self):
        for field, value in (("identity_digest", "1"*64), ("operation_id", uid(999)),
                             ("authority_pin_digest", "2"*64), ("storage_generation_id", uid(998)),
                             ("control_plane_generation_id", uid(997)), ("core_installation_id", uid(996))):
            with self.subTest(field=field):
                self.reject_fault("target", field, value, "permit issue target/checkpoints")

    def test_local_apply_target_cannot_differ_from_verified_issuance(self):
        for field, value in (("identity_digest", "1"*64), ("operation_id", uid(999)),
                             ("authority_pin_digest", "2"*64), ("storage_generation_id", uid(998)),
                             ("control_plane_generation_id", uid(997)), ("core_installation_id", uid(996))):
            with self.subTest(field=field):
                world = build_world(faults={"local_target": {field: value}})
                self.all_signatures_valid(world)
                self.assertEqual(world.objects["use_input"]["target_digest"], raw(world.objects["local_target"]))
                self.assertEqual(world.objects["completion"]["target_digest"], raw(world.objects["local_target"]))
                with self.assertRaisesRegex(ContractError, "historical APPLY full target differs"):
                    self.validate_world(world)

    def test_apply_selected_effect_result_audit_and_completion_exact_content(self):
        for field in ("effect_digest", "result_digest", "audit_record_digest"):
            with self.subTest(field=field):
                world = build_world(faults={"use_input": {field: "1"*64}, "completion": {field: "1"*64}})
                self.all_signatures_valid(world)
                self.assertEqual(world.objects["completion"]["local_use_digest"], raw(world.objects["use_snapshot"]))
                with self.assertRaisesRegex(ContractError, "historical APPLY selected terminal content"):
                    self.validate_world(world)
                self.reject_fault("completion", field, "2"*64, "completion exact use binding")

    def test_signed_terminal_selected_content_and_original_execution(self):
        for field in ("effect_digest", "result_digest", "audit_candidate_digest", "candidate_digest", "identity_digest"):
            with self.subTest(field=field):
                self.reject_fault("receipt", field, "1"*64, "terminal binding mismatch")
        for field in ("fix_execution_digest", "terminal_execution_digest"):
            self.reject_fault("receipt", field, "2"*64, "receipt execution positions")

    def test_permit_issuer_principal_is_actual_historical_session(self):
        self.reject_fault("permit", "runtime_principal", "claimed-foreign-core", "issuance actual admitted principal")
        self.reject_fault("permit", "session_id", uid(999), "subject did not exist")
        self.reject_fault("permit_issuance", "runtime_principal", "claimed-foreign-core", "issuance subject/input differs")

    def test_signed_permit_and_grant_bounded_issuance_deadline(self):
        self.reject_fault("permit", "expires_at", 40000, "issuance bounded deadline")
        self.reject_fault("grant", "expires_at", 31000, "grant lease deadline")
        self.reject_fault("grant", "lease_generation", 2, "issuance lease mapping")

    def test_action_and_issuance_use_their_original_prefix(self):
        self.reject_fault("grant", "issued_at", 500, "registry time backdating")
        self.reject_fault("prepare", "checked_at", 1101, "execution event position/action/time")
        self.reject_fault("terminal", "session_id", uid(999), "subject did not exist")
        self.reject_fault("use_snapshot", "session_id", uid(999), "subject did not exist")
        world = build_world(times={"permit_expires": 2500})
        self.all_signatures_valid(world)
        with self.assertRaisesRegex(ContractError, "first use conservative deadline"):
            self.validate_world(world)
        world = build_world(times={"permit_expires": 2501})
        self.validate_world(world)

    def test_later_revocation_and_expiry_preserve_original_history(self):
        for decision, override in (("COMMIT", False), ("ABORT", False), ("COMMIT", True)):
            with self.subTest(decision=decision, override=override):
                world = build_world(decision=decision, override=override)
                before = self.validate_world(world)
                for kind, name in (("POLICY_REVOKE", "policy"), ("SESSION_REVOKE", "session"),
                                   ("LEASE_REVOKE", "lease"), ("GRANT_REVOKE", "grant"), ("PERMIT_REVOKE", "permit")):
                    original = world.objects[name]
                    digest = h2(original) if "type" in original else raw(original)
                    event(world.authority, kind, 200000, record("revocation", history_version=2, object_digest=digest))
                event(world.core, "LOCAL_SESSION_REVOKE", 200000,
                      record("revocation", history_version=2, object_digest=raw(world.objects["session"])))
                result = self.validate_world(world)
                self.assertEqual(before, result)
                self.assertEqual(result.current_eligibility, "NOT_EVALUATED")

    def test_policy_and_inventory_same_id_different_content_rejected(self):
        for name, kind, field, changed in (("policy", "POLICY_REGISTER", "expires_at", 90000),
                                           ("inventory", "INVENTORY_ACCEPT", "entries", [])):
            with self.subTest(name=name):
                world = build_world()
                conflict = deepcopy(world.objects[name]); conflict[field] = changed
                if name == "policy":
                    world.sign(conflict)
                    verify_signed(conflict, world.trust)
                event(world.authority, kind, 1600, conflict)
                self.all_signatures_valid(world)
                with self.assertRaisesRegex(ContractError, "immutable " + name + " ID content conflict"):
                    self.validate_world(world)

    def test_exact_repeat_registration_is_idempotent_and_does_not_reactivate(self):
        world = build_world()
        for name, kind in (("policy", "POLICY_REGISTER"), ("inventory", "INVENTORY_ACCEPT")):
            event(world.authority, kind, 1600, world.objects[name])
        self.validate_world(world)
        event(world.authority, "POLICY_REVOKE", 1700,
              record("revocation", history_version=2, object_digest=h2(world.objects["policy"])))
        event(world.authority, "POLICY_REGISTER", 1800, world.objects["policy"])
        self.validate_world(world)  # A repeat does not invalidate old events.
        renewed = deepcopy(world.objects["session"])
        renewed.update(session_id=uid(998), issued_at=1800)
        event(world.authority, "SESSION_CREATE", 1800, renewed)
        with self.assertRaisesRegex(ContractError, "session created without current policy"):
            self.validate_world(world)

    def test_same_millisecond_has_strict_event_order(self):
        names = ("register", "grant", "prepare", "observe", "proposal", "fix", "publication", "terminal", "permit", "permit_observe", "apply")
        world = build_world(times=dict.fromkeys(names, 1000))
        self.validate_world(world)
        prefix = deepcopy(world.authority)
        prefix["events"] = prefix["events"][:4]
        prefix["events"][2], prefix["events"][3] = prefix["events"][3], prefix["events"][2]
        for index, value in enumerate(prefix["events"], 1):
            value["position"]["event_sequence"] = index
        evidence = replace(world.evidence(), authority_history=c2(prefix), core_histories=())
        with self.assertRaisesRegex(ContractError, "inventory missing active source"):
            self.validate_world(world, "REGISTRY_RELATIONS", evidence)

    def test_session_creation_prefix_binds_original_policy_before_any_grant(self):
        for field, value in (("identity_digest", "1"*64), ("core_installation_id", uid(999)),
                             ("runtime_principal", "another-core"), ("purpose", "LIFECYCLE_OPENING")):
            with self.subTest(field=field):
                world = build_world(faults={"enrollment": {field: value}})
                self.all_signatures_valid(world)
                prefix = deepcopy(world.authority)
                prefix["events"] = prefix["events"][:3]  # FENCES, POLICY, SESSION only.
                evidence = replace(world.evidence(), authority_history=c2(prefix), core_histories=())
                with self.assertRaisesRegex(ContractError, "session enrollment differs from its original policy target"):
                    self.validate_world(world, "REGISTRY_RELATIONS", evidence)

    def test_restore_assertion_cannot_supply_production_qualification(self):
        # A caller's claimed restore status without the required source/context
        # is never ordinary production qualification. Actual restore admission
        # remains unsupported by this slice and is tested below separately.
        world = build_world(faults={"enrollment": {"context_kind": "MANUAL_RESTORE_ADMITTED"}})
        self.all_signatures_valid(world)
        with self.assertRaisesRegex(MissingTrustedContext, "restore history"):
            self.validate_world(world)

    def test_signed_restore_context_requires_complete_source_archive(self):
        world = build_world()
        scope = world.request["intent"]["scope"]
        source = obj("source_snapshot", source_kind="V2_GENERATION_RESTORE", identity=world.request["intent"]["identity"],
                     source_authority_domain_id=world.pin["authority_domain_id"], source_authority_instance_id=world.pin["authority_instance_id"],
                     source_authority_generation=1, authority_tip=world.objects["after"]["authority_ref"], audit_tip=world.objects["after"]["audit_ref"],
                     state_version=5, owner_identity=scope["actor_identity"], owner_version=1, continuity_epoch=1,
                     storage_generation_id=scope["storage_generation_id"], control_plane_generation_id=scope["control_plane_generation_id"],
                     signed_origin_digest="1"*64, history_archive_digest="2"*64, operation_inventory_digest="3"*64,
                     source_deployment_digest="4"*64, source_fencing_evidence_digest="5"*64, captured_at=1600)
        context = obj("restoration_context", context_id=uid(800), identity=world.request["intent"]["identity"], source_snapshot=source,
                      target_core_installation_id=uid(801), target_storage_generation_id=uid(802), target_control_plane_generation_id=uid(803),
                      target_authority_pin_digest=h2(world.pin), restore_start_checkpoint=world.objects["before"], restore_source_state_digest="6"*64,
                      allowed_actions=["APPLY_VERIFIED_TERMINAL", "VERIFY_HISTORY"], issued_at=1700, expires_at=30000,
                      reason="Synthetic restore context without original archive", operator_root_key_id=world.pin["operator_root_key_id"], root_signature="0"*128)
        world.sign(context)
        verify_signed(context, world.trust)
        evidence = replace(world.evidence(), context_wires=(c2(context),))
        for operation in ("REGISTRY_RELATIONS", "TERMINAL_HISTORY", "COMPLETION_HISTORY"):
            with self.subTest(operation=operation), self.assertRaisesRegex(MissingTrustedContext, "restore|restoration"):
                self.validate_world(world, operation, evidence)

    def test_same_operation_id_different_request_content(self):
        world = build_world()
        other = build_world(decision="ABORT")
        evidence = replace(world.evidence(), request_wires=(c2(world.request), c2(other.request)))
        # Pin fields and keys do not alter source request; both have the same
        # operation identity but distinct valid intent/source/branch content.
        with self.assertRaisesRegex(ContractError, "same operation ID with different canonical content"):
            self.validate_world(world, evidence=evidence)

    def test_second_terminal_even_resigned_cannot_replace_original(self):
        world = build_world(complete=False)
        snap = deepcopy(world.objects["terminal"])
        snap.update(position=position(world.authority), checked_at=1400)
        receipt = deepcopy(world.objects["receipt"])
        receipt.update(terminal_execution_digest=raw(snap), decided_at=1400)
        world.sign(receipt)
        event(world.authority, "TERMINAL", 1400, snap, receipt)
        self.all_signatures_valid(world)
        with self.assertRaisesRegex(ContractError, "execution fences differ|execution phase differs|second terminal"):
            self.validate_world(world, "TERMINAL_HISTORY")

    def test_second_local_apply_is_not_an_idempotent_new_consume(self):
        world = build_world()
        snap = deepcopy(world.objects["use_snapshot"])
        snap.update(position=position(world.core), checked_at=1600)
        completion = deepcopy(world.objects["completion"])
        completion.update(position=position(world.core), completed_at=1600, local_use_digest=raw(snap))
        event(world.core, "APPLY", 1600, snap, completion)
        with self.assertRaisesRegex(ContractError, "second local consume"):
            self.validate_world(world)

    def test_missing_original_bytes_and_publication_fail_closed(self):
        world = build_world()
        del world.authority["records"][raw(world.objects["fix"])]
        with self.assertRaisesRegex(ContractError, "missing registry input"):
            self.validate_world(world)
        world = build_world(complete=False)
        evidence = replace(world.evidence(), core_histories=())
        with self.assertRaises(ContractError):
            self.validate_world(world, "TERMINAL_HISTORY", evidence)

    def test_unsupported_operations_and_missing_trust_never_authorize(self):
        world = build_world()
        for operation in ("TRUSTED_HISTORY", "QUERY_EXISTING", "CURRENT_ELIGIBILITY", "ADMIT_SOURCE", "RESTORE_ADMISSION", "ACTIVE", "ADMITTED"):
            with self.subTest(operation=operation), self.assertRaises(MissingTrustedContext):
                self.validate_world(world, operation)
        for operation in ("PREPARE_EXISTING", "FIX_ORIGINAL_DISPATCH", "TERMINATE_ORIGINAL", "APPLY_VERIFIED_TERMINAL", "ISSUE_GRANT", "ISSUE_PERMIT", "OPENING_HISTORY", "", None, True):
            with self.subTest(operation=operation), self.assertRaises(UnsupportedOperation):
                self.validate_world(world, operation)
        for trust in (None, {}, world.pin, True):
            with self.subTest(trust_type=type(trust).__name__), self.assertRaises(MissingTrustedContext):
                validate_evidence("COMPLETION_HISTORY", world.evidence(), trust, (world.deployment,))

    def test_caller_claims_and_malformed_source_inputs_fail_closed(self):
        world = build_world()
        for evidence in (None, {}, True, {"history_origin": "ADMITTED"}):
            with self.subTest(type=type(evidence).__name__), self.assertRaises(ContractError):
                validate_evidence("REGISTRY_RELATIONS", evidence, world.trust, (world.deployment,))
        for raw_wire in (b"{}", b"[]", b'{"header":null}', b' {"header":null}', b'{"header":null,"header":null}'):
            with self.subTest(raw=raw_wire), self.assertRaises(ContractError):
                self.validate_world(world, evidence=replace(world.evidence(), authority_history=raw_wire))
        with self.assertRaisesRegex(ContractError, "missing deployment"):
            validate_evidence("COMPLETION_HISTORY", world.evidence(), world.trust, ())

    def test_validation_has_no_io_or_input_mutation(self):
        world = build_world()
        evidence = world.evidence()
        before = (c2(world.request), c2(world.authority), c2(world.core), world.trust.pin_wire)
        def denied(*args, **kwargs):
            raise AssertionError("validation attempted an I/O boundary")
        with patch("builtins.open", denied), patch("os.open", denied), patch("socket.socket", denied), patch("subprocess.Popen", denied):
            result = self.validate_world(world, evidence=evidence)
        self.assertEqual(result.history_origin, "UNVERIFIED")
        self.assertEqual(before, (c2(world.request), c2(world.authority), c2(world.core), world.trust.pin_wire))
        self.assertEqual(evidence, world.evidence())


if __name__ == "__main__":
    unittest.main(verbosity=2)
