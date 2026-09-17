"""Original provisioning format helper tests; no provisioning or real I/O."""
from dataclasses import replace
import hashlib
import json
import unittest

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.control_plane._r1_validation_legacy import verify_origin
from app.control_plane.r1_validation_codec import ContractError, c2
from app.control_plane.r1_validation_crypto import FixedTrust
from tests.r1_validation_legacy_fixtures import make_origin, build_legacy_source


class OriginalOriginTests(unittest.TestCase):
    def setUp(self):
        self.root = Ed25519PrivateKey.generate()
        self.receipt = Ed25519PrivateKey.generate()
        root_raw = self.root.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        receipt_raw = self.receipt.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.pin = dict(type="authority_pin", version=2, authority_domain_id="20000000-0000-0000-0000-000000000001",
                        authority_instance_id="20000000-0000-0000-0000-000000000002", authority_generation=1,
                        receipt_public_key=receipt_raw.hex(), receipt_key_id=hashlib.sha256(receipt_raw).hexdigest(),
                        api_version=1, https_origin="https://authority.example.test", server_spki_sha256="a" * 64,
                        operator_root_key_id=hashlib.sha256(root_raw).hexdigest())
        self.trust = FixedTrust(c2(self.pin), root_raw)
        self.raw, self.observed = make_origin(self.root, self.trust)

    def resign(self, changed, field):
        body = {k: v for k, v in changed[field].items() if k != "signature"}
        prefix = b"QINGYU-CP-R1-PROVISIONING-" + field.upper().encode() + b"\0"
        changed[field]["signature"] = self.root.sign(prefix + rfc8785.dumps(body)).hex()
        return rfc8785.dumps(changed)

    def test_real_both_envelopes_original_domain_and_independent_observations(self):
        result = verify_origin(self.raw, self.trust, self.observed)
        self.assertEqual(result.digest, hashlib.sha256(b"QINGYU-CP-R1-PROVISIONING-ORIGIN\0" + self.raw).hexdigest())
        self.assertEqual(result.observation_status, "CONSISTENT_WITH_SUPPLIED_OBSERVATIONS")
        self.assertEqual(result.completion["receipt_key_id"], self.pin["receipt_key_id"])
        self.assertEqual(verify_origin(self.raw, self.trust).observation_status, "NOT_PROVIDED")
        self.assertNotEqual(result.digest, hashlib.sha256(self.raw).hexdigest())
        with self.assertRaises(TypeError):
            result.intent["authority_generation"] = 9

    def test_missing_signature_version_and_malformed_original_bytes(self):
        for field in ("intent", "completion"):
            for mutation in ("placeholder", "wrong_version", "wrong_role_domain"):
                value = json.loads(self.raw)
                if mutation == "placeholder":
                    value[field]["signature"] = "a5" * 64
                elif mutation == "wrong_version":
                    value[field]["version"] = 1
                    value = json.loads(self.resign(value, field))
                else:
                    body = {k: v for k, v in value[field].items() if k != "signature"}
                    value[field]["signature"] = self.root.sign(b"QINGYU-R1-SCOPED-SIGN-V2/recovery_policy\0" + c2(body)).hex()
                with self.subTest(field=field, mutation=mutation), self.assertRaises(ContractError):
                    verify_origin(rfc8785.dumps(value), self.trust, self.observed)
        for wire in (b" " + self.raw, self.raw + b"\n", b'{"intent":null,"completion":null}', self.raw[:-1]):
            with self.assertRaises(ContractError):
                verify_origin(wire, self.trust)

    def test_valid_resigned_wrong_intent_completion_relation_rejected(self):
        value = json.loads(self.raw)
        value["completion"]["payload"]["initial_migration_artifact_digest"] = "f" * 64
        with self.assertRaises(ContractError):
            verify_origin(self.resign(value, "completion"), self.trust, self.observed)

    def test_separately_supplied_observation_mismatch_is_not_self_certified(self):
        for changed in (replace(self.observed, database_oid=999),
                        replace(self.observed, external_storage_identity="30000000-0000-0000-0000-000000000001"),
                        replace(self.observed, observed_tls_origin="https://different.example.test")):
            with self.assertRaises(ContractError):
                verify_origin(self.raw, self.trust, changed)
        with self.assertRaises(ContractError):
            verify_origin(self.raw, self.trust, {"verified": True})

    def test_correct_signatures_cannot_change_fixed_domain_key_or_tls(self):
        for change in ({"authority_domain_id": "30000000-0000-0000-0000-000000000001"},
                       {"authority_instance_id": "30000000-0000-0000-0000-000000000002"},
                       {"https_origin": "https://different.example.test"}):
            trust = FixedTrust(c2({**self.pin, **change}), self.trust.root_public_key)
            with self.assertRaises(ContractError):
                verify_origin(self.raw, trust, self.observed)
        other = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        trust = FixedTrust(c2({**self.pin, "operator_root_key_id": hashlib.sha256(other).hexdigest()}), other)
        with self.assertRaises(ContractError):
            verify_origin(self.raw, trust, self.observed)

    def test_later_generation_retains_initial_origin_without_claiming_opening_chain(self):
        later_pin = {**self.pin, "authority_generation": 2,
                     "authority_instance_id": "40000000-0000-0000-0000-000000000001"}
        trust = FixedTrust(c2(later_pin), self.trust.root_public_key)
        result = verify_origin(self.raw, trust, self.observed)
        self.assertEqual(result.intent["authority_generation"], 1)
        self.assertEqual(result.intent["authority_instance_id"], self.pin["authority_instance_id"])
        self.assertFalse(hasattr(result, "opening_chain_valid"))


class ActualLegacySourceTests(unittest.TestCase):
    def check(self, world, source=None, trust=None):
        from app.control_plane.r1_validation import validate_source_evidence
        return validate_source_evidence(source or world.source, trust or world.trust, world.deployments)

    def repack(self, source, transform):
        """Recompute all archive/snapshot hashes after a deliberate raw change."""
        from app.control_plane.r1_validation import ArchiveMember
        from app.control_plane.r1_validation_codec import obj, h2, sha
        members = tuple(transform(list(source.members)))
        members = tuple(sorted(members, key=lambda m:(m.role,m.index)))
        manifest = obj("archive_manifest", entries=[{"role": m.role, "index":m.index,
            "byte_length":len(m.raw), "sha256":sha(m.raw)} for m in members])
        snapshot = json.loads(source.snapshot_wire)
        snapshot["history_archive_digest"] = h2(manifest)
        return replace(source, members=members, manifest_wire=c2(manifest), snapshot_wire=c2(snapshot))

    def test_public_source_preserves_real_v1_chains_for_different_identities_and_lengths(self):
        for offset, decisions in ((0, ()), (2000, ("COMMIT",)), (6000, ("ABORT", "COMMIT", "ABORT")),
                                  (9000, ("COMMIT", "ABORT", "COMMIT", "COMMIT", "ABORT", "COMMIT"))):
            with self.subTest(offset=offset, decisions=decisions):
                world = build_legacy_source(decisions, offset=offset)
                original = tuple(m.raw for m in world.source.members)
                result = self.check(world)
                tail = json.loads(result.verified_checkpoint_wire)
                self.assertEqual(tail["state_version"], 1 + decisions.count("COMMIT"))
                self.assertEqual(tail["authority_ref"]["authority_sequence"], len(decisions)+1)
                self.assertEqual(tail["audit_ref"]["audit_sequence"], len(decisions)+1)
                self.assertEqual(tail["authority_ref"]["wire_version"], 1)
                self.assertEqual(tail["audit_ref"]["wire_version"], 1)
                self.assertEqual(result.terminal_checkpoint_wire, result.verified_checkpoint_wire)
                self.assertEqual((result.profile, result.history_origin, result.environment_origin, result.current_eligibility),
                                 ("ALIGNED_OPENING", "UNVERIFIED", "NOT_OBSERVED", "NOT_EVALUATED"))
                self.assertEqual(original, tuple(m.raw for m in world.source.members))
                # Independent literal CoreJSON/JCS distinction is present in
                # actual source members; no Scoped V2 C2 reinterpretation.
                if decisions:
                    candidate = next(m.raw for m in world.source.members if m.role=="AUDIT_CANDIDATE")
                    self.assertIn(b'"operation_type":"GOVERNED_MUTATION"', candidate)
                    request = next(m.raw for m in world.source.members if m.role=="REQUEST" and b'"operation_type":"MUTATION"' in m.raw)
                    self.assertIn('晴雨'.encode(), request)
                    self.assertIn(b'1e-7', request)

    def test_explicit_genesis_intent_attestation_and_original_result_are_required(self):
        world = build_legacy_source()
        legacy = world.source.legacy
        cases = [replace(world.source, legacy=None),
                 replace(world.source, restoration_evidence=(object(),)),
                 replace(world.source, legacy=replace(legacy, expected_intent=replace(legacy.expected_intent, staged_result_hash="f"*64))),
                 replace(world.source, legacy=replace(legacy, result_wire=b'{}')),
                 replace(world.source, legacy=replace(legacy, attestation_wire=b'{}')),
                 replace(world.source, observed_origin=None),
                 replace(world.source, source_deployment_observation=None),
                 replace(world.source, source_fencing_observation=None)]
        for index, source in enumerate(cases):
            with self.subTest(index=index), self.assertRaises(ContractError): self.check(world, source)

    def test_valid_resigned_genesis_audit_semantics_do_not_follow_self_consistent_hashes(self):
        changes = ({"state_version":8}, {"operation_type":"GOVERNED_MUTATION"}, {"result_code":"ABORTED"},
                   {"capability":"read_only"}, {"mutation_id":"not-genesis"})
        for change in changes:
            def fault(name, value):
                if name=="genesis_audit": value.update(change)
            with self.subTest(change=change), self.assertRaises(ContractError): self.check(build_legacy_source(fault=fault))

    def test_true_signed_recomputed_mutation_relations_rejected(self):
        cases = [("request", {"qingyu_identity_id":"99999999-0000-0000-0000-000000000001"}),
                 ("request", {"expected_state_version":19}),
                 ("candidate_COMMITTED", {"payload_hash":"f"*64}),
                 ("candidate_ABORTED", {"state_version":9}),
                 ("receipt", {"owner_version":9}),
                 ("ack", {"core_audit_candidate_hash":"f"*64}),
                 ("authorization", {"transaction_evidence_hash":"f"*64})]
        for phase, change in cases:
            def fault(name, value):
                if name==phase and (phase not in ("receipt","ack") or value["operation_type"]=="MUTATION"):
                    value.update(change)
            with self.subTest(phase=phase, change=change), self.assertRaises(ContractError):
                self.check(build_legacy_source(("COMMIT",), fault=fault))

    def test_manifest_self_consistent_missing_extra_and_profile_members_rejected(self):
        from app.control_plane.r1_validation import ArchiveMember
        world = build_legacy_source()
        for role in ("SOURCE_ADMISSION", "SOURCE_REQUEST", "AUDIT_CANDIDATE", "PREPARE_ACK", "STAGED_EVIDENCE", "CORE_AUDIT"):
            changed = self.repack(world.source, lambda rows:[m for m in rows if m.role!=role])
            with self.subTest(role=role), self.assertRaises(ContractError): self.check(world, changed)
        changed = self.repack(world.source, lambda rows:rows+[ArchiveMember("SOURCE_ADMISSION",99,b'{}')])
        with self.assertRaises(ContractError): self.check(world, changed)
        def change_profile(rows):
            result=[]
            for member in rows:
                if member.role=="SOURCE_PROFILE":
                    value=json.loads(member.raw); value["profile"]="HISTORY_ONLY_TAIL"
                    member=replace(member,raw=c2(value))
                result.append(member)
            return result
        with self.assertRaises(ContractError): self.check(world,self.repack(world.source,change_profile))

    def test_source_capture_must_include_original_iso_timestamps(self):
        world=build_legacy_source()
        value=json.loads(world.source.snapshot_wire); value["captured_at"]=1
        source=replace(world.source,snapshot_wire=c2(value),
                       source_fencing_observation=replace(world.source.source_fencing_observation,observed_at=1))
        with self.assertRaisesRegex(ContractError,"postdates source capture"): self.check(world,source)
        for stamp in ("2026-09-13T00:01:01", "2030-01-01T00:00:00Z", "2026-09-12T00:00:00Z"):
            def fault(name,value):
                if name=="receipt" and value["operation_type"]=="MUTATION": value["decided_at"]=stamp
            with self.subTest(stamp=stamp),self.assertRaises(ContractError): self.check(build_legacy_source(fault=fault))

    def test_independent_boundary_and_fixed_keys_cannot_be_replaced_by_archive(self):
        world=build_legacy_source()
        after=json.loads(world.source.chain_boundary.expected_end_checkpoint_wire)
        after["authority_ref"]["receipt_hash"]="f"*64
        boundary=replace(world.source.chain_boundary,expected_end_checkpoint_wire=c2(after))
        with self.assertRaises(ContractError): self.check(world,replace(world.source,chain_boundary=boundary))
        before=json.loads(world.source.chain_boundary.start_checkpoint_wire)
        before["audit_ref"]["audit_hash"]="e"*64
        with self.assertRaises(ContractError): self.check(world,replace(world.source,chain_boundary=replace(world.source.chain_boundary,start_checkpoint_wire=c2(before))))
        other=Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
        trust=FixedTrust(c2({**world.pin,"operator_root_key_id":hashlib.sha256(other).hexdigest()}),other)
        with self.assertRaises(ContractError): self.check(world,trust=trust)

    def test_resource_bound_rejects_more_than_64_original_mutations(self):
        with self.assertRaisesRegex(ContractError,"bounded V1 source operation count"):
            self.check(build_legacy_source(("ABORT",)*65))


if __name__ == "__main__":
    unittest.main()
