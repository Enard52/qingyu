"""Pure unit tests: ephemeral in-memory Ed25519 keys, no I/O adapters.

The objects below are independent schema-shaped signing fixtures, not assertions
of complete semantic history.  They do not import the evidence reference or V1.
Run with unittest discovery to avoid pytest's database-oriented conftest.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
import hashlib
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.control_plane.r1_validation_codec import ContractError, s2
from app.control_plane.r1_validation_crypto import FixedTrust, verify_signed


U = "00000000-0000-0000-0000-000000000001"
V = "00000000-0000-0000-0000-000000000002"
H = "11" * 32
J = "22" * 32
PLACEHOLDER = "a5" * 64
ROOT_TYPES = {"abort_override", "opening_authorization", "recovery_policy", "restoration_context"}
RECEIPT_TYPES = {"execution_grant", "local_finish_permit", "opening_prepare", "opening_receipt", "prepare_ack", "terminal_receipt"}


def independent_json(value):
    # All fixtures contain scalar Unicode and safe integers.  This independent
    # stdlib encoder covers that subset without using product C2/S2 as an oracle.
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def independent_s2(value):
    signature = "root_signature" if value["type"] in ROOT_TYPES else "receipt_signature"
    body = {name: item for name, item in value.items() if name != signature}
    return b"QINGYU-R1-SCOPED-SIGN-V2/" + value["type"].encode("ascii") + b"\0" + independent_json(body)


def typed(name, **fields):
    return {"type": name, "version": 2, **fields}


def hashes(names):
    return {name: H for name in names.split()}


def ids(names):
    return {name: U for name in names.split()}


def fixtures(root_id, receipt_id):
    """Field lists transcribed from the accepted catalog, not product SCHEMA."""
    identity = typed("identity", **ids("qingyu_identity_id continuity_id genesis_operation_id"))
    authority_ref = typed("authority_ref", wire_version=2, authority_generation=1, authority_sequence=0, receipt_hash=H)
    audit_ref = typed("audit_ref", wire_version=2, audit_sequence=0, audit_hash=H)
    checkpoint = typed("local_checkpoint", state_version=0, audit_ref=audit_ref, authority_ref=authority_ref)
    authority = {**ids("authority_domain_id authority_instance_id"), "authority_generation": 1}
    target_authority = {**ids("target_authority_domain_id target_authority_instance_id"), "target_authority_generation": 1}
    root = {"operator_root_key_id": root_id, "root_signature": PLACEHOLDER}
    receipt = {"receipt_key_id": receipt_id, "receipt_signature": PLACEHOLDER}
    interval = {"issued_at": 10, "expires_at": 20}
    source = typed("source_snapshot", source_kind="V2_GENERATION_RESTORE", identity=identity,
                   **ids("source_authority_domain_id source_authority_instance_id"), source_authority_generation=1,
                   authority_tip=authority_ref, audit_tip=audit_ref, state_version=0, owner_identity="owner",
                   owner_version=1, continuity_epoch=1, **ids("storage_generation_id control_plane_generation_id"),
                   **hashes("signed_origin_digest history_archive_digest operation_inventory_digest source_deployment_digest source_fencing_evidence_digest"),
                   captured_at=5)
    values = [
        typed("abort_override", **ids("override_id operation_id supersedes_authorization_id"),
              **hashes("request_digest source_decision_digest previous_authorization_digest identity_digest scope_digest abort_candidate_digest"),
              authorized_decision="ABORT", reason="test \u96ea \U0001f642", **interval, **root),
        typed("recovery_policy", **ids("policy_id continuity_id qingyu_identity_id genesis_operation_id core_installation_id storage_generation_id control_plane_generation_id"),
              **authority, **hashes("deployment_admission_digest component_artifact_digest trust_config_digest"),
              runtime_principal="recovery", restoration_context_digest=None,
              capabilities=["QUERY_EXISTING"], allowed_operation_type="MUTATION", **interval, **root),
        typed("restoration_context", context_id=U, identity=identity, source_snapshot=source,
              **ids("target_core_installation_id target_storage_generation_id target_control_plane_generation_id"),
              **hashes("target_authority_pin_digest restore_source_state_digest"), restore_start_checkpoint=checkpoint,
              allowed_actions=["APPLY_VERIFIED_TERMINAL", "VERIFY_HISTORY"], reason="test", **interval, **root),
        typed("opening_authorization", opening_id=U, opening_kind="NEW_GENESIS", identity=identity,
              source_snapshot=None, **target_authority, **ids("target_storage_generation_id target_control_plane_generation_id core_installation_id"),
              initializer_principal="initializer", **hashes("initializer_artifact_digest signed_origin_digest deployment_admission_digest trust_config_digest"),
              initial_or_current_owner_identity="owner", owner_version=1, continuity_epoch=1, state_version=0,
              receipt_key_id=receipt_id, tls_origin="https://authority.example.test", tls_spki_sha256=J,
              reason="test", **interval, **root),
        typed("execution_grant", contract_revision=2,
              **ids("grant_id operation_id continuity_id qingyu_identity_id genesis_operation_id storage_generation_id control_plane_generation_id session_id lease_id"),
              grant_sequence=1, **hashes("policy_digest inventory_digest request_digest source_decision_digest issuance_digest"),
              **authority, owner_identity="owner", owner_version=1, continuity_epoch=1, expected_state_version=0,
              runtime_principal="recovery", lease_generation=1, **interval, **receipt),
        typed("local_finish_permit", contract_revision=2, **ids("permit_id core_installation_id session_id operation_id"),
              permit_sequence=1, **hashes("policy_digest inventory_digest request_digest source_decision_digest terminal_digest issuance_digest"),
              restoration_context_digest=None, runtime_principal="recovery", before_checkpoint=checkpoint,
              after_checkpoint=deepcopy(checkpoint), **interval, **receipt),
        typed("opening_prepare", opening_id=U,
              **hashes("opening_authorization_digest audit_candidate_digest"), genesis_attempt_digest=H,
              **target_authority, prepared_at=11, **receipt),
        typed("opening_receipt", opening_id=U, opening_kind="NEW_GENESIS",
              **hashes("identity_digest opening_authorization_digest opening_prepare_digest audit_candidate_digest"),
              source_snapshot_digest=None, **authority, authority_sequence=1, previous_authority_ref=authority_ref,
              state_version=0, owner_identity="owner", owner_version=1, continuity_epoch=1, decided_at=12, **receipt),
        typed("prepare_ack", contract_revision=2, **authority, operation_id=U,
              **hashes("identity_digest request_digest source_decision_digest commit_candidate_digest abort_candidate_digest prepare_execution_grant_digest prepare_execution_digest"),
              authority_predecessor=authority_ref, prepared_at=11, **receipt),
        typed("terminal_receipt", contract_revision=2, **authority, operation_id=U, operation_type="MUTATION",
              **hashes("identity_digest request_digest source_decision_digest ack_digest semantic_authorization_digest execution_grant_digest candidate_digest effect_digest result_digest audit_candidate_digest fix_execution_digest terminal_execution_digest"),
              authorization_kind="NORMAL", decision="COMMIT", result_state="COMMITTED", state_before=0,
              state_after=1, audit_sequence=1, authority_sequence=1, previous_authority_ref=authority_ref,
              decided_at=12, **receipt),
    ]
    return {value["type"]: value for value in values}


class R1ValidationCryptoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Keys stay in process memory.  No private serialization, logging or file.
        cls.root_key = Ed25519PrivateKey.generate()
        cls.receipt_key = Ed25519PrivateKey.generate()
        cls.other_key = Ed25519PrivateKey.generate()
        cls.root_public = cls.root_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        cls.receipt_public = cls.receipt_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        cls.root_id = hashlib.sha256(cls.root_public).hexdigest()
        cls.receipt_id = hashlib.sha256(cls.receipt_public).hexdigest()
        cls.pin = typed("authority_pin", authority_domain_id=U, authority_instance_id=V, authority_generation=1,
                        receipt_public_key=cls.receipt_public.hex(), receipt_key_id=cls.receipt_id, api_version=2,
                        https_origin="https://authority.example.test", server_spki_sha256=J, operator_root_key_id=cls.root_id)
        cls.trust = FixedTrust(independent_json(cls.pin), cls.root_public)
        cls.objects = fixtures(cls.root_id, cls.receipt_id)

    def sign(self, value, key=None, preimage=None):
        signed = deepcopy(value)
        root = signed["type"] in ROOT_TYPES
        key = key or (self.root_key if root else self.receipt_key)
        signed["root_signature" if root else "receipt_signature"] = key.sign(
            independent_s2(signed) if preimage is None else preimage).hex()
        return signed

    def test_all_ten_types_real_signatures_and_independent_bytes(self):
        self.assertEqual(set(self.objects), ROOT_TYPES | RECEIPT_TYPES)
        for name, value in self.objects.items():
            with self.subTest(name=name):
                signed = self.sign(value)
                before = deepcopy(signed)
                self.assertEqual(s2(signed), independent_s2(signed))
                expected_digest = hashlib.sha256(b"QINGYU-R1-SCOPED-V2/" + name.encode("ascii") + b"\0" + independent_json(signed)).hexdigest()
                for representation in (signed, independent_json(signed)):
                    result = verify_signed(representation, self.trust)
                    self.assertEqual(result.object_type, name)
                    self.assertEqual(result.signer_role, "ROOT" if name in ROOT_TYPES else "RECEIPT")
                    self.assertEqual(result.key_id, self.root_id if name in ROOT_TYPES else self.receipt_id)
                    self.assertEqual(result.object_digest, expected_digest)
                    self.assertEqual(result.signing_input_digest, hashlib.sha256(independent_s2(signed)).hexdigest())
                self.assertEqual(signed, before)

    def test_literal_signing_bytes(self):
        value = self.objects["abort_override"]
        expected = (
            b'QINGYU-R1-SCOPED-SIGN-V2/abort_override\0{"abort_candidate_digest":"' + H.encode() +
            b'","authorized_decision":"ABORT","expires_at":20,"identity_digest":"' + H.encode() +
            b'","issued_at":10,"operation_id":"' + U.encode() + b'","operator_root_key_id":"' + self.root_id.encode() +
            b'","override_id":"' + U.encode() + b'","previous_authorization_digest":"' + H.encode() +
            b'","reason":"test \\u96ea \\ud83d\\ude42","request_digest":"' + H.encode() +
            b'","scope_digest":"' + H.encode() + b'","source_decision_digest":"' + H.encode() +
            b'","supersedes_authorization_id":"' + U.encode() + b'","type":"abort_override","version":2}'
        )
        self.assertEqual(s2(value), expected)
        self.assertEqual(independent_s2(value), expected)
        verify_signed(self.sign(value, preimage=expected), self.trust)

    def test_placeholder_zero_and_corrupted_signatures_rejected_for_every_type(self):
        for name, value in self.objects.items():
            field = "root_signature" if name in ROOT_TYPES else "receipt_signature"
            signed = self.sign(value)
            for signature in (PLACEHOLDER, "00" * 64, (bytes([int(signed[field][:2], 16) ^ 1]) + bytes.fromhex(signed[field][2:])).hex()):
                with self.subTest(name=name, kind=signature[:2]):
                    changed = {**signed, field: signature}
                    before = deepcopy(changed)
                    with self.assertRaisesRegex(ContractError, "invalid V2 Ed25519 signature"):
                        verify_signed(changed, self.trust)
                    self.assertEqual(changed, before)

    def test_wrong_key_and_cross_role_signatures_rejected_for_every_type(self):
        for name, value in self.objects.items():
            wrong_role_key = self.receipt_key if name in ROOT_TYPES else self.root_key
            for key in (wrong_role_key, self.other_key):
                with self.subTest(name=name):
                    with self.assertRaisesRegex(ContractError, "invalid V2 Ed25519 signature"):
                        verify_signed(self.sign(value, key=key), self.trust)

    def test_unknown_and_other_role_key_ids_rejected_even_when_signed(self):
        for name, value in self.objects.items():
            id_field = "operator_root_key_id" if name in ROOT_TYPES else "receipt_key_id"
            other_id = self.receipt_id if name in ROOT_TYPES else self.root_id
            for key_id in (H, other_id):
                with self.subTest(name=name, id=key_id):
                    with self.assertRaisesRegex(ContractError, "fixed signer role"):
                        verify_signed(self.sign({**value, id_field: key_id}), self.trust)

    def test_schema_valid_body_mutation_rejected_for_every_type(self):
        # These changes retain valid shapes, and must reach cryptographic
        # rejection.  Independent S2 equality above covers the complete body.
        for name, value in self.objects.items():
            signed = self.sign(value)
            field = "reason" if "reason" in value else "runtime_principal" if "runtime_principal" in value else "operation_id" if "operation_id" in value else "opening_id"
            changed = {**signed, field: V if field.endswith("_id") else "changed"}
            with self.subTest(name=name, field=field):
                with self.assertRaisesRegex(ContractError, "invalid V2 Ed25519 signature"):
                    verify_signed(changed, self.trust)

    def test_wrong_preimage_domains_and_omitted_fields_rejected(self):
        for name in ("abort_override", "prepare_ack", "execution_grant", "terminal_receipt", "local_finish_permit"):
            value = self.objects[name]
            signature_field = "root_signature" if name in ROOT_TYPES else "receipt_signature"
            unsigned = {key: item for key, item in value.items() if key != signature_field}
            prefix = b"QINGYU-R1-SCOPED-SIGN-V2/" + name.encode() + b"\0"
            missing_id = {key: item for key, item in unsigned.items() if key not in ("operator_root_key_id", "receipt_key_id")}
            wrong_inputs = [
                independent_json(unsigned),
                b"QINGYU-CP-R1-AUTHORITY-RECEIPT\0" + independent_json(unsigned),
                b"QINGYU-R1-SCOPED-V2/" + name.encode() + b"\0" + independent_json(unsigned),
                b"QINGYU-R1-SCOPED-SIGN-V2/business_payload\0" + independent_json(unsigned),
                prefix + json.dumps(unsigned, sort_keys=True).encode(),
                prefix + independent_json(value),
                prefix + independent_json(missing_id),
            ]
            if "contract_revision" in unsigned:
                wrong_inputs.append(prefix + independent_json({k: v for k, v in unsigned.items() if k != "contract_revision"}))
            for i, preimage in enumerate(wrong_inputs):
                with self.subTest(name=name, case=i):
                    with self.assertRaisesRegex(ContractError, "invalid V2 Ed25519 signature"):
                        verify_signed(self.sign(value, preimage=preimage), self.trust)

    def test_shape_version_revision_unknown_types_and_signer_fields_rejected(self):
        value = self.sign(self.objects["prepare_ack"])
        malformed = [
            {**value, "version": 1}, {**value, "version": True}, {**value, "version": 3},
            {**value, "contract_revision": 1}, {**value, "type": "unregistered_type"},
            {**value, "root_signature": PLACEHOLDER}, {**value, "receipt_signature": "AA" * 64},
            {**value, "receipt_signature": "00" * 63}, {**value, "receipt_signature": None},
            {k: v for k, v in value.items() if k != "contract_revision"},
            {k: v for k, v in value.items() if k != "receipt_signature"},
            typed("business_payload", value={"message": "unsigned"}),
        ]
        for i, body in enumerate(malformed):
            with self.subTest(case=i):
                with self.assertRaises(ContractError):
                    verify_signed(body, self.trust)

    def test_noncanonical_wire_and_wrong_input_types_rejected(self):
        signed = self.sign(self.objects["abort_override"])
        raw = independent_json(signed)
        for value in (b" " + raw, raw + b"\n", b'{"version":2,' + raw[1:], raw.replace(b'"version":2', b'"version":2.0'),
                      bytearray(raw), raw.decode(), None, [], 2):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(ContractError):
                    verify_signed(value, self.trust)

    def test_fixed_configuration_public_material_checks(self):
        self.assertEqual(self.trust.receipt_key_id, self.receipt_id)
        self.assertEqual(self.trust.operator_root_key_id, self.root_id)
        for pin in ({**self.pin, "receipt_key_id": H}, {**self.pin, "operator_root_key_id": H},
                    {**self.pin, "receipt_public_key": self.root_public.hex()}, {**self.pin, "version": 1},
                    {**self.pin, "https_origin": "http://authority.example.test"}, {**self.pin, "unknown": "claim"}):
            with self.subTest(pin=pin):
                with self.assertRaises(ContractError):
                    FixedTrust(independent_json(pin), self.root_public)
        for public in (b"", self.root_public[:-1], self.receipt_public, self.root_public.hex(), bytearray(self.root_public), None):
            with self.assertRaises(ContractError):
                FixedTrust(independent_json(self.pin), public)
        for pin_wire in (self.pin, b" " + independent_json(self.pin), independent_json(self.objects["abort_override"])):
            with self.assertRaises(ContractError):
                FixedTrust(pin_wire, self.root_public)

    def test_explicit_trust_is_required_and_cannot_be_selected_by_body(self):
        signed = self.sign(self.objects["prepare_ack"])
        for trust in (None, {}, self.pin, self.receipt_public):
            with self.assertRaisesRegex(ContractError, "explicit FixedTrust"):
                verify_signed(signed, trust)
        other_public = self.other_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        other_id = hashlib.sha256(other_public).hexdigest()
        replacement_pin = {**self.pin, "receipt_public_key": other_public.hex(), "receipt_key_id": other_id}
        replacement = FixedTrust(independent_json(replacement_pin), self.root_public)
        attacker_signed = self.sign({**self.objects["prepare_ack"], "receipt_key_id": other_id}, key=self.other_key)
        with self.assertRaisesRegex(ContractError, "fixed signer role"):
            verify_signed(attacker_signed, self.trust)
        # An explicitly different trusted configuration is a different caller
        # decision; no evidence field can cause this substitution automatically.
        verify_signed(attacker_signed, replacement)

    def test_trust_and_return_value_are_immutable_and_no_admission_is_claimed(self):
        exposed = self.trust.pin
        exposed["receipt_key_id"] = H
        self.assertEqual(self.trust.pin, self.pin)
        with self.assertRaises(FrozenInstanceError):
            self.trust.pin_wire = b"{}"
        result = verify_signed(self.sign(self.objects["abort_override"]), self.trust)
        with self.assertRaises(FrozenInstanceError):
            result.key_id = H
        for name in ("active", "admitted", "may_apply", "authorized", "history_complete"):
            self.assertFalse(hasattr(result, name))

    def test_valid_signature_does_not_assert_semantics_or_present_day_authority(self):
        # A freshly signed contradictory result remains a valid signature only.
        contradictory = {**self.objects["terminal_receipt"], "decision": "ABORT", "result_state": "COMMITTED"}
        result = verify_signed(self.sign(contradictory), self.trust)
        self.assertEqual(result.object_type, "terminal_receipt")
        # Old timestamps do not cause this narrow signature verifier to rewrite
        # history based on the machine's current date or current authorization.
        historical = {**self.objects["abort_override"], "issued_at": 1, "expires_at": 2}
        self.assertEqual(verify_signed(self.sign(historical), self.trust).signer_role, "ROOT")


if __name__ == "__main__":
    unittest.main()
