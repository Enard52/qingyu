"""Required V1 regression using the unchanged product verifier and real JCS.

Only process-local Ed25519 keys and synthetic objects are used. No fixtures,
services, source adapters or reference implementation are imported. The literal
byte expectations deliberately include cases where V1 JCS and V2 C2 differ.
"""

from copy import deepcopy
from dataclasses import replace
import hashlib
import unittest

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.control_plane import r1_protocol as v1
from app.control_plane import r1_validation_codec as v2
from app.control_plane.r1_validation import HistoryEvidence, validate_evidence
from app.control_plane.r1_validation_crypto import FixedTrust


U = "00000000-0000-0000-0000-000000000001"
V = "00000000-0000-0000-0000-000000000002"
PREPARE_DOMAIN = b"QINGYU-CP-R1-PREPARE-ACK\0"
RECEIPT_DOMAIN = b"QINGYU-CP-R1-AUTHORITY-RECEIPT\0"


class V1ProductRegressionTests(unittest.TestCase):
    def setUp(self):
        self.private = Ed25519PrivateKey.generate()
        self.root_private = Ed25519PrivateKey.generate()
        public = self.private.public_key()
        self.key_id = hashlib.sha256(public.public_bytes(Encoding.Raw, PublicFormat.Raw)).hexdigest()
        root_public = self.root_private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        root_id = hashlib.sha256(root_public).hexdigest()
        self.pin = v1.AuthorityPin(U, V, 1, public, self.key_id, 1,
                                   "https://authority.example.test", "a" * 64, root_id)
        self.request = {
            "schema_version": 1, "authority_domain_id": U, "authority_instance_id": V,
            "authority_generation": 1, "qingyu_identity_id": U, "continuity_id": V,
            "operation_id": U, "operation_type": "MUTATION", "expected_continuity_epoch": 1,
            "expected_state_version": 0, "expected_owner_version": 1,
            "actor_or_owner_identity": "owner-\u96ea", "caller_runtime_id": U,
            "storage_generation_id": V, "payload": {"label": "\u4e2d", "value": 1.0}, "reason": "test",
        }
        self.request_hash = hashlib.sha256(rfc8785.dumps(self.request)).hexdigest()
        self.intent = v1.ExpectedIntent(self.request_hash, "1" * 64, "2" * 64, "3" * 64)
        self.ack_body = {
            "ack_version": 1,
            **{key: self.request[key] for key in (
                "authority_domain_id", "authority_instance_id", "authority_generation",
                "qingyu_identity_id", "continuity_id", "operation_id", "operation_type",
                "caller_runtime_id", "storage_generation_id", "expected_continuity_epoch",
                "expected_owner_version", "expected_state_version")},
            "request_envelope_hash": self.request_hash, "staged_result_hash": "1" * 64,
            "core_audit_predecessor_hash": "2" * 64, "core_audit_candidate_hash": "3" * 64,
            "state": "PREPARED", "prepared_at": "2026-09-13T00:00:00Z", "receipt_key_id": self.key_id,
        }
        self.receipt_body = {
            "receipt_version": 1, "schema_version": 1,
            **{key: self.request[key] for key in (
                "authority_domain_id", "authority_instance_id", "authority_generation",
                "qingyu_identity_id", "continuity_id", "operation_id", "operation_type",
                "actor_or_owner_identity", "storage_generation_id")},
            "request_envelope_hash": self.request_hash, "result_state": "COMMITTED", "result_code": "APPLIED",
            "continuity_epoch": 1, "control_plane_generation_id": U, "owner_version": 1,
            "lease_generation": 1, "authority_sequence": 2, "previous_receipt_hash": "9" * 64,
            "result_payload_hash": "4" * 64, "staged_result_hash": "1" * 64,
            "core_audit_predecessor_hash": "2" * 64, "core_audit_candidate_hash": "3" * 64,
            "decided_at": "2026-09-13T00:00:01Z", "signed_provisioning_origin_digest": None,
            "previous_generation": None, "previous_generation_sequence": None,
            "previous_generation_head_hash": None, "signed_dr_artifact_digest": None,
            "receipt_key_id": self.key_id,
        }
        fixed_pin = dict(type="authority_pin", version=2, authority_domain_id=U, authority_instance_id=V,
                         authority_generation=1, receipt_public_key=public.public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
                         receipt_key_id=self.key_id, api_version=1, https_origin=self.pin.https_origin,
                         server_spki_sha256=self.pin.server_spki_sha256, operator_root_key_id=root_id)
        self.v2_trust = FixedTrust(v2.c2(fixed_pin), root_public)

    def signed(self, body, field, prefix, *, key=None, encoded=None):
        key = self.private if key is None else key
        # Independent of the product signing helpers; uses the actual declared
        # RFC8785 dependency and the literal historical domain bytes above.
        signature = key.sign(prefix + (rfc8785.dumps(body) if encoded is None else encoded))
        return {**deepcopy(body), field: signature.hex()}

    def receipt(self, body=None):
        return self.signed(self.receipt_body if body is None else body, "receipt_signature", RECEIPT_DOMAIN)

    def verify_receipt(self, receipt, **kwargs):
        return v1.verify_terminal_receipt_wire(rfc8785.dumps(receipt), self.request, self.pin, self.intent,
                                               expected_sequence=2, expected_previous_hash="9" * 64, **kwargs)

    def test_literal_jcs_numbers_and_raw_utf8(self):
        value = {"numbers": [333333333.33333329, 1e30, 4.50, 2e-3, 1e-27], "text": "\u4e2d"}
        expected = b'{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"text":"\xe4\xb8\xad"}'
        self.assertEqual(v1.canonical_bytes(value), expected)
        self.assertEqual(v1.decode_canonical_wire(expected), value)
        self.assertEqual(v1.canonical_bytes([-0.0, 1e-6, 1e-7]), b'[0,0.000001,1e-7]')
        with self.assertRaises(v2.ContractError):
            v2.c2(value)

    def test_literal_utf16_key_order_and_no_unicode_normalization(self):
        value = {"\ufffd": "replacement", "\U0001f600": "grin", "\u20ac": "euro", "\r": "control", "1": "one", "\u0080": "control128", "\u00f6": "o"}
        expected = b'{"\\r":"control","1":"one","\xc2\x80":"control128","\xc3\xb6":"o","\xe2\x82\xac":"euro","\xf0\x9f\x98\x80":"grin","\xef\xbf\xbd":"replacement"}'
        self.assertEqual(v1.canonical_bytes(value), expected)
        self.assertEqual(v1.decode_canonical_wire(expected), value)
        self.assertNotEqual(v2.c2(value), expected)
        self.assertEqual(v1.canonical_bytes({"s": "e\u0301"}), b'{"s":"e\xcc\x81"}')
        self.assertNotEqual(v1.canonical_bytes({"s": "e\u0301"}), v1.canonical_bytes({"s": "\u00e9"}))

    def test_noncanonical_or_ambiguous_v1_wires_rejected(self):
        for raw in (b'{"n":1.0}', b'{"n":-0}', b'{"n":1e+0}', b'{"s":"\\u4e2d"}',
                    b'{"a":1,"a":2}', b'{"z":0,"a":1}', b' {"n":1}', b'{"n":NaN}', b'"\xff"'):
            with self.subTest(raw=raw), self.assertRaises(v1.ProtocolError):
                v1.decode_canonical_wire(raw)
        for value in (float("nan"), float("inf"), 9007199254740992, "\ud800"):
            with self.subTest(kind=type(value).__name__), self.assertRaises(v1.ProtocolError):
                v1.canonical_bytes(value)

    def test_real_prepare_and_both_terminal_states_preserve_original_bytes(self):
        ack = self.signed(self.ack_body, "ack_signature", PREPARE_DOMAIN)
        ack_wire = rfc8785.dumps(ack)
        self.assertEqual(v1.verify_prepare_ack_wire(ack_wire, self.request, self.pin, self.intent), ack)
        self.assertEqual(v1.request_envelope_hash(self.request), self.request_hash)
        for state, code in (("COMMITTED", "APPLIED"), ("ABORTED", "ABORTED")):
            receipt = self.receipt({**self.receipt_body, "result_state": state, "result_code": code})
            wire = rfc8785.dumps(receipt)
            saved = bytes(wire)
            expected = hashlib.sha256(RECEIPT_DOMAIN + wire).hexdigest()
            with self.subTest(state=state):
                for _ in range(2):
                    self.assertEqual(self.verify_receipt(receipt, prepared_ack=ack), expected)
                    self.assertEqual(v1.receipt_hash(receipt), expected)
                self.assertEqual(wire, saved)
                self.assertIn("owner-\u96ea".encode(), wire)

    def test_c2_and_wrong_domain_signatures_cannot_replace_v1_preimages(self):
        for prefix, encoded in ((PREPARE_DOMAIN, None), (b"QINGYU-R1-SCOPED-SIGN-V2/terminal_receipt\0", None),
                                (RECEIPT_DOMAIN, v2.c2(self.receipt_body))):
            with self.subTest(prefix=prefix, c2=encoded is not None):
                receipt = self.signed(self.receipt_body, "receipt_signature", prefix, encoded=encoded)
                with self.assertRaisesRegex(v1.ProtocolError, "invalid Authority signature"):
                    self.verify_receipt(receipt)

    def test_real_signature_does_not_hide_wrong_original_scope_or_chain(self):
        for field, value in (("operation_id", V), ("storage_generation_id", U),
                             ("request_envelope_hash", "f" * 64), ("staged_result_hash", "f" * 64),
                             ("core_audit_predecessor_hash", "f" * 64), ("core_audit_candidate_hash", "f" * 64),
                             ("previous_receipt_hash", "f" * 64), ("authority_sequence", 3),
                             ("actor_or_owner_identity", "different-owner")):
            with self.subTest(field=field), self.assertRaises(v1.ProtocolError):
                self.verify_receipt(self.receipt({**self.receipt_body, field: value}))

    def test_wrong_fixed_key_and_pin_scope_rejected(self):
        wrong = Ed25519PrivateKey.generate()
        receipt = self.signed(self.receipt_body, "receipt_signature", RECEIPT_DOMAIN, key=wrong)
        with self.assertRaisesRegex(v1.ProtocolError, "invalid Authority signature"):
            self.verify_receipt(receipt)
        wire = rfc8785.dumps(self.receipt())
        for pin in (replace(self.pin, authority_instance_id=U), replace(self.pin, authority_generation=2),
                    replace(self.pin, receipt_key_id="f" * 64)):
            with self.subTest(pin_generation=pin.authority_generation), self.assertRaises(v1.ProtocolError):
                v1.verify_terminal_receipt_wire(wire, self.request, pin, self.intent,
                                                expected_sequence=2, expected_previous_hash="9" * 64)

    def test_operation_identity_replay_and_content_conflict(self):
        before = deepcopy(self.request)
        self.assertTrue(v1.same_operation_envelope(U, self.request_hash, self.request))
        changed = deepcopy(self.request)
        changed["payload"]["label"] = "different"
        with self.assertRaises(v1.ProtocolError):
            v1.same_operation_envelope(U, self.request_hash, changed)
        self.assertEqual(self.request, before)

    def test_public_v2_entry_does_not_promote_a_v1_request(self):
        wire = rfc8785.dumps(self.request)
        before = hashlib.sha256(wire).hexdigest()
        evidence = HistoryEvidence(request_wires=(wire,), authority_history=b"{}", core_histories=())
        with self.assertRaises(v2.ContractError):
            validate_evidence("REGISTRY_RELATIONS", evidence, self.v2_trust, ())
        self.assertEqual(hashlib.sha256(wire).hexdigest(), before)


if __name__ == "__main__":
    unittest.main()
