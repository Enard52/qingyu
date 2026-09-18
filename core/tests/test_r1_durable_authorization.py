import unittest
from types import SimpleNamespace
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import ed25519

from app.control_plane.r1_durable_authorization import (
    _id, _registry_delta, _signed_issue, credential_digest,
)
from app.control_plane.r1_durable_schema import SQL
from app.control_plane.r1_validation_codec import decode, record, s2


class _Signer:
    def __init__(self):
        self.key = ed25519.Ed25519PrivateKey.generate()

    def sign(self, message):
        return self.key.sign(message)


class DurableAuthorizationUnitTests(unittest.TestCase):
    def setUp(self):
        self.header = {"history_version": 2, "authority_domain_id": str(uuid4()),
            "authority_instance_id": str(uuid4()), "authority_generation": 1}
        self.engine = SimpleNamespace(authority={"header": self.header, "events": [], "records": {}})

    def test_credential_is_digest_only_and_ids_are_stable(self):
        token = b"x" * 32
        self.assertEqual(len(credential_digest(token)), 64)
        scope, op = str(uuid4()), str(uuid4())
        self.assertEqual(_id(scope, op, "grant:1"), _id(scope, op, "grant:1"))
        self.assertNotEqual(_id(scope, op, "grant:1"), _id(scope, op, "grant:2"))

    def test_delta_allocates_contiguous_positions_even_same_millisecond(self):
        one = record("revocation", history_version=2, object_digest="a" * 64)
        two = record("revocation", history_version=2, object_digest="b" * 64)
        part = _registry_delta(self.engine, (("GRANT_REVOKE", 5000, one, None),
                                             ("PERMIT_REVOKE", 5000, two, None)))
        events = [decode(raw) for raw in part.event_wires]
        self.assertEqual([e["position"]["event_sequence"] for e in events], [1, 2])
        self.assertEqual([e["recorded_at"] for e in events], [5000, 5000])

    def test_issue_signature_covers_exact_snapshot_digest(self):
        signer = _Signer()
        target = record("revocation", history_version=2, object_digest="c" * 64)
        body = {"grant_id": str(uuid4()), "grant_sequence": 1,
            "policy_digest": "e" * 64, "inventory_digest": "f" * 64,
            "operation_id": str(uuid4()), "request_digest": "1" * 64,
            "source_decision_digest": "2" * 64, "authority_domain_id": str(uuid4()),
            "authority_instance_id": str(uuid4()), "authority_generation": 1,
            "continuity_id": str(uuid4()), "qingyu_identity_id": str(uuid4()),
            "genesis_operation_id": str(uuid4()), "owner_identity": "owner", "owner_version": 1,
            "continuity_epoch": 1, "expected_state_version": 4,
            "storage_generation_id": str(uuid4()), "control_plane_generation_id": str(uuid4()),
            "runtime_principal": "runtime", "session_id": str(uuid4()),
            "lease_id": str(uuid4()), "lease_generation": 1, "issued_at": 7000,
            "expires_at": 8000, "receipt_key_id": "d" * 64}
        snapshot, issued = _signed_issue(signer, self.engine, "execution_grant", 7000,
                                          body, target, 1)
        self.assertEqual(issued["issuance_digest"],
                         __import__("app.control_plane._r1_validation_semantics", fromlist=["rawhash"]).rawhash(snapshot))
        signer.key.public_key().verify(bytes.fromhex(issued["receipt_signature"]), s2(issued))

    def test_schema_keeps_runtime_off_base_tables(self):
        self.assertIn("SECURITY DEFINER", SQL)
        self.assertIn("REVOKE ALL ON control_plane.r1d_subjects", SQL)
        self.assertNotIn("GRANT SELECT ON control_plane.r1d_", SQL)
        self.assertIn("credential_digest", SQL)
        self.assertNotIn("credential_token", SQL)


if __name__ == "__main__":
    unittest.main()
