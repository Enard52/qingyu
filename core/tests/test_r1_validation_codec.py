"""Product codec tests against immutable accepted byte vectors, never its runner."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import unittest

from app.control_plane import r1_validation_codec as codec


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "docs/evidence/r1-acceptance-marathon/remaining-findings-full-review-20260916T141212Z/synthetic-vectors.json"


class CanonicalProductTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vectors = json.loads(VECTORS.read_text(encoding="utf-8"))

    def test_all_accepted_typed_c2_h2_s2_vectors(self):
        for digest, row in self.vectors["objects"].items():
            with self.subTest(type=row["value"]["type"], digest=digest):
                value = row["value"]
                expected = bytes.fromhex(row["c2_hex"])
                self.assertEqual(codec.c2(value), expected)
                self.assertEqual(codec.decode(expected), value)
                self.assertEqual(codec.h2(value), digest)
                self.assertEqual(len(expected), row["c2_length"])
                if "root_signature" in value or "receipt_signature" in value:
                    field = "root_signature" if "root_signature" in value else "receipt_signature"
                    unsigned = {k: v for k, v in value.items() if k != field}
                    # Independent stdlib formatting and literal contractual domain.
                    independent = (b"QINGYU-R1-SCOPED-SIGN-V2/" + value["type"].encode("ascii") + b"\0"
                                   + json.dumps(unsigned, sort_keys=True, ensure_ascii=True,
                                                separators=(",", ":")).encode("ascii"))
                    self.assertEqual(codec.s2(value), independent)

    def test_all_accepted_nonwire_and_raw_vectors(self):
        for digest, row in self.vectors["nonwire_objects"].items():
            with self.subTest(digest=digest):
                self.assertEqual(codec.c2(row["value"]).hex(), row["c2_hex"])
                self.assertEqual(codec.sha(codec.c2(row["value"])), digest)
        for digest, row in self.vectors["raw_blobs"].items():
            with self.subTest(raw=digest):
                raw = bytes.fromhex(row["hex"])
                self.assertEqual(len(raw), row["byte_length"])
                self.assertEqual(codec.sha(raw), digest)

    def test_literal_unicode_safe_integer_and_order_rules(self):
        self.assertEqual(codec.c2({"中": "😀", "a": [None, True, -9007199254740991]}),
                         b'{"a":[null,true,-9007199254740991],"\\u4e2d":"\\ud83d\\ude00"}')
        for value in (1.0, float("nan"), 9007199254740992, "\0", "\ud800", {1: "x"}, [0] * 4097):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(codec.ContractError):
                codec.c2(value)

    def test_wire_and_type_fail_closed(self):
        bad_wires = (b'{"a":1,"a":2}', b'{"b":0,"a":1}', b' {"a":1}', b'{"a":1.0}',
                     b'{"a":NaN}', b'"\xff"', b'"\\ud800"', b'[' * 2000 + b'0' + b']' * 2000)
        for raw in bad_wires:
            with self.subTest(raw_length=len(raw)), self.assertRaises(codec.ContractError):
                codec.decode(raw)
        identity = next(row["value"] for row in self.vectors["objects"].values()
                        if row["value"]["type"] == "identity")
        for changed in (dict(identity, version=True), dict(identity, version=1),
                        dict(identity, version="2"), dict(identity, extra=True),
                        dict(identity, type="unsupported")):
            with self.subTest(changed=changed), self.assertRaises(codec.ContractError):
                codec.validate(changed)

    def test_v1_wire_is_not_promoted_or_reencoded(self):
        # Preservation is byte-for-byte. The V2 entry never chooses the V1 codec.
        raw = b'{"reason":"\\u4e2d","schema_version":1}'
        before = hashlib.sha256(raw).hexdigest()
        with self.assertRaises(codec.ContractError):
            codec.validate(codec.decode(raw))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), before)

    def test_existing_v1_runtime_canonical_behavior(self):
        # This declared dependency is required. Missing it is a test error, not
        # evidence that the V1 compatibility requirement has been satisfied.
        from app.control_plane.r1_protocol import canonical_bytes, decode_canonical_wire
        raw = '{"text":"中"}'.encode("utf-8")
        self.assertEqual(canonical_bytes({"text": "中"}), raw)
        self.assertEqual(decode_canonical_wire(raw), {"text": "中"})
        with self.assertRaises(ValueError):
            decode_canonical_wire(b'{"text":"\\u4e2d"}')


if __name__ == "__main__":
    unittest.main()
