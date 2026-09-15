"""Synthetic, public test values. Never production provisioning or real identity."""

from copy import deepcopy
from uuid import UUID, uuid4

from app.control_plane.r1_protocol import canonical_bytes, sha256_hex


def uid(number: int) -> str:
    return str(UUID(int=number, version=4))


def mutation_envelope(*, operation_id=None, mutation_id="test-mutation", state_version=1,
                      predecessor="a" * 64, **changes):
    staged = {"mutation_id": mutation_id, "state_version": state_version + 1,
              "value": {"example": "synthetic 测试", "nested": [True, None, 1e-7]}}
    abort = {"mutation_id": mutation_id, "state_version": state_version,
             "result_state": "ABORTED", "core_audit_candidate_hash": "d" * 64}
    value = {
        "schema_version": 1, "authority_domain_id": uid(1), "authority_instance_id": uid(2),
        "authority_generation": 1, "qingyu_identity_id": uid(3), "continuity_id": uid(4),
        "operation_id": str(operation_id or uuid4()), "operation_type": "MUTATION",
        "expected_continuity_epoch": 1, "expected_state_version": state_version,
        "expected_owner_version": 1, "actor_or_owner_identity": "test-owner",
        "caller_runtime_id": uid(5), "storage_generation_id": uid(6), "reason": "synthetic F3 test",
        "payload": {"payload_version": 1, "mutation_id": mutation_id, "local_commit_id": uid(7),
                    "lease_id": uid(8), "lease_generation": 1, "session_id": uid(9),
                    "control_plane_generation_id": uid(10), "genesis_operation_id": uid(11),
                    "staged_result": staged, "staged_result_hash": sha256_hex(canonical_bytes(staged)),
                    "core_audit_predecessor_hash": predecessor, "core_audit_candidate_hash": "b" * 64,
                    "abort_result": abort, "abort_result_hash": sha256_hex(canonical_bytes(abort))},
    }
    value.update(deepcopy(changes))
    return value


def authorization_value(intent, decision="COMMIT"):
    result = {"authorization_version": 1, "decision": decision,
              "operation_id": intent.operation_id, "request_envelope_hash": intent.request_hash,
              **{field: intent.payload[field] for field in ("local_commit_id", "staged_result_hash",
                 "core_audit_predecessor_hash", "core_audit_candidate_hash")}}
    if decision == "COMMIT":
        result["transaction_evidence_hash"] = "c" * 64
    else:
        result.update(no_local_business_commit=True, abort_evidence_hash="e" * 64)
    return result
