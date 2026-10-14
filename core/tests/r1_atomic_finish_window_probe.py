"""Independent read-only probe of the existing bounded-history API.

This does not bypass product limits or assert that 65-operation histories have
passed semantic validation. It records the exact integration limit separately
from a two-operation legal control and verifies generated signatures itself.
"""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from tests.r1_validation_completion_independent_fixtures import IndependentHistory, wire
from app.control_plane.r1_validation import validate_evidence


def execute():
    output = {"at": datetime.now(timezone.utc).isoformat(), "observations": []}

    def run(name, world, evidence, boundary):
        trust, deployments = world.product_inputs()[1:]
        try:
            value = validate_evidence("TERMINAL_HISTORY", evidence, trust, deployments, chain_boundary=boundary)
            result = {"outcome": "ACCEPT", "request_count": len(value.request_digests)}
        except Exception as exc:
            result = {"outcome": "REJECT", "error_type": type(exc).__name__, "error": str(exc)}
        signatures = 0
        for row in world.operations:
            for name_ in ("policy", "grant", "ack", "receipt", "permit"):
                value = row[name_]
                field = "root_signature" if name_ == "policy" else "receipt_signature"
                key = world.root_key if name_ == "policy" else world.receipt_key
                preimage = b"QINGYU-R1-SCOPED-SIGN-V2/" + value["type"].encode("ascii") + b"\0" + wire({k: v for k, v in value.items() if k != field})
                key.public_key().verify(bytes.fromhex(value[field]), preimage)
                signatures += 1
        result.update(name=name, input_requests=len(evidence.request_wires),
                      independently_verified_generated_signatures=signatures,
                      authority_bytes=len(evidence.authority_history),
                      authority_sha256=hashlib.sha256(evidence.authority_history).hexdigest(),
                      request_sha256=[hashlib.sha256(x).hexdigest() for x in evidence.request_wires])
        output["observations"].append(result)

    world = IndependentHistory(seed=825000)
    world.add_operation(); world.add_operation()
    evidence = world.product_inputs()[0]
    run("two_operations_full_prefix_legal_control", world, evidence, world.boundary())
    run("last_one_request_full_original_registries", world,
        replace(evidence, request_wires=(evidence.request_wires[-1],), source_admission_wires=(evidence.source_admission_wires[-1],)),
        replace(world.boundary(), start_checkpoint_wire=wire(world.operations[-1]["before"])))
    world = IndependentHistory(seed=826000)
    for ordinal in range(65):
        world.add_operation("ABORT" if ordinal % 3 == 0 else "COMMIT")
    run("65_real_distinct_signed_sequential_operations", world, world.product_inputs()[0], world.boundary())
    output["source_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    return output


if __name__ == "__main__":
    result = execute()
    target = Path("docs/evidence/r1-acceptance-marathon/core-local-atomic-finish-slice-02-20260916T181453Z/independent-window-probe.json")
    saved = json.loads(target.read_text(encoding="utf-8")) if target.exists() else {}
    saved.setdefault("subsequent_executions", []).append(result)
    target.write_text(json.dumps(saved, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"observations": [{k: v for k, v in row.items() if k != "request_sha256"} for row in result["observations"]]}, indent=2))
