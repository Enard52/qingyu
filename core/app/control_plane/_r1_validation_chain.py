"""Bounded, ordered mutation-chain relations against an external boundary.

The boundary is a caller-supplied trust prerequisite, never a declaration taken
from an archive member. Checking it does not authenticate its provenance.
Authority terminal order and each Core's local APPLY order are kept separate.
"""
from dataclasses import dataclass

from .r1_validation_codec import c2, decode, h2, match, require, validate, obj
from . import _r1_validation_semantics as sem

MAX_OPERATIONS = 64


@dataclass(frozen=True, slots=True)
class ChainBoundary:
    identity_wire: bytes
    start_checkpoint_wire: bytes
    expected_end_checkpoint_wire: bytes
    owner_identity: str
    owner_version: int
    continuity_epoch: int
    storage_generation_id: str
    control_plane_generation_id: str
    trust_domain_id: str


@dataclass(frozen=True, slots=True)
class ChainValidation:
    operation_ids: tuple[str, ...]
    checkpoint_wires: tuple[bytes, ...]
    core_checkpoint_wires: tuple[tuple[str, bytes], ...]


def decode_boundary(boundary):
    require(type(boundary) is ChainBoundary, "explicit external ChainBoundary required")
    values = [decode(raw) for raw in (boundary.identity_wire,
              boundary.start_checkpoint_wire, boundary.expected_end_checkpoint_wire)]
    for value, kind in zip(values, ("identity", "local_checkpoint", "local_checkpoint")):
        validate(value)
        require(value["type"] == kind, "chain boundary object type")
    match(boundary.owner_identity, "text256")
    for name in ("owner_version", "continuity_epoch"):
        match(getattr(boundary, name), "p")
    for name in ("storage_generation_id", "control_plane_generation_id", "trust_domain_id"):
        match(getattr(boundary, name), "uuid")
    return values


def verify_operation_chain(requests, authority, cores, boundary, contexts=None):
    """Check already individually validated evidence, without sorting or repair.

This same-generation mutation segment requires a separately supplied start and
expected terminal tail. Version/generation openings are separate evidence and
must be verified before their resulting checkpoint becomes a segment boundary.
Core may lag Authority; actual local completion is returned, never fabricated.
"""
    identity, start, expected_end = decode_boundary(boundary)
    require(0 < len(requests) <= MAX_OPERATIONS, "operation chain resource limit")
    mutation_ids, commit_ids = set(), set()
    for request in requests.values():
        intent, scope = request["intent"], request["intent"]["scope"]
        require(intent["identity"] == identity, "chain stable identity/continuity mismatch")
        sem.eq_fields(scope, {"actor_identity": boundary.owner_identity,
            **{k: getattr(boundary, k) for k in ("owner_version", "continuity_epoch",
                "storage_generation_id", "control_plane_generation_id", "trust_domain_id")}},
            "chain external governance scope mismatch")
        require(intent["mutation_id"] not in mutation_ids, "mutation identity reused by different operations")
        require(intent["local_commit_id"] not in commit_ids, "local commit identity reused by different operations")
        mutation_ids.add(intent["mutation_id"]); commit_ids.add(intent["local_commit_id"])
    cursor = start
    ordered, checkpoints, terminal_by_op = [], [c2(start)], {}
    pending = None
    for event in authority["events"]:
        kind = event["event_kind"]
        if kind not in ("PREPARE", "FIX_ACCEPTED", "TERMINAL"):
            continue
        snapshot = authority["records"][event["input_digest"]]
        op = snapshot["operation_id"]
        request = requests[op]
        require(sem.before_checkpoint(request) == cursor,
                "Authority chain missing predecessor or original checkpoint mismatch")
        require(pending is None or pending == op, "overlapping unresolved mutation chain")
        if kind == "PREPARE":
            require(pending is None, "duplicate PREPARE in operation chain")
            pending = op
        elif kind == "FIX_ACCEPTED":
            require(pending == op, "FIX without chain PREPARE")
        else:
            require(pending == op and op not in terminal_by_op, "terminal chain conflict")
            receipt = authority["records"][event["output_digest"]]
            predecessor = cursor["authority_ref"]
            require(predecessor["wire_version"] == 2
                    and predecessor["authority_generation"] == receipt["authority_generation"],
                    "mutation cannot perform version/generation opening")
            require(receipt["previous_authority_ref"] == predecessor
                    and receipt["authority_sequence"] == predecessor["authority_sequence"] + 1,
                    "Authority receipt predecessor/sequence mismatch")
            selected = request[receipt["decision"].lower()]
            candidate = selected["audit_candidate"]
            require(candidate["previous_audit_ref"] == cursor["audit_ref"]
                    and candidate["audit_sequence"] == cursor["audit_ref"]["audit_sequence"] + 1,
                    "Core Audit predecessor/sequence mismatch")
            require(receipt["state_before"] == cursor["state_version"]
                    and receipt["state_after"] == cursor["state_version"] + (receipt["decision"] == "COMMIT"),
                    "COMMIT/ABORT state progression mismatch")
            audit = obj("audit_record", candidate=candidate, receipt_digest=h2(receipt))
            cursor = sem.after_checkpoint(receipt, audit)
            ordered.append(op); checkpoints.append(c2(cursor)); terminal_by_op[op] = receipt
            pending = None
    require(cursor == expected_end, "Authority chain does not reach external expected tail")
    # Every request must occur in the supplied actual event stream. A final
    # pending request is allowed for prefix checking and leaves the tail intact.
    require(set(ordered) | ({pending} if pending else set()) == set(requests),
            "request missing from ordered Authority history")

    contexts = contexts or {}
    core_tips = []
    for core, material in cores:
        local_cursor, used, started = start, set(), False
        for event in core["events"]:
            if event["event_kind"] not in ("PROPOSAL", "PUBLICATION", "APPLY"):
                continue
            snapshot = core["records"][event["input_digest"]]
            op = snapshot["operation_id"]
            # Subject policy is available in Authority's immutable records.
            policy = sem.record_by(authority, snapshot["policy_digest"])
            require(policy.get("type") == "recovery_policy", "chain subject policy type")
            context = contexts.get(policy["restoration_context_digest"])
            if not started:
                if context is not None:
                    local_cursor = context["restore_start_checkpoint"]
                    require(c2(local_cursor) in checkpoints, "restore start is not an exact chain checkpoint")
                started = True
            require(sem.before_checkpoint(requests[op]) == local_cursor,
                    "Core local chain missing APPLY or exact predecessor mismatch")
            if event["event_kind"] == "APPLY":
                completion = core["records"][event["output_digest"]]
                require(op in terminal_by_op and op not in used, "Core completion absent/conflicting terminal")
                require(completion["before_checkpoint"] == local_cursor, "Core completion predecessor mismatch")
                receipt = terminal_by_op[op]
                audit = obj("audit_record", candidate=requests[op][receipt["decision"].lower()]["audit_candidate"],
                            receipt_digest=h2(receipt))
                local_cursor = sem.after_checkpoint(receipt, audit)
                require(completion["after_checkpoint"] == local_cursor, "Core completion post checkpoint mismatch")
                used.add(op)
        core_tips.append((material.runtime_principal, c2(local_cursor)))
    return ChainValidation(tuple(ordered), tuple(checkpoints), tuple(core_tips))
