"""Test-issued public operation deltas at their original global positions.

Each original object is signed once using temporary in-memory test issuer keys.
The generator retains no accumulated registry records in its construction seed;
only the true event counts are carried into the next object's original position.
No old event is re-numbered or re-signed to construct a later validation slice.
"""
from copy import deepcopy
from dataclasses import dataclass, replace

from app.control_plane.r1_validation_codec import c2, decode, h2
from tests.r1_validation_fixtures import build_world, registry


@dataclass(frozen=True)
class WindowOperation:
    ordinal: int
    operation_id: str
    request_wire: bytes
    source_admission_wire: bytes
    authority_header_wire: bytes
    authority_events: tuple
    authority_records: tuple
    core_header_wire: bytes
    core_prior_events: tuple
    core_complete_events: tuple
    core_records: tuple
    permit_wire: bytes
    policy_wire: bytes
    inventory_wire: bytes
    terminal_wire: bytes
    audit_wire: bytes
    effect_wire: bytes
    result_wire: bytes
    completion_wire: bytes
    before_wire: bytes
    after_wire: bytes
    now: int


@dataclass(frozen=True)
class PublicSequence:
    operations: tuple
    pin_wire: bytes
    root_public_key: bytes
    deployment: object
    identity_wire: bytes
    owner_identity: str
    owner_version: int
    continuity_epoch: int
    trust_domain_id: str
    alternatives: tuple = ()


def _public_operation(world, ordinal, authority_count, core_count):
    authority_events = world.authority["events"][authority_count:]
    core_events = world.core["events"][core_count:]
    if core_events[-1]["event_kind"] != "APPLY":
        raise AssertionError("issuer fixture complete operation expected")
    selected = world.request[world.objects["receipt"]["decision"].lower()]
    return WindowOperation(ordinal, world.request["intent"]["operation_id"], c2(world.request),
        c2(world.objects["source_admission"]), c2(world.authority["header"]),
        tuple(c2(value) for value in authority_events),
        tuple((key, c2(value)) for key, value in world.authority["records"].items()),
        c2(world.core["header"]), tuple(c2(value) for value in core_events[:-1]),
        tuple(c2(value) for value in core_events),
        tuple((key, c2(value)) for key, value in world.core["records"].items()),
        c2(world.objects["permit"]), c2(world.objects["policy"]), c2(world.objects["inventory"]),
        c2(world.objects["receipt"]), c2(world.objects["audit"]), c2(selected["effect"]), c2(selected["result"]),
        c2(world.objects["completion"]), c2(world.objects["before"]), c2(world.objects["after"]),
        world.objects["completion"]["completed_at"])


def generate_sequence(count=129, *, override_ordinals=(64, 128), decisions=None):
    """Produce count different business operations with one continuous scope.

    Placeholder rows are construction-only length markers. They never become
    evidence, registry bytes, persisted records, or inputs to any verifier.
    """
    if type(count) is not int or not 1 <= count <= 256:
        raise ValueError("finite author sequence count")
    world = None
    authority_count = core_count = 0
    operations, alternatives = [], []
    for index in range(count):
        ordinal = index + 1
        decision = decisions[index] if decisions is not None else ("ABORT" if ordinal % 3 == 0 else "COMMIT")
        override = ordinal in override_ordinals
        if override:
            decision = "COMMIT"
        seed = None
        if world is not None:
            authority = registry(world.pin)
            core = registry(world.pin, world.deployment)
            marker = {"output_digest": None, "input_digest": ""}
            authority["events"] = [marker] * authority_count
            core["events"] = [marker] * core_count
            seed = replace(world, authority=authority, core=core,
                objects={"after": world.objects["after"]})
        world = build_world(decision, override=override, parent=seed, id_offset=index * 100,
                            time_offset=index * 2000, faults={"policy": {"expires_at": 1_000_000},
                                                            "session": {"expires_at": 1_000_000}})
        operations.append(_public_operation(world, ordinal, authority_count, core_count))
        if ordinal in (65, 129) and seed is not None:
            specifications = {
                "competing_successor": {},
                "policy_identity_reuse": {"policy": {"policy_id": decode(operations[0].policy_wire)["policy_id"]}},
                "inventory_identity_reuse": {"inventory": {"inventory_id": decode(operations[0].inventory_wire)["inventory_id"]}},
                "old_operation_identity_reuse": {},
                "wrong_authority_predecessor": {},
                "wrong_audit_predecessor": {},
                "wrong_business_predecessor": {},
            }
            for number, (label, changes) in enumerate(specifications.items(), 1):
                faults = {"policy": {"expires_at": 1_000_000}, "session": {"expires_at": 1_000_000}}
                for name, values in changes.items():
                    faults.setdefault(name, {}).update(values)
                before = deepcopy(seed.objects["after"])
                if label == "wrong_authority_predecessor":
                    before["authority_ref"]["receipt_hash"] = "c"*64
                elif label == "wrong_audit_predecessor":
                    before["audit_ref"]["audit_hash"] = "d"*64
                elif label == "wrong_business_predecessor":
                    before["state_version"] += 1
                offset = 0 if label == "old_operation_identity_reuse" else 100000+index*100+number*10000
                alternate = build_world("COMMIT", parent=seed, id_offset=offset,
                                        time_offset=index*2000, faults=faults, initial_checkpoint=before)
                alternatives.append((ordinal, label, _public_operation(alternate, ordinal, authority_count, core_count)))
        authority_count += len(operations[-1].authority_events)
        core_count += len(operations[-1].core_complete_events)
    first = decode(operations[0].request_wire)
    scope = first["intent"]["scope"]
    return PublicSequence(tuple(operations), world.trust.pin_wire, world.trust.root_public_key,
        world.deployment, c2(first["intent"]["identity"]), scope["actor_identity"], scope["owner_version"],
        scope["continuity_epoch"], scope["trust_domain_id"], tuple(alternatives))


def small_original_history(sequence, end=2):
    """Only a small control joins records; never used for long-window testing."""
    from app.control_plane.r1_validation import ChainBoundary, CoreHistory, HistoryEvidence
    operations = sequence.operations[:end]
    authority = {"header": decode(operations[0].authority_header_wire), "events": [], "records": {}}
    core = {"header": decode(operations[0].core_header_wire), "events": [], "records": {}}
    for operation in operations:
        authority["events"].extend(decode(wire) for wire in operation.authority_events)
        authority["records"].update({key: decode(wire) for key, wire in operation.authority_records})
        core["events"].extend(decode(wire) for wire in operation.core_complete_events)
        core["records"].update({key: decode(wire) for key, wire in operation.core_records})
    boundary = ChainBoundary(sequence.identity_wire, operations[0].before_wire, operations[-1].after_wire,
        sequence.owner_identity, sequence.owner_version, sequence.continuity_epoch,
        sequence.deployment.storage_generation_id, sequence.deployment.control_plane_generation_id, sequence.trust_domain_id)
    return HistoryEvidence(tuple(row.request_wire for row in operations), c2(authority),
        (CoreHistory(sequence.deployment.runtime_principal, c2(core)),),
        source_admission_wires=tuple(row.source_admission_wire for row in operations)), boundary


def slice_for(operations, *, core=False, completed=False):
    from app.control_plane._r1_validation_stream import RegistrySlice
    header = operations[0].core_header_wire if core else operations[0].authority_header_wire
    events, records = [], {}
    for op in operations:
        wires = op.core_complete_events if completed else op.core_prior_events
        events.extend(wires if core else op.authority_events)
        records.update(dict(op.core_records if core else op.authority_records))
    return RegistrySlice(header, tuple(events), tuple(records.items()))


def window_evidence(sequence, operations, *, completed=False):
    from app.control_plane._r1_validation_stream import WindowEvidence
    return WindowEvidence(tuple(op.request_wire for op in operations), slice_for(operations),
        ((sequence.deployment.runtime_principal, slice_for(operations, core=True, completed=completed)),),
        source_admission_wires=tuple(op.source_admission_wire for op in operations))


def boundary_for(sequence, operations):
    from app.control_plane.r1_validation import ChainBoundary
    return ChainBoundary(sequence.identity_wire, operations[0].before_wire, operations[-1].after_wire,
        sequence.owner_identity, sequence.owner_version, sequence.continuity_epoch,
        sequence.deployment.storage_generation_id, sequence.deployment.control_plane_generation_id, sequence.trust_domain_id)


def input_for(sequence, op):
    from app.r1_atomic_finish import FinishInput
    return FinishInput(op.operation_id, window_evidence(sequence, (op,)), h2(decode(op.permit_wire)),
                       boundary_for(sequence, (op,)))


def scope_for(sequence):
    material = sequence.deployment
    return c2({"identity": decode(sequence.identity_wire), "core_installation_id": material.core_installation_id,
        "storage_generation_id": material.storage_generation_id, "control_plane_generation_id": material.control_plane_generation_id,
        "trust_domain_id": sequence.trust_domain_id, "owner_identity": sequence.owner_identity,
        "owner_version": sequence.owner_version, "continuity_epoch": sequence.continuity_epoch})


def merge_test_source(configured, persisted):
    """Merge authentic public slices by original positions, never re-numbering."""
    from app.control_plane._r1_validation_stream import RegistrySlice
    if persisted is None:
        return configured
    if configured.header_wire != persisted.header_wire:
        raise ValueError("synthetic source header conflict")
    events = {decode(w)["position"]["event_sequence"]: w for w in persisted.event_wires}
    records = dict(persisted.record_wires)
    for wire in configured.event_wires:
        position = decode(wire)["position"]["event_sequence"]
        if position in events and events[position] != wire:
            # Send conflicting authentic delta to product for fail-closed
            # conflict handling; the fixture does not decide admissibility.
            return configured
        events[position] = wire
    for key, wire in configured.record_wires:
        if key in records and records[key] != wire:
            return configured
        records[key] = wire
    return RegistrySlice(configured.header_wire, tuple(events[n] for n in sorted(events)), tuple(records.items()))


class WindowSource:
    """Test-only authenticated source and clock; product decides qualification."""
    def __init__(self, sequence, operation, *, now=None):
        self.sequence, self.operation = sequence, operation
        self.clock = operation.now if now is None else now
        self.authority = slice_for((operation,))
        self.core = slice_for((operation,), core=True)

    def capture(self, operation_id, action, *, local_history=None, authority_history=None):
        from app.r1_atomic_finish import TrustedLocalContext
        permit = decode(self.operation.permit_wire)
        return TrustedLocalContext(self.authority, self.core, self.sequence.deployment.runtime_principal,
            permit["session_id"], permit["policy_digest"], permit["inventory_digest"], self.clock)

    def now_ms(self):
        return self.clock


def open_window_service(path, sequence, operation, *, create=False, now=None, hook=None):
    from app._r1_scoped_sqlite import ScopedSQLiteStore
    from app.control_plane.r1_validation import FixedTrust
    from app.r1_atomic_finish import ScopedCoreFinisher
    store = (ScopedSQLiteStore.create(path, scope_wire=scope_for(sequence),
        checkpoint_wire=sequence.operations[0].before_wire, business_state_wire=c2({}), busy_timeout_ms=30000)
        if create else ScopedSQLiteStore.open(path, expected_scope_wire=scope_for(sequence), busy_timeout_ms=30000))
    return ScopedCoreFinisher(store, trust=FixedTrust(sequence.pin_wire, sequence.root_public_key),
        deployments=(sequence.deployment,), runtime_principal=sequence.deployment.runtime_principal,
        source=WindowSource(sequence, operation, now=now), checkpoint_hook=hook)
