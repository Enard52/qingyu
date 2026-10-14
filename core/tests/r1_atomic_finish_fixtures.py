"""Slice 02 synthetic issuer material; only public data reaches worker processes.

Real temporary Ed25519 keys live only in the existing in-memory issuer builders.
These providers describe test-controlled authentication/time/registry sources;
they are not production Authority, registry synchronization or OS admission.
"""
from copy import deepcopy
from dataclasses import dataclass, replace

from app.control_plane.r1_validation import CoreHistory, HistoryEvidence, ChainBoundary
from app.control_plane.r1_validation_codec import c2, decode, h2
from tests.r1_validation_fixtures import build_world
from tests.r1_validation_restore_fixtures import build_restore_world


@dataclass(frozen=True)
class PublicCase:
    operation_id: str
    request_wire: bytes
    evidence: HistoryEvidence
    trust: object
    deployments: tuple
    deployment: object
    boundary: ChainBoundary
    restore_evidence: tuple
    core_history: bytes
    authority_history: bytes
    session_id: str
    now: int
    permit_wire: bytes
    terminal_wire: bytes
    target_wire: bytes
    before_wire: bytes
    after_wire: bytes
    effect_wire: bytes
    result_wire: bytes
    audit_wire: bytes
    original_completion_wire: bytes


def without_last_apply(core):
    core = deepcopy(core)
    last = core["events"].pop()
    if last["event_kind"] != "APPLY":
        raise AssertionError("synthetic issuer builder expected final APPLY")
    # Records are original bytes, including candidates. Only the nonexistent
    # local completion and use snapshot are removed, not prior observations.
    core["records"].pop(last["output_digest"], None)
    core["records"].pop(last["input_digest"], None)
    return core


def public_case(world=None, *, decision="COMMIT", override=False, restore=False):
    if restore:
        restored = build_restore_world(decision, override=override)
        world = restored.world
        objects, evidence = restored.objects, restored.history
        deployment, deployments = restored.target, restored.deployments
        core = without_last_apply(objects["core"])
        evidence = replace(evidence, core_histories=(*evidence.core_histories[:-1],
            CoreHistory(deployment.runtime_principal, c2(core))))
        boundary, proofs, now = restored.boundary, (restored.proof,), 2500
    else:
        world = world or build_world(decision, override=override)
        objects, evidence = world.objects, world.evidence()
        deployment, deployments = world.deployment, (world.deployment,)
        core = without_last_apply(world.core)
        evidence = replace(evidence, core_histories=(CoreHistory(deployment.runtime_principal, c2(core)),))
        intent, scope = world.request["intent"], world.request["intent"]["scope"]
        boundary = ChainBoundary(c2(intent["identity"]), c2(objects["before"]), c2(objects["after"]),
            scope["actor_identity"], scope["owner_version"], scope["continuity_epoch"],
            scope["storage_generation_id"], scope["control_plane_generation_id"], scope["trust_domain_id"])
        proofs, now = (), objects["completion"]["completed_at"]
    receipt = world.objects["receipt"]
    selected = world.request[receipt["decision"].lower()]
    permit = objects["permit"]
    return PublicCase(receipt["operation_id"], c2(world.request), evidence, world.trust, deployments,
        deployment, boundary, proofs, c2(core), evidence.authority_history, permit["session_id"], now,
        c2(permit), c2(receipt), c2(objects["target"]), c2(objects["target"]["before_checkpoint"]),
        c2(objects["target"]["after_checkpoint"]), c2(selected["effect"]), c2(selected["result"]),
        c2(world.objects["audit"]), c2(objects["completion"]))


def public_chain(decisions=("COMMIT", "ABORT")):
    worlds, cases = [], []
    for index, decision in enumerate(decisions):
        world = build_world(decision, parent=worlds[-1] if worlds else None,
            id_offset=index * 100, time_offset=index * 2000)
        worlds.append(world)
        case = public_case(world)
        history = replace(case.evidence, request_wires=tuple(c2(w.request) for w in worlds),
            source_admission_wires=tuple(c2(w.objects["source_admission"]) for w in worlds))
        boundary = replace(case.boundary, start_checkpoint_wire=cases[0].before_wire if cases else case.before_wire)
        cases.append(replace(case, evidence=history, boundary=boundary))
    return tuple(cases)


def scope_wire(case):
    intent = decode(case.request_wire)["intent"]
    return c2({"identity": intent["identity"], "core_installation_id": case.deployment.core_installation_id,
        "storage_generation_id": case.deployment.storage_generation_id,
        "control_plane_generation_id": case.deployment.control_plane_generation_id,
        "trust_domain_id": intent["scope"]["trust_domain_id"],
        "owner_identity": case.boundary.owner_identity,
        "owner_version": case.boundary.owner_version,
        "continuity_epoch": case.boundary.continuity_epoch})


def finish_input(case):
    from app.r1_atomic_finish import FinishInput
    return FinishInput(case.operation_id, case.evidence, h2(decode(case.permit_wire)),
        case.boundary, case.restore_evidence)


class SyntheticSource:
    """Test admission source, independently installed before invoking the input.

    It merges only authenticated extension histories and retains persisted local
    APPLY. It never provides a bypass boolean or decides product eligibility.
    """
    def __init__(self, case, *, now=None, session_id=None, runtime_principal=None):
        self.case = case
        self.clock = case.now if now is None else now
        self.session_id = case.session_id if session_id is None else session_id
        self.runtime_principal = case.deployment.runtime_principal if runtime_principal is None else runtime_principal
        self.core_history = case.core_history
        self.authority_history = case.authority_history

    @staticmethod
    def _extend(configured, persisted):
        if persisted is not None and type(persisted) is not bytes:
            from app.control_plane._r1_validation_stream import RegistrySlice
            from tests.r1_window_fixtures import merge_test_source
            value = decode(configured)
            supplied = RegistrySlice(c2(value["header"]), tuple(c2(v) for v in value["events"]),
                                     tuple((key, c2(v)) for key, v in value["records"].items()))
            return merge_test_source(supplied, persisted)
        if persisted is None:
            return configured
        old, new = decode(persisted), decode(configured)
        if old["header"] != new["header"]:
            raise ValueError("test registry source target mismatch")
        shorter, longer = sorted((old, new), key=lambda value: len(value["events"]))
        if longer["events"][:len(shorter["events"])] != shorter["events"]:
            raise ValueError("test registry source refuses non-prefix history")
        # The source may preinstall candidate records without claiming their
        # execution. Preserve all exact prior records when extending events.
        combined = deepcopy(shorter["records"])
        for key, value in longer["records"].items():
            if key in combined and combined[key] != value:
                raise ValueError("test registry source record collision")
            combined[key] = value
        return c2({**longer, "records": combined})

    def capture(self, operation_id, action, *, local_history=None, authority_history=None):
        from app.r1_atomic_finish import TrustedLocalContext
        permit = decode(self.case.permit_wire)
        return TrustedLocalContext(self._extend(self.authority_history, authority_history),
            self._extend(self.core_history, local_history), self.runtime_principal, self.session_id,
            permit["policy_digest"], permit["inventory_digest"], self.clock)

    def now_ms(self):
        return self.clock


def open_finisher(path, case, *, create=False, source=None, hook=None, busy_timeout_ms=5000):
    from app.r1_atomic_finish import ScopedCoreFinisher
    from app._r1_scoped_sqlite import ScopedSQLiteStore
    if create:
        store = ScopedSQLiteStore.create(path, scope_wire=scope_wire(case), checkpoint_wire=case.before_wire,
            business_state_wire=c2({}), busy_timeout_ms=busy_timeout_ms)
    else:
        store = ScopedSQLiteStore.open(path, expected_scope_wire=scope_wire(case), busy_timeout_ms=busy_timeout_ms)
    return ScopedCoreFinisher(store, trust=case.trust, deployments=case.deployments,
        runtime_principal=case.deployment.runtime_principal, source=source or SyntheticSource(case), checkpoint_hook=hook)
