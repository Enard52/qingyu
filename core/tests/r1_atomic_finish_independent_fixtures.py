"""Non-author local-finish inputs; bytes/signatures come from our own builder.

The preceding slice's independent builder encodes C2/H2/S2 and the complete
qualification history itself. This module never invokes an author fixture or
the product codec to construct expected results. Private test keys stay in
memory; persisted cases contain public bytes only.
"""
from copy import deepcopy
import json
from pathlib import Path
from uuid import uuid4

from tests.r1_validation_completion_independent_fixtures import (
    IndependentHistory, append_event, h, observe, raw, wire,
)


TEST_ROOT = Path(__file__).resolve().parents[1] / ".tmp" / "r1-slice-02-completion-20260916T193823Z" / "independent"


def new_case(decision="COMMIT", seed=810000):
    world = IndependentHistory(seed=seed, initial_state=7)
    row = world.add_operation(decision)
    # An Authority terminal and issued permit already exist. This local Core
    # has persisted its real proposal/publication/observations, but NOT APPLY.
    expected_completion = deepcopy(row["completion"])
    expected_event = deepcopy(world.core["events"][-1])
    assert expected_event["event_kind"] == "APPLY"
    world.core["events"].pop()
    # Retaining harmless immutable supporting records does not assert an event.
    evidence, trust, deployments = world.product_inputs()
    return {
        "world": world, "row": row, "evidence": evidence, "trust": trust,
        "deployments": deployments, "core_wire": wire(world.core),
        "expected_completion": expected_completion,
        "expected_event": expected_event,
        "expected_result_wire": wire(row["request"][decision.lower()]["result"]),
        "expected_audit_wire": wire(row["audit"]),
        "expected_receipt_wire": wire(row["receipt"]),
        "now": row["use_snapshot"]["checked_at"],
    }


def fresh_database_path():
    # Unique ownership per run; no cleanup or existing DB is opened here.
    root = TEST_ROOT.resolve()
    expected = Path(__file__).resolve().parents[1] / ".tmp" / "r1-slice-02-completion-20260916T193823Z" / "independent"
    assert root == expected.resolve()
    root.mkdir(parents=True, exist_ok=True)
    directory = root / uuid4().hex
    directory.mkdir()
    (directory / "ownership.txt").write_text("R1_CORE_LOCAL_ATOMIC_FINISH_SLICE_02_COMPLETION independent test\n", encoding="utf-8")
    return directory / "local.sqlite"


def append_local_revoke(case, *, at=None):
    world, row = case["world"], case["row"]
    at = case["now"] - 1 if at is None else at
    revocation = {"history_version": 2, "object_digest": raw(row["session"])}
    append_event(world.core, "LOCAL_SESSION_REVOKE", at, revocation)
    evidence, _, _ = world.product_inputs()
    case["evidence"] = evidence
    case["core_wire"] = wire(world.core)
    return case


def reobserve_original_session(case):
    world, row = case["world"], case["row"]
    source = next(e for e in world.authority["events"] if e["event_kind"] == "SESSION_CREATE")
    observe(world.core, source, row["session"], "SESSION_OBSERVED", case["now"])
    case["evidence"] = world.product_inputs()[0]
    case["core_wire"] = wire(world.core)
    return case


class IndependentSource:
    """Synthetic authenticated source, deliberately outside FinishInput.

    It supplies exact real signed public evidence, a separately chosen clock and
    an authenticated subject. Product qualification checks remain enabled.
    """

    def __init__(self, case):
        self.case = case
        self.clock = case["now"]
        self.principal = case["world"].deployment["runtime_principal"]
        self.session_id = case["row"]["session"]["session_id"]
        self.policy_digest = h(case["row"]["policy"])
        self.inventory_digest = h(case["row"]["inventory"])
        self.revoke = False
        self.reobserve = False

    def now_ms(self):
        return self.clock

    def capture(self, operation_id, action, *, local_history=None, authority_history=None):
        from app.r1_atomic_finish import TrustedLocalContext
        if local_history is not None and not isinstance(local_history, bytes):
            core = {"header": json.loads(local_history.header_wire),
                    "events": [json.loads(w) for w in local_history.event_wires],
                    "records": {digest: json.loads(w) for digest, w in local_history.record_wires}}
        else:
            core = json.loads(local_history or self.case["core_wire"])
        if self.revoke and not any(e["event_kind"] == "LOCAL_SESSION_REVOKE" for e in core["events"]):
            append_event(core, "LOCAL_SESSION_REVOKE", self.clock,
                         {"history_version": 2, "object_digest": raw(self.case["row"]["session"])})
            if self.reobserve:
                event = next(e for e in self.case["world"].authority["events"] if e["event_kind"] == "SESSION_CREATE")
                observe(core, event, self.case["row"]["session"], "SESSION_OBSERVED", self.clock)
        return TrustedLocalContext(
            authority_history=wire(self.case["world"].authority), core_history=wire(core),
            runtime_principal=self.principal, session_id=self.session_id,
            policy_digest=self.policy_digest, inventory_digest=self.inventory_digest,
            checked_at=self.clock,
        )


def scope_wire(case):
    world = case["world"]
    return wire({"identity": world.identity,
                 **{k: world.deployment[k] for k in ("core_installation_id", "storage_generation_id", "control_plane_generation_id")},
                 "trust_domain_id": world.trust_domain_id,
                 "owner_identity": world.owner, "owner_version": world.owner_version,
                 "continuity_epoch": world.continuity_epoch})


def create_service(case, *, source=True, hook=None, store_scope=None):
    from app._r1_scoped_sqlite import ScopedSQLiteStore
    from app.r1_atomic_finish import FinishInput, ScopedCoreFinisher
    store = ScopedSQLiteStore.create(fresh_database_path(), scope_wire=scope_wire(case) if store_scope is None else store_scope,
                                    checkpoint_wire=wire(case["row"]["before"]), business_state_wire=wire({}))
    provider = IndependentSource(case) if source is True else source
    service = ScopedCoreFinisher(store, trust=case["trust"], deployments=case["deployments"],
                                runtime_principal=case["world"].deployment["runtime_principal"],
                                source=provider, checkpoint_hook=hook)
    request = FinishInput(case["row"]["request"]["intent"]["operation_id"], case["evidence"], h(case["row"]["permit"]),
                          chain_boundary=case["world"].boundary())
    return service, store, provider, request
