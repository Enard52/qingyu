"""Reviewer-owned raw windows; no product codec creates expected evidence.

Reuses this reviewer's previous from-zero signing/event builder. Synthetic
private keys remain in memory and are never written to a case or subprocess.
"""
from copy import deepcopy
from dataclasses import replace
import json

from tests.r1_validation_completion_independent_fixtures import (
    IndependentHistory, append_event, h, observe, raw, sign, typed, wire,
)


def unpack_registry(value):
    if type(value) is bytes:
        return json.loads(value)
    return {"header": json.loads(value.header_wire),
            "events": [json.loads(x) for x in value.event_wires],
            "records": {digest: json.loads(x) for digest, x in value.record_wires}}


def registry_slice(registry, *, start=0, old_keys=()):
    from app.control_plane._r1_validation_stream import RegistrySlice
    old_keys = set(old_keys)
    return RegistrySlice(wire(registry["header"]),
                         tuple(wire(x) for x in registry["events"][start:]),
                         tuple((k, wire(v)) for k, v in sorted(registry["records"].items()) if k not in old_keys))


class IndependentWindowChain:
    def __init__(self, seed=910000):
        self.world = IndependentHistory(seed=seed, initial_state=7)
        self.authority_count = self.core_count = 0
        self.authority_keys, self.core_keys = set(), set()

    def next(self, decision="COMMIT", *, faults=None, request_checkpoint=None):
        from app.control_plane._r1_validation_stream import WindowEvidence
        from app.control_plane.r1_validation import ChainBoundary, DeploymentEvidence
        from app.control_plane.r1_validation_crypto import FixedTrust
        from app.r1_atomic_finish import FinishInput
        world = self.world
        row = world.add_operation(decision, faults=faults, request_checkpoint=request_checkpoint)
        before_apply = {"header": world.core["header"], "events": world.core["events"][:-1], "records": world.core["records"]}
        authority = registry_slice(world.authority, start=self.authority_count, old_keys=self.authority_keys)
        core = registry_slice(before_apply, start=self.core_count, old_keys=self.core_keys)
        material = DeploymentEvidence(**world.deployment)
        evidence = WindowEvidence((wire(row["request"]),), authority,
                                  ((material.runtime_principal, core),),
                                  source_admission_wires=(wire(row["admission"]),))
        boundary = ChainBoundary(wire(world.identity), wire(row["before"]), wire(row["after"]), world.owner,
                                 world.owner_version, world.continuity_epoch, material.storage_generation_id,
                                 material.control_plane_generation_id, world.trust_domain_id)
        self.authority_count, self.core_count = len(world.authority["events"]), len(world.core["events"])
        self.authority_keys, self.core_keys = set(world.authority["records"]), set(world.core["records"])
        return {"world": world, "row": row, "input": FinishInput(row["request"]["intent"]["operation_id"], evidence, h(row["permit"]), boundary),
                "evidence": evidence, "trust": FixedTrust(wire(world.pin), world.root_public), "deployments": (material,),
                "authority": registry_slice(world.authority), "core": registry_slice(before_apply),
                "now": row["use_snapshot"]["checked_at"]}

    def query_context(self, rows):
        """Admit a new QUERY-only subject for original operations after expiry."""
        world = self.world
        latest = world.operations[-1]
        at = latest["use_snapshot"]["checked_at"] + 20000
        policy = deepcopy(latest["policy"])
        policy.update(policy_id=world.uid(900001), issued_at=at, expires_at=at + 40000,
                      capabilities=["QUERY_EXISTING"])
        policy = sign(policy, world.root_key)
        session = deepcopy(latest["session"])
        session.update(session_id=world.uid(900002), issued_at=at, expires_at=at + 40000)
        session["enrollment"]["policy_digest"] = h(policy)
        inventory = typed("recovery_inventory", inventory_id=world.uid(900003), policy_digest=h(policy),
                          core_installation_id=world.deployment["core_installation_id"],
                          runtime_principal=world.deployment["runtime_principal"], session_id=session["session_id"],
                          entries=[{"operation_id": r["request"]["intent"]["operation_id"], "request_digest": h(r["request"]),
                                    "source_decision_digest": h(r["request"]["source_decision"]),
                                    "local_commit_id": r["request"]["intent"]["local_commit_id"]} for r in rows])
        for kind, local_kind, value in (("POLICY_REGISTER", "POLICY_OBSERVED", policy), ("SESSION_CREATE", "SESSION_OBSERVED", session),
                                       ("INVENTORY_ACCEPT", "INVENTORY_OBSERVED", inventory)):
            event = append_event(world.authority, kind, at, value)
            observe(world.core, event, value, local_kind, at)
        append_event(world.core, "LOCAL_PROTECTION", at, {"history_version": 2, "policy_digest": h(policy),
                     "component_valid": True, "policy_active": True, "context_kind": "INTACT_ADMITTED"})
        return {"authority": registry_slice(world.authority), "core": registry_slice(world.core), "now": at,
                "principal": world.deployment["runtime_principal"], "session_id": session["session_id"],
                "policy_digest": h(policy), "inventory_digest": h(inventory)}


class IndependentWindowSource:
    """Local-only synthetic authenticated snapshots; no verification shortcut."""
    def __init__(self, case):
        self.set_case(case)

    def set_case(self, case):
        self.authority, self.core, self.clock = case["evidence"].authority, case["evidence"].cores[0][1], case["now"]
        self.principal = case["world"].deployment["runtime_principal"]
        self.session_id = case["row"]["session"]["session_id"]
        self.policy_digest, self.inventory_digest = h(case["row"]["policy"]), h(case["row"]["inventory"])

    def set_query(self, context):
        self.authority, self.core, self.clock = context["authority"], context["core"], context["now"]
        self.principal, self.session_id = context["principal"], context["session_id"]
        self.policy_digest, self.inventory_digest = context["policy_digest"], context["inventory_digest"]

    def now_ms(self):
        return self.clock

    def capture(self, operation_id, action, *, local_history=None, authority_history=None):
        from app.r1_atomic_finish import TrustedLocalContext
        # An authenticated original delta preserves absolute positions. The
        # product must join it to its journal and actual local APPLY itself.
        # No provider-side prefix test or whole-history filtering grants trust.
        return TrustedLocalContext(self.authority, self.core, self.principal,
                                   self.session_id, self.policy_digest, self.inventory_digest, self.clock)
