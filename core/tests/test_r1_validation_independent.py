"""Non-author checks: independent DAG rewriting and real in-memory signatures.

The author-owned builder supplies legal seeds only. Mutation selection, expected
relationships, C2/H2/RAW/S2 derivation and downstream rebinding below are separate
from product helpers and the builder's fault mechanism. No private key is saved.
"""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import unittest
from uuid import UUID

from app.control_plane.r1_validation import (
    CoreHistory, DeploymentEvidence, HistoryEvidence, MissingTrustedContext, UnsupportedOperation,
    validate_evidence,
)
from app.control_plane.r1_validation_codec import ContractError
from app.control_plane.r1_validation_crypto import verify_signed
from r1_validation_fixtures import build_world


OBSERVATIONS = []
ROOT_TYPES = {"abort_override", "opening_authorization", "recovery_policy", "restoration_context"}


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def raw_digest(value):
    return digest(canonical(value))


def typed_digest(value):
    return digest(b"QINGYU-R1-SCOPED-V2/" + value["type"].encode("ascii") + b"\0" + canonical(value))


def sign(value, world):
    result = deepcopy(value)
    field = "root_signature" if result["type"] in ROOT_TYPES else "receipt_signature"
    unsigned = {k: v for k, v in result.items() if k != field}
    data = b"QINGYU-R1-SCOPED-SIGN-V2/" + result["type"].encode("ascii") + b"\0" + canonical(unsigned)
    key = world.root if field == "root_signature" else world.receipt_key
    result[field] = key.sign(data).hex()
    return result


def seed_tree(world):
    return {"request": deepcopy(world.request), "authority": deepcopy(world.authority),
            "core": deepcopy(world.core), "contexts": list(deepcopy(world.contexts)),
            "admissions": [deepcopy(world.objects["source_admission"])]}


def rebind(world, edits):
    """Apply explicit raw-object edits, then propagate all digests and signatures.

    Original-object digests identify each mutation. Signed issuance projection
    preimages are derived independently even when absent from registry.records.
    A fixed point demonstrates that all downstream content has been recomputed.
    """
    original = seed_tree(world)
    mapping = {}
    previous = None
    for iteration in range(96):
        following = {}

        def visit(value):
            if type(value) is str:
                return mapping.get(value, value)
            if type(value) is list:
                return [visit(v) for v in value]
            if type(value) is not dict:
                return value
            changed = {mapping.get(k, k): visit(v) for k, v in value.items()}
            edit = edits.get(raw_digest(value))
            if edit:
                changed.update(deepcopy(edit))
            if "type" in value and ("root_signature" in value or "receipt_signature" in value):
                changed = sign(changed, world)
                if "issuance_digest" in value:
                    old_projection = {k: v for k, v in value.items() if k not in ("issuance_digest", "receipt_signature")}
                    new_projection = {k: v for k, v in changed.items() if k not in ("issuance_digest", "receipt_signature")}
                    following[raw_digest(old_projection)] = raw_digest(new_projection)
            following[raw_digest(value)] = raw_digest(changed)
            if "type" in value and "version" in value:
                following[typed_digest(value)] = typed_digest(changed)
            return changed

        transformed = visit(original)
        if transformed == previous:
            return transformed, iteration
        previous = transformed
        mapping = following
    raise AssertionError("independent DAG rewriting did not converge")


def evidence(tree, world):
    return HistoryEvidence((canonical(tree["request"]),) + tuple(canonical(v) for v in tree.get("extra_requests", [])), canonical(tree["authority"]),
                           (CoreHistory(world.deployment.runtime_principal, canonical(tree["core"])),)
                           + tuple(CoreHistory(principal, canonical(reg)) for principal, reg in tree.get("extra_cores", [])),
                           tuple(canonical(v) for v in tree["contexts"]),
                           tuple(canonical(v) for v in tree["admissions"]))


def integrity(tree, world):
    """Check actual hash links and real signatures without semantic helpers."""
    seen = set()
    for registry in (tree["authority"], tree["core"], *(r for _, r in tree.get("extra_cores", []))):
        records = registry["records"]
        for key, value in records.items():
            allowed = {raw_digest(value)}
            if "type" in value and "version" in value:
                allowed.add(typed_digest(value))
            assert key in allowed, "independent registry key/preimage mismatch"
            if "receipt_signature" in value or "root_signature" in value:
                result = verify_signed(value, world.trust)
                assert result.object_digest == typed_digest(value)
                seen.add(result.object_digest)
        for event in registry["events"]:
            assert raw_digest(records[event["input_digest"]]) == event["input_digest"]
            out = event["output_digest"]
            if out is not None:
                value = records[out]
                assert (typed_digest(value) if "type" in value else raw_digest(value)) == out
    for context in tree["contexts"]:
        seen.add(verify_signed(context, world.trust).object_digest)
    return len(seen)


def observe(label, expected, operation, tree, world, *, prefix_only=False, extra_deployments=()):
    item = evidence(tree, world)
    if prefix_only:
        item = HistoryEvidence(item.request_wires, item.authority_history, (), item.context_wires, item.source_admission_wires)
    before = deepcopy(item)
    signature_count = integrity(tree, world)
    try:
        result = validate_evidence(operation, item, world.trust, (world.deployment,) + extra_deployments)
        actual, detail = "ACCEPT", asdict(result)
    except ContractError as exc:
        actual, detail = "REJECT", {"exception": type(exc).__name__, "message": str(exc)}
    row = {"label": label, "expected": expected, "actual": actual, "detail": detail,
           "operation": operation, "real_signature_count": signature_count,
           "input_unchanged": item == before, "input": asdict(item),
           "fixed_pin": world.pin, "root_public_key": world.trust.root_public_key,
           "deployment": asdict(world.deployment), "extra_deployments": [asdict(d) for d in extra_deployments]}
    OBSERVATIONS.append(row)
    return row


def restore_history(world, *, contradictory_identity=False):
    """Independently add a restore-only subject/permit/use to an existing terminal.

    No source archive or original backup proof is provided: current API has no
    such input. Both this missing-scope case and an explicit identity contradiction
    must fail closed, rather than receiving whole-history semantic success.
    """
    tree = seed_tree(world)
    uid = lambda number: str(UUID(int=number))
    typed = lambda name, **values: {"type": name, "version": 2, **values}
    material = DeploymentEvidence("restored-review", uid(300), uid(301), uid(302),
                                  b"independent-restored-deployment", b"independent-restored-code", world.deployment.tls_spki_der)
    scope = {"registry_kind": "CORE_LOCAL", **{k: world.pin[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation")},
             **{k: getattr(material, k) for k in ("core_installation_id", "storage_generation_id", "control_plane_generation_id")}}
    header = {"history_version": 2, "registry_id": str(UUID(bytes=hashlib.sha256(b"QINGYU-R1-SCOPED-REGISTRY-V2\0" + canonical(scope)).digest()[:16])),
              **scope, "provenance_digest": digest(material.deployment_bytes)}
    local = {"header": header, "events": [], "records": {}}
    authority = tree["authority"]
    def pos(reg):
        return {"history_version": 2, "registry_digest": raw_digest(reg["header"]), "event_sequence": len(reg["events"]) + 1}
    def put(reg, value):
        d = typed_digest(value) if "type" in value else raw_digest(value)
        reg["records"][d] = deepcopy(value)
        return d
    def event(reg, kind, at, inp, out=None):
        reg["records"][raw_digest(inp)] = deepcopy(inp)
        put(reg, inp)
        result = {"history_version": 2, "position": pos(reg), "recorded_at": at, "event_kind": kind,
                  "input_digest": raw_digest(inp), "output_digest": put(reg, out) if out is not None else None}
        reg["events"].append(result)
        return result
    request, receipt = tree["request"], world.objects["receipt"]
    ident = request["intent"]["identity"]
    before, after = world.objects["before"], world.objects["after"]
    source_identity = deepcopy(ident)
    if contradictory_identity:
        source_identity["qingyu_identity_id"] = uid(999)
    source = typed("source_snapshot", source_kind="V2_GENERATION_RESTORE", identity=source_identity,
                   **{"source_" + k: world.pin[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation")},
                   authority_tip=after["authority_ref"], audit_tip=after["audit_ref"], state_version=after["state_version"],
                   owner_identity=request["intent"]["scope"]["actor_identity"], owner_version=1, continuity_epoch=1,
                   storage_generation_id=world.deployment.storage_generation_id, control_plane_generation_id=world.deployment.control_plane_generation_id,
                   signed_origin_digest="c" * 64, history_archive_digest="d" * 64, operation_inventory_digest="e" * 64,
                   source_deployment_digest=digest(world.deployment.deployment_bytes), source_fencing_evidence_digest="f" * 64, captured_at=1400)
    context = sign(typed("restoration_context", context_id=uid(310), identity=ident, source_snapshot=source,
                         target_core_installation_id=material.core_installation_id, target_storage_generation_id=material.storage_generation_id,
                         target_control_plane_generation_id=material.control_plane_generation_id, target_authority_pin_digest=typed_digest(world.pin),
                         restore_start_checkpoint=before, restore_source_state_digest="a" * 64,
                         allowed_actions=["APPLY_VERIFIED_TERMINAL", "VERIFY_HISTORY"], issued_at=1500, expires_at=50000,
                         reason="Independent supplied restore context without archive/backup evidence", operator_root_key_id=world.pin["operator_root_key_id"], root_signature="0" * 128), world)
    policy = deepcopy(world.objects["policy"])
    policy.update(policy_id=uid(311), restoration_context_digest=typed_digest(context), issued_at=1500, expires_at=50000,
                  capabilities=["APPLY_VERIFIED_TERMINAL", "PERSIST_COORDINATION", "QUERY_EXISTING"],
                  deployment_admission_digest=digest(material.deployment_bytes), component_artifact_digest=digest(material.component_bytes),
                  **{k: getattr(material, k) for k in ("runtime_principal", "core_installation_id", "storage_generation_id", "control_plane_generation_id")})
    policy = sign(policy, world)
    enrollment = {k: policy[k] for k in ("runtime_principal", "core_installation_id", "restoration_context_digest", "authority_domain_id", "authority_instance_id", "authority_generation", "storage_generation_id", "control_plane_generation_id", "deployment_admission_digest", "component_artifact_digest", "trust_config_digest")}
    enrollment.update(policy_digest=typed_digest(policy), context_kind="MANUAL_RESTORE_ADMITTED", purpose="MUTATION_RECOVERY", identity_digest=typed_digest(ident))
    session = {"history_version": 2, "session_id": uid(312), "enrollment": enrollment, "issued_at": 1600, "expires_at": 50000}
    common = {"operation_id": request["intent"]["operation_id"], "request_digest": typed_digest(request), "source_decision_digest": typed_digest(request["source_decision"])}
    inventory = typed("recovery_inventory", inventory_id=uid(313), policy_digest=typed_digest(policy), core_installation_id=material.core_installation_id,
                      runtime_principal=material.runtime_principal, session_id=session["session_id"], entries=[{**common, "local_commit_id": request["intent"]["local_commit_id"]}])
    observed = []
    for kind, value in (("POLICY_REGISTER", policy), ("SESSION_CREATE", session), ("INVENTORY_ACCEPT", inventory)):
        observed.append((event(authority, kind, 1600, value), value))
    binding = {"runtime_principal": material.runtime_principal, "session_id": session["session_id"], "policy_digest": typed_digest(policy), "inventory_digest": typed_digest(inventory)}
    target = {"history_version": 2, "identity_digest": typed_digest(ident), "authority_pin_digest": typed_digest(world.pin),
              **{k: policy[k] for k in ("core_installation_id", "storage_generation_id", "control_plane_generation_id", "restoration_context_digest")},
              **common, "terminal_digest": typed_digest(receipt), "before_checkpoint": before, "after_checkpoint": after}
    permit_body = typed("local_finish_permit", contract_revision=2, permit_id=uid(314), permit_sequence=1, **binding, **common,
                        restoration_context_digest=typed_digest(context), core_installation_id=material.core_installation_id, terminal_digest=typed_digest(receipt),
                        before_checkpoint=before, after_checkpoint=after, issued_at=1700, expires_at=15000, receipt_key_id=world.pin["receipt_key_id"])
    issuance = {"history_version": 2, "position": pos(authority), "issued_at": 1700, "issuance_kind": "PERMIT", "issuer_key_id": world.pin["receipt_key_id"],
                **binding, **common, "restoration_context_digest": typed_digest(context), "issue_body_digest": raw_digest(permit_body), "fences_or_target_digest": raw_digest(target)}
    permit = sign({**permit_body, "issuance_digest": raw_digest(issuance), "receipt_signature": "0" * 128}, world)
    put(authority, target)
    observed.append((event(authority, "PERMIT_ISSUED", 1700, issuance, permit), permit))
    for (original, value), kind in zip(observed, ("POLICY_OBSERVED", "SESSION_OBSERVED", "INVENTORY_OBSERVED", "PERMIT_OBSERVED")):
        observation = {"history_version": 2, "authority_position": original["position"], "authority_event_digest": raw_digest(original),
                       "object_digest": typed_digest(value) if "type" in value else raw_digest(value)}
        event(local, kind, 1750, observation)
    event(local, "LOCAL_PROTECTION", 1750, {"history_version": 2, "policy_digest": typed_digest(policy), "component_valid": True, "policy_active": True, "context_kind": "MANUAL_RESTORE_ADMITTED"})
    selected = request[receipt["decision"].lower()]
    audit = typed("audit_record", candidate=selected["audit_candidate"], receipt_digest=typed_digest(receipt))
    content = {"effect_digest": typed_digest(selected["effect"]), "result_digest": typed_digest(selected["result"]), "audit_record_digest": typed_digest(audit)}
    use = {"history_version": 2, "permit_digest": typed_digest(permit), "issuance_digest": raw_digest(issuance), "target_digest": raw_digest(target), "terminal_digest": typed_digest(receipt), **content}
    put(local, target); put(local, use)
    snapshot = {"history_version": 2, "position": pos(local), "checked_at": 1800, "action": "APPLY_VERIFIED_TERMINAL", **binding, **common,
                "target_digest": raw_digest(target), "action_input_digest": raw_digest(use)}
    completion = {"history_version": 2, "position": pos(local), "completed_at": 1800, "permit_digest": typed_digest(permit), "issuance_digest": raw_digest(issuance),
                  "local_use_digest": raw_digest(snapshot), **common, "terminal_digest": typed_digest(receipt), "target_digest": raw_digest(target),
                  "before_checkpoint": before, "after_checkpoint": after, **content}
    event(local, "APPLY", 1800, snapshot, completion)
    tree["contexts"] = [context]
    tree["extra_cores"] = [(material.runtime_principal, local)]
    return tree, material


class IndependentProductTests(unittest.TestCase):
    def assert_outcome(self, row):
        self.assertEqual(row["actual"], row["expected"], row["detail"])
        self.assertTrue(row["input_unchanged"])

    def test_legal_seeds_leave_provenance_and_current_qualification_unverified(self):
        for decision, override in (("COMMIT", False), ("ABORT", False), ("COMMIT", True)):
            world = build_world(decision=decision, override=override)
            row = observe(f"legal_{decision}_{override}", "ACCEPT", "COMPLETION_HISTORY", seed_tree(world), world)
            self.assert_outcome(row)
            self.assertEqual(row["detail"]["history_origin"], "UNVERIFIED")
            self.assertEqual(row["detail"]["current_eligibility"], "NOT_EVALUATED")

    def test_real_signature_and_recomputed_dag_do_not_legalize_wrong_ack_identity(self):
        world = build_world()
        tree, rounds = rebind(world, {raw_digest(world.objects["ack"]): {"identity_digest": "e" * 64}})
        row = observe("signed_valid_ack_wrong_identity", "REJECT", "COMPLETION_HISTORY", tree, world)
        row["rebind_rounds"] = rounds
        self.assertGreater(row["real_signature_count"], 0)
        self.assert_outcome(row)
        self.assertIn("Ack", row["detail"]["message"])

    def test_recomputed_publication_original_operation_is_rejected(self):
        world = build_world()
        tree = seed_tree(world)
        core = tree["core"]
        payload = {**world.objects["publication_input"], "operation_id": str(UUID(int=999))}
        snapshot = {**world.objects["publication_snapshot"], "action_input_digest": raw_digest(payload)}
        core["records"][raw_digest(payload)] = payload
        core["records"][raw_digest(snapshot)] = snapshot
        next(e for e in core["events"] if e["event_kind"] == "PUBLICATION")["input_digest"] = raw_digest(snapshot)
        row = observe("publication_wrong_original_operation", "REJECT", "COMPLETION_HISTORY", tree, world)
        row["original_authority_unchanged"] = tree["authority"] == world.authority
        self.assert_outcome(row)
        self.assertIn("publication action original source", row["detail"]["message"])

    def test_restore_without_required_source_proof_fails_closed(self):
        for wrong_identity in (False, True):
            with self.subTest(wrong_identity=wrong_identity):
                world = build_world(complete=False)
                tree, material = restore_history(world, contradictory_identity=wrong_identity)
                row = observe("restore_missing_source_proof" + ("_and_wrong_identity" if wrong_identity else ""), "REJECT",
                              "COMPLETION_HISTORY", tree, world, extra_deployments=(material,))
                self.assert_outcome(row)
                self.assertEqual(row["detail"]["exception"], "MissingTrustedContext")

    def test_source_admission_cannot_be_replaced_by_a_matching_request(self):
        for kind in ("missing", "wrong_actor", "wrong_installation", "session_expired_at_admission"):
            with self.subTest(kind=kind):
                world = build_world()
                tree = seed_tree(world)
                if kind == "missing":
                    tree["admissions"] = []
                elif kind == "wrong_actor":
                    tree["admissions"][0]["actor_identity"] = "different-original-caller"
                elif kind == "wrong_installation":
                    tree["admissions"][0]["core_installation_id"] = str(UUID(int=999))
                else:
                    tree["admissions"][0]["session_expires_at"] = tree["admissions"][0]["admitted_at"]
                row = observe("original_admission_" + kind, "REJECT", "COMPLETION_HISTORY", tree, world)
                self.assert_outcome(row)
                self.assertIn("source", row["detail"]["message"])

    def test_multiple_operations_require_an_independent_chain_boundary(self):
        world = build_world()
        tree = seed_tree(world)
        tree["extra_requests"] = [deepcopy(tree["request"])]
        row = observe("exact_duplicate_request_bytes", "ACCEPT", "COMPLETION_HISTORY", tree, world)
        self.assert_outcome(row)
        other = deepcopy(tree["request"])
        other["intent"]["operation_id"] = str(UUID(int=999))
        other["source_decision"]["intent_digest"] = typed_digest(other["intent"])
        for branch in ("commit", "abort"):
            audit = other[branch]["audit_candidate"]
            audit.update(operation_id=other["intent"]["operation_id"], intent_digest=typed_digest(other["intent"]),
                         source_decision_digest=typed_digest(other["source_decision"]))
        tree["extra_requests"] = [other]
        row = observe("multiple_distinct_operation_scope", "REJECT", "REGISTRY_RELATIONS", tree, world)
        self.assert_outcome(row)
        self.assertEqual(row["detail"]["exception"], "MissingTrustedContext")

    def test_valid_root_signature_cannot_rebind_override_operation(self):
        world = build_world(override=True)
        tree, rounds = rebind(world, {raw_digest(world.objects["authorization"]): {"operation_id": str(UUID(int=999))}})
        row = observe("signed_valid_override_wrong_operation", "REJECT", "COMPLETION_HISTORY", tree, world)
        row["rebind_rounds"] = rounds
        self.assert_outcome(row)
        self.assertIn("operator ABORT scope mismatch", row["detail"]["message"])

    def test_prefix_session_must_match_its_signed_policy(self):
        world = build_world()
        tree = seed_tree(world)
        # This is a valid strict prefix, not a failed later action. Independently
        # rewrite only the claimed enrollment target and all record/event hashes.
        enrollment = deepcopy(world.objects["session"]["enrollment"])
        enrollment["core_installation_id"] = str(UUID(int=999))
        tree, rounds = rebind(world, {raw_digest(world.objects["session"]): {"enrollment": enrollment}})
        cutoff = next(i for i, event in enumerate(tree["authority"]["events"], 1) if event["event_kind"] == "SESSION_CREATE")
        tree["authority"]["events"] = tree["authority"]["events"][:cutoff]
        # Restrict registry records to the exact prefix so no later object can
        # supply or repair the missing historical enrollment relationship.
        used = {e["input_digest"] for e in tree["authority"]["events"]}
        tree["authority"]["records"] = {k: v for k, v in tree["authority"]["records"].items() if k in used}
        tree["core"]["events"] = []
        tree["core"]["records"] = {}
        row = observe("session_prefix_wrong_policy_installation", "REJECT", "REGISTRY_RELATIONS", tree, world, prefix_only=True)
        row["rebind_rounds"] = rounds
        self.assert_outcome(row)

    def test_actions_and_missing_trust_never_unlock_with_claims(self):
        world = build_world()
        for operation in ("APPLY_VERIFIED_TERMINAL", "TERMINATE_ORIGINAL", "QUERY_EXISTING", "TRUSTED_HISTORY", "ADMIT_SOURCE", "ACTIVE", "ADMITTED"):
            with self.subTest(operation=operation):
                row = observe("unsupported_" + operation, "REJECT", operation, seed_tree(world), world)
                self.assert_outcome(row)
        with self.assertRaises(MissingTrustedContext):
            validate_evidence("COMPLETION_HISTORY", world.evidence(), None, (world.deployment,))


if __name__ == "__main__":
    unittest.main()
