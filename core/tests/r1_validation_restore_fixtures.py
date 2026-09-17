"""Synthetic real-key source/archive/backup histories for restore integration.

No private key serialization, old reference import, service or database access.
The original single-operation seed is rebased onto a genuine signed GENESIS.
"""
from copy import deepcopy
from dataclasses import dataclass, replace
from types import SimpleNamespace

from app.control_plane.r1_validation import CoreHistory, DeploymentEvidence, HistoryEvidence
from app.control_plane._r1_validation_chain import ChainBoundary
from app.control_plane.r1_validation_crypto import FixedTrust
from app.control_plane._r1_validation_restore import (
    ArchiveMember, OpeningEvidence, RestoreEvidence, SourceEvidence, SourceDeploymentObservation, SourceFencingObservation,
)
from app.control_plane.r1_validation_codec import SCHEMA, c2, decode, h2, obj, record, sha
from tests.r1_validation_fixtures import build_world, event, observe, position, put, raw, registry, request_branch, uid
from tests.r1_validation_legacy_fixtures import make_origin


@dataclass(repr=False)
class RestoreWorld:
    world: object
    proof: RestoreEvidence
    history: HistoryEvidence
    target: DeploymentEvidence
    boundary: ChainBoundary
    objects: dict

    @property
    def deployments(self):
        return (self.world.deployment, self.target)


def genesis(world, origin_raw, failed_first=False):
    pin, material, identity = world.pin, world.deployment, world.request["intent"]["identity"]
    component = b"synthetic-original-initializer"
    auth = obj("opening_authorization", opening_id=identity["genesis_operation_id"], opening_kind="NEW_GENESIS", identity=identity,
               source_snapshot=None, target_authority_domain_id=pin["authority_domain_id"], target_authority_instance_id=pin["authority_instance_id"],
               target_authority_generation=1, target_storage_generation_id=material.storage_generation_id,
               target_control_plane_generation_id=material.control_plane_generation_id, core_installation_id=material.core_installation_id,
               initializer_principal="synthetic-initializer", initializer_artifact_digest=sha(component),
               initial_or_current_owner_identity=world.request["intent"]["scope"]["actor_identity"], owner_version=1, continuity_epoch=1, state_version=0,
               signed_origin_digest=sha(b"QINGYU-CP-R1-PROVISIONING-ORIGIN\0" + origin_raw), deployment_admission_digest=sha(material.deployment_bytes),
               trust_config_digest=h2(pin), receipt_key_id=pin["receipt_key_id"], tls_origin=pin["https_origin"], tls_spki_sha256=pin["server_spki_sha256"],
               operator_root_key_id=pin["operator_root_key_id"], issued_at=500, expires_at=100000, reason="Synthetic genesis evidence", root_signature="0"*128)
    world.sign(auth)
    origins = {"identity_digest": h2(identity), "opening_authorization_digest": h2(auth),
               "signed_origin_digest": auth["signed_origin_digest"], "trust_config_digest": h2(pin)}
    prior_a = obj("authority_ref", wire_version=2, authority_generation=1, authority_sequence=0, receipt_hash=h2(obj("authority_origin", **origins)))
    prior_c = obj("audit_ref", wire_version=2, audit_sequence=0, audit_hash=h2(obj("audit_origin", **origins)))
    candidate = obj("opening_audit_content", opening_id=auth["opening_id"], opening_kind="NEW_GENESIS", identity_digest=h2(identity),
                    opening_authorization_digest=h2(auth), source_snapshot_digest=None, state_version=0, owner_identity=auth["initial_or_current_owner_identity"],
                    owner_version=1, continuity_epoch=1, audit_sequence=1, previous_audit_ref=prior_c)
    attempt = obj("genesis_attempt", attempt_id=uid(4000), opening_id=auth["opening_id"], opening_authorization_digest=h2(auth),
                  identity_digest=h2(identity), attempt_number=1, previous_attempt_digest=None, created_at=510)
    ack = obj("opening_prepare", opening_id=auth["opening_id"], opening_authorization_digest=h2(auth), audit_candidate_digest=h2(candidate),
              genesis_attempt_digest=h2(attempt), target_authority_domain_id=pin["authority_domain_id"], target_authority_instance_id=pin["authority_instance_id"],
              target_authority_generation=1, prepared_at=520, receipt_key_id=pin["receipt_key_id"], receipt_signature="0"*128)
    world.sign(ack)
    attempts, earlier_events, evidence = (c2(attempt),), (), ()
    if failed_first:
        first_attempt, first_ack = deepcopy(attempt), deepcopy(ack)
        failure = record("genesis_failure", attempt_digest=h2(first_attempt), opening_prepare_digest=h2(first_ack), checked_at=524,
            authority_sequence=0, audit_sequence=0, terminal_observation="ABSENT", proposal_observation="NONE_COMMITTABLE",
            transaction_outcome="ROLLED_BACK", cause_code="TRANSACTION_ROLLBACK_CONFIRMED", observed_by="synthetic initializer observation")
        first_prepared = obj("genesis_attempt_event", event_id=uid(4011), attempt_id=first_attempt["attempt_id"], previous_event_digest=None,
            state="PREPARED", reason_code="PREPARE_PERSISTED", evidence_digest=sha(c2(first_ack)), created_at=520)
        first_failed = obj("genesis_attempt_event", event_id=uid(4012), attempt_id=first_attempt["attempt_id"], previous_event_digest=h2(first_prepared),
            state="GENESIS_ATTEMPT_ABORTED", reason_code=failure["cause_code"], evidence_digest=sha(c2(failure)), created_at=524)
        attempt.update(attempt_id=uid(4010), attempt_number=2, previous_attempt_digest=h2(first_attempt), created_at=525)
        ack.update(genesis_attempt_digest=h2(attempt), prepared_at=526); world.sign(ack)
        attempts, earlier_events, evidence = (c2(first_attempt), c2(attempt)), (c2(first_prepared), c2(first_failed)), (c2(first_ack), c2(failure))
    receipt = obj("opening_receipt", opening_id=auth["opening_id"], opening_kind="NEW_GENESIS", identity_digest=h2(identity),
                  opening_authorization_digest=h2(auth), opening_prepare_digest=h2(ack), source_snapshot_digest=None,
                  **{key: pin[key] for key in ("authority_domain_id", "authority_instance_id", "authority_generation")},
                  authority_sequence=1, previous_authority_ref=prior_a, audit_candidate_digest=h2(candidate), state_version=0,
                  owner_identity=auth["initial_or_current_owner_identity"], owner_version=1, continuity_epoch=1,
                  decided_at=530, receipt_key_id=pin["receipt_key_id"], receipt_signature="0"*128)
    world.sign(receipt)
    audit = obj("audit_record", candidate=candidate, receipt_digest=h2(receipt))
    binding = record("initializer_binding", opening_id=auth["opening_id"], runtime_principal=auth["initializer_principal"],
                     core_installation_id=material.core_installation_id, initializer_artifact_digest=sha(component),
                     deployment_admission_digest=sha(material.deployment_bytes), trust_config_digest=h2(pin),
                     purpose="LIFECYCLE_OPENING", registration_state="ACTIVE", admitted_at=500, expires_at=100000)
    prepared = obj("genesis_attempt_event", event_id=uid(4001), attempt_id=attempt["attempt_id"], previous_event_digest=None,
                   state="PREPARED", reason_code="PREPARE_PERSISTED", evidence_digest=sha(c2(ack)), created_at=ack["prepared_at"])
    success = obj("genesis_attempt_event", event_id=uid(4002), attempt_id=attempt["attempt_id"], previous_event_digest=h2(prepared),
                  state="SUCCEEDED", reason_code="OPENING_RECEIPT_PERSISTED", evidence_digest=sha(c2(receipt)), created_at=530)
    opening = OpeningEvidence(c2(auth), c2(ack), c2(receipt), c2(audit), c2(binding), component,
                              attempts, (*earlier_events, c2(prepared), c2(success)), evidence)
    checkpoint = obj("local_checkpoint", state_version=0,
                     authority_ref=obj("authority_ref", wire_version=2, authority_generation=1, authority_sequence=1, receipt_hash=h2(receipt)),
                     audit_ref=obj("audit_ref", wire_version=2, audit_sequence=1, audit_hash=h2(audit)))
    return opening, checkpoint


def rebase_world(world, checkpoint):
    """Rewrite the seed dependency DAG and re-sign; no product semantics used."""
    old_request = deepcopy(world.request)
    intent = deepcopy(old_request["intent"])
    intent["scope"].update(expected_state_version=0, expected_authority_ref=checkpoint["authority_ref"], expected_audit_ref=checkpoint["audit_ref"])
    source = deepcopy(old_request["source_decision"])
    source.update(intent_digest=h2(intent), scope_digest=h2(intent["scope"]))
    request = obj("mutation_request", intent=intent, source_decision=source,
                  commit=request_branch(intent, source, "COMMIT"), abort=request_branch(intent, source, "ABORT"))
    replacements = {}
    def pair(old, new):
        if type(old) is dict:
            replacements[c2(old)] = new
            for key in old.keys() & new.keys():
                if type(old[key]) is dict and type(new[key]) is dict:
                    pair(old[key], new[key])
    pair(old_request, request)
    mapping = {}
    for encoded, value in replacements.items():
        old = decode(encoded)
        mapping[raw(old)] = raw(value)
        if old.get("type") in SCHEMA:
            mapping[h2(old)] = h2(value)
    tree = {"request": world.request, "authority": world.authority, "core": world.core, "objects": world.objects}
    def mapped(value):
        visited = set()
        while value in mapping and value not in visited and mapping[value] != value:
            visited.add(value); value = mapping[value]
        return value
    def walk(value):
        if type(value) is str:
            return mapped(value)
        if type(value) is list:
            return [walk(item) for item in value]
        if type(value) is not dict:
            return value
        old = value
        encoded = c2(old)
        if encoded in replacements:
            new = deepcopy(replacements[encoded])
        else:
            new = {mapped(key): walk(child) for key, child in old.items()}
            kind = new.get("type")
            if kind == "execution_grant":
                new["expected_state_version"] = 0
            if kind == "terminal_receipt":
                new.update(state_before=0, state_after=1 if new["decision"] == "COMMIT" else 0, audit_sequence=2, authority_sequence=2)
            if kind == "local_checkpoint":
                new["state_version"] = 0 if old["state_version"] == 4 else 1 if old["state_version"] == 5 else old["state_version"]
            if kind == "authority_ref" and new["authority_sequence"] == 5:
                new["authority_sequence"] = 2
            if kind == "audit_ref" and new["audit_sequence"] == 5:
                new["audit_sequence"] = 2
            if "state_version" in new and "owner_identity" in new and "fences" not in new and kind is None:
                new["state_version"] = 0
            # Issuance projection binds a signed body's fields before issuance_digest.
            if set(new).issuperset({"issuance_kind", "issue_body_digest", "fences_or_target_digest"}):
                original_kind = "grant" if new["issuance_kind"] == "GRANT" else "permit"
                body = walk(tree["objects"][original_kind])
                new["issue_body_digest"] = raw({key: child for key, child in body.items() if key not in ("issuance_digest", "receipt_signature")})
            if "root_signature" in new or "receipt_signature" in new:
                world.sign(new)
        if encoded != c2(new):
            mapping[sha(encoded)] = raw(new)
            if old.get("type") in SCHEMA:
                mapping[h2(old)] = h2(new)
        return new
    for _ in range(40):
        before = c2(tree)
        tree = walk(tree)
        for name in ("authority", "core"):
            normalized = {}
            for key, value in tree[name]["records"].items():
                acceptable = {raw(value)}
                if value.get("type") in SCHEMA:
                    acceptable.add(h2(value))
                if key not in acceptable:
                    correct = h2(value) if value.get("type") in SCHEMA else raw(value)
                    mapping[key] = correct
                    key = correct
                normalized[key] = value
            tree[name]["records"] = normalized
            for entry in tree[name]["events"]:
                if entry["input_digest"] in normalized:
                    original_event_hash = raw(entry)
                    value = normalized[entry["input_digest"]]
                    actual_raw = raw(value)
                    normalized[actual_raw] = value
                    entry["input_digest"] = actual_raw
                    if original_event_hash != raw(entry):
                        mapping[original_event_hash] = raw(entry)
        if c2(tree) == before:
            break
    else:
        raise AssertionError("test dependency rebasing did not converge")
    world.request, world.authority, world.core, world.objects = (tree[key] for key in ("request", "authority", "core", "objects"))
    return world


def members_for(world, opening, inventory, origin_raw, source_deployment, fencing, profile):
    pairs = []
    def add(role, value):
        wire = value if type(value) is bytes else c2(value)
        if (role, wire) not in pairs:
            pairs.append((role, wire))
    for role, wire in (("OPENING_AUTHORIZATION", opening.authorization_wire), ("OPENING_PREPARE", opening.prepare_wire),
                       ("AUTHORITY_RECEIPT", opening.receipt_wire), ("CORE_AUDIT", opening.audit_wire),
                       ("INITIALIZER_ADMISSION", opening.initializer_binding_wire), ("INITIALIZER_COMPONENT", opening.initializer_component_bytes)):
        add(role, wire)
    for wire in opening.attempt_wires: add("GENESIS_ATTEMPT", wire)
    for wire in opening.attempt_event_wires: add("GENESIS_ATTEMPT_EVENT", wire)
    for wire in opening.attempt_evidence_wires:
        add("OPENING_PREPARE" if decode(wire).get("type") == "opening_prepare" else "GENESIS_ATTEMPT_EVIDENCE", wire)
    for role, value in (("SIGNED_ORIGIN", origin_raw), ("SOURCE_DEPLOYMENT", source_deployment), ("SOURCE_FENCING", fencing),
                        ("SOURCE_PROFILE", profile), ("OPERATION_INVENTORY", inventory), ("AUTHORITY_PIN", world.pin),
                        ("ROOT_PUBLIC_KEY", world.trust.root_public_key), ("RECEIPT_PUBLIC_KEY", bytes.fromhex(world.pin["receipt_public_key"])),
                        ("DEPLOYMENT_ADMISSION", world.deployment.deployment_bytes), ("RECOVERY_COMPONENT", world.deployment.component_bytes),
                        ("TLS_SPKI_DER", world.deployment.tls_spki_der), ("REQUEST", world.request), ("SOURCE_ADMISSION", world.objects["source_admission"]),
                        ("TERMINAL_AUTHORIZATION", world.objects["authorization"]), ("AUTHORITY_RECEIPT", world.objects["receipt"]),
                        ("PREPARE_ACK", world.objects["ack"]), ("STAGED_EVIDENCE", world.objects["stage"]), ("EXECUTION_GRANT", world.objects["grant"])):
        add(role, value)
    add("AUDIT_CANDIDATE", world.request["commit"]["audit_candidate"]); add("AUDIT_CANDIDATE", world.request["abort"]["audit_candidate"])
    add("CORE_AUDIT" if "completion" in world.objects else "DERIVED_AUDIT", world.objects["audit"])
    for role, reg in (("AUTHORITY_REGISTRY", world.authority), ("CORE_REGISTRY", world.core)):
        add(role, reg); add("REGISTRY_HEADER", reg["header"])
        for entry in reg["events"]:
            add("REGISTRY_EVENT", entry); add("REGISTRY_INPUT", reg["records"][entry["input_digest"]])
            if entry["output_digest"] is not None:
                add("REGISTRY_OUTPUT", reg["records"][entry["output_digest"]])
    if "completion" in world.objects:
        for name, role in (("permit", "FINISH_PERMIT"), ("permit_issuance", "ISSUANCE_SNAPSHOT"), ("target", "FINISH_TARGET"),
                           ("use_snapshot", "LOCAL_USE"), ("completion", "COMPLETION_RECORD")):
            add(role, world.objects[name])
    counters = {}
    members = []
    for role, wire in pairs:
        counters[role] = counters.get(role, 0) + 1
        members.append(ArchiveMember(role, counters[role], wire))
    members.sort(key=lambda value: (value.role, value.index))
    return tuple(members)


def manifest(members):
    return obj("archive_manifest", entries=[{"role": value.role, "index": value.index, "byte_length": len(value.raw), "sha256": sha(value.raw)} for value in members])


def build_restore_world(decision="COMMIT", override=False, aligned=False, failed_first=False):
    world = build_world(decision=decision, override=override, complete=aligned)
    origin_raw, observed_origin = make_origin(world.root, world.trust)
    opening, before = genesis(world, origin_raw, failed_first)
    rebase_world(world, before)
    receipt, audit, after = world.objects["receipt"], world.objects["audit"], world.objects["after"]
    scope, identity = world.request["intent"]["scope"], world.request["intent"]["identity"]
    boundary = ChainBoundary(c2(identity), c2(before), c2(after), scope["actor_identity"], 1, 1,
                             world.deployment.storage_generation_id, world.deployment.control_plane_generation_id, scope["trust_domain_id"])
    inventory = obj("source_operation_inventory", authority_domain_id=world.pin["authority_domain_id"], authority_generation=1,
                    entries=sorted([
                        {"operation_id": identity["genesis_operation_id"], "wire_version": 2, "request_raw_sha256": sha(opening.authorization_wire),
                         "authorization_raw_sha256": sha(opening.authorization_wire), "terminal_ref": before["authority_ref"], "audit_ref": before["audit_ref"], "state": "COMMITTED"},
                        {"operation_id": world.request["intent"]["operation_id"], "wire_version": 2, "request_raw_sha256": sha(c2(world.request)),
                         "authorization_raw_sha256": sha(c2(world.objects["authorization"])), "terminal_ref": after["authority_ref"],
                         "audit_ref": after["audit_ref"] if aligned else None, "state": receipt["result_state"]}], key=lambda item: item["operation_id"]))
    actual = after if aligned else before
    profile = {"history_version": 2, "profile": "ALIGNED_OPENING" if aligned else "HISTORY_ONLY_TAIL", "authority_tip": after["authority_ref"],
               "actual_core_audit_tip": actual["audit_ref"], "actual_core_state_version": actual["state_version"],
               "completion_digest": raw(world.objects["completion"]) if aligned else None}
    source_deployment, fencing = b"synthetic source deployment inspector original bytes", b"synthetic isolated old writers observation original bytes"
    members = members_for(world, opening, inventory, origin_raw, source_deployment, fencing, profile)
    snapshot = obj("source_snapshot", source_kind="V2_GENERATION_RESTORE", identity=identity,
                   **{"source_"+key: world.pin[key] for key in ("authority_domain_id", "authority_instance_id", "authority_generation")},
                   authority_tip=after["authority_ref"], audit_tip=actual["audit_ref"], state_version=actual["state_version"],
                   owner_identity=scope["actor_identity"], owner_version=1, continuity_epoch=1,
                   storage_generation_id=world.deployment.storage_generation_id, control_plane_generation_id=world.deployment.control_plane_generation_id,
                   signed_origin_digest=sha(b"QINGYU-CP-R1-PROVISIONING-ORIGIN\0" + origin_raw), history_archive_digest=h2(manifest(members)),
                   operation_inventory_digest=h2(inventory), source_deployment_digest=sha(source_deployment), source_fencing_evidence_digest=sha(fencing), captured_at=2000)
    observation = SourceDeploymentObservation(sha(source_deployment), c2(identity), world.trust.pin_wire, world.deployment.core_installation_id,
                                              world.deployment.storage_generation_id, world.deployment.control_plane_generation_id,
                                              scope["actor_identity"], 1, 1, actual["state_version"], c2(after["authority_ref"]), c2(actual["audit_ref"]), sha(world.deployment.deployment_bytes))
    source = SourceEvidence(c2(snapshot), c2(manifest(members)), c2(inventory), members, world.evidence(), boundary, opening,
                            observed_origin=observed_origin, source_deployment_observation=observation,
                            source_fencing_observation=SourceFencingObservation(sha(fencing), sha(source_deployment), c2(after["authority_ref"]),
                                c2(actual["audit_ref"]), 1999, "synthetic isolated source inspector", "ISOLATED", "ISOLATED"))
    backup = record("backup_state", identity=identity, checkpoint=before, governed_results=[],
                    receipt_wires=[opening.receipt_wire.hex()], audit_wires=[opening.audit_wire.hex()], captured_at=800)
    target = DeploymentEvidence("restore-test-core", uid(4100), uid(4101), uid(4102), b"synthetic restore deployment", b"synthetic restore component", world.deployment.tls_spki_der)
    context = obj("restoration_context", context_id=uid(4103), identity=identity, source_snapshot=snapshot,
                  target_core_installation_id=target.core_installation_id, target_storage_generation_id=target.storage_generation_id,
                  target_control_plane_generation_id=target.control_plane_generation_id, target_authority_pin_digest=h2(world.pin),
                  restore_start_checkpoint=before, restore_source_state_digest=sha(c2(backup)), allowed_actions=["APPLY_VERIFIED_TERMINAL", "VERIFY_HISTORY"],
                  issued_at=2100, expires_at=40000, reason="Synthetic explicit history-only restore", operator_root_key_id=world.pin["operator_root_key_id"], root_signature="0"*128)
    world.sign(context)
    authority, core = deepcopy(world.authority), registry(world.pin, target)
    policy = deepcopy(world.objects["policy"])
    policy.update(policy_id=uid(4104), restoration_context_digest=h2(context), issued_at=2100, expires_at=40000,
                  capabilities=["APPLY_VERIFIED_TERMINAL", "PERSIST_COORDINATION", "QUERY_EXISTING"],
                  deployment_admission_digest=sha(target.deployment_bytes), component_artifact_digest=sha(target.component_bytes),
                  **{key: getattr(target, key) for key in ("runtime_principal", "core_installation_id", "storage_generation_id", "control_plane_generation_id")})
    world.sign(policy)
    enrollment = {key: policy[key] for key in ("runtime_principal", "core_installation_id", "restoration_context_digest", "authority_domain_id", "authority_instance_id", "authority_generation",
                                              "storage_generation_id", "control_plane_generation_id", "deployment_admission_digest", "component_artifact_digest", "trust_config_digest")}
    enrollment.update(policy_digest=h2(policy), context_kind="MANUAL_RESTORE_ADMITTED", purpose="MUTATION_RECOVERY", identity_digest=h2(identity))
    session = record("session_binding", history_version=2, session_id=uid(4105), enrollment=enrollment, issued_at=2200, expires_at=40000)
    common = {"operation_id": receipt["operation_id"], "request_digest": h2(world.request), "source_decision_digest": h2(world.request["source_decision"])}
    inv = obj("recovery_inventory", inventory_id=uid(4106), policy_digest=h2(policy), core_installation_id=target.core_installation_id,
              runtime_principal=target.runtime_principal, session_id=session["session_id"], entries=[{**common, "local_commit_id": world.request["intent"]["local_commit_id"]}])
    for kind, value in (("POLICY_REGISTER", policy), ("SESSION_CREATE", session), ("INVENTORY_ACCEPT", inv)):
        event(authority, kind, 2200, value)
    binding = {"runtime_principal": target.runtime_principal, "session_id": session["session_id"], "policy_digest": h2(policy), "inventory_digest": h2(inv)}
    finish_target = record("finish_target", history_version=2, identity_digest=h2(identity), authority_pin_digest=h2(world.pin),
                           **{key: policy[key] for key in ("core_installation_id", "storage_generation_id", "control_plane_generation_id", "restoration_context_digest")},
                           **common, terminal_digest=h2(receipt), before_checkpoint=before, after_checkpoint=after)
    body = {"type": "local_finish_permit", "version": 2, "contract_revision": 2, "permit_id": uid(4107), "permit_sequence": 2 if aligned else 1,
            **binding, **common, "restoration_context_digest": h2(context), "core_installation_id": target.core_installation_id,
            "terminal_digest": h2(receipt), "before_checkpoint": before, "after_checkpoint": after, "issued_at": 2300, "expires_at": 15000, "receipt_key_id": world.pin["receipt_key_id"]}
    issuance = record("issuance_snapshot", history_version=2, position=position(authority), issued_at=2300, issuance_kind="PERMIT", issuer_key_id=world.pin["receipt_key_id"],
                      **binding, **common, restoration_context_digest=h2(context), issue_body_digest=raw(body), fences_or_target_digest=raw(finish_target))
    permit = {**body, "issuance_digest": raw(issuance), "receipt_signature": "0"*128}; world.sign(permit)
    put(authority, finish_target); event(authority, "PERMIT_ISSUED", 2300, issuance, permit)
    for kind, value in (("POLICY_OBSERVED", policy), ("SESSION_OBSERVED", session), ("INVENTORY_OBSERVED", inv), ("PERMIT_OBSERVED", permit)):
        observe(core, authority, kind, value, 2400)
    event(core, "LOCAL_PROTECTION", 2400, record("local_protection", history_version=2, policy_digest=h2(policy), component_valid=True, policy_active=True, context_kind="MANUAL_RESTORE_ADMITTED"))
    selected = world.request[receipt["decision"].lower()]
    content = {"effect_digest": h2(selected["effect"]), "result_digest": h2(selected["result"]), "audit_record_digest": h2(audit)}
    use = record("use_input", history_version=2, permit_digest=h2(permit), issuance_digest=raw(issuance), target_digest=raw(finish_target), terminal_digest=h2(receipt), **content)
    put(core, finish_target); put(core, use)
    snap = record("local_snapshot", history_version=2, position=position(core), checked_at=2500, action="APPLY_VERIFIED_TERMINAL", **binding, **common,
                  target_digest=raw(finish_target), action_input_digest=raw(use))
    completion = record("completion_record", history_version=2, position=position(core), completed_at=2500, permit_digest=h2(permit), issuance_digest=raw(issuance),
                        local_use_digest=raw(snap), **common, terminal_digest=h2(receipt), target_digest=raw(finish_target), before_checkpoint=before, after_checkpoint=after, **content)
    event(core, "APPLY", 2500, snap, completion)
    history = replace(world.evidence(), authority_history=c2(authority), core_histories=(*world.evidence().core_histories, CoreHistory(target.runtime_principal, c2(core))), context_wires=(c2(context),))
    proof = RestoreEvidence(c2(context), c2(backup), source, c2(before))
    return RestoreWorld(world, proof, history, target, boundary, {"context": context, "snapshot": snapshot, "backup": backup, "target": finish_target,
                         "authority": authority, "core": core, "policy": policy, "permit": permit, "completion": completion})


def replace_source_parts(source, *, members=None, snapshot=None, **changes):
    """Rehash explicit original members, without changing their semantic content."""
    members = source.members if members is None else tuple(sorted(members, key=lambda row: (row.role, row.index)))
    snapshot = decode(source.snapshot_wire) if snapshot is None else deepcopy(snapshot)
    snapshot["history_archive_digest"] = h2(manifest(members))
    return replace(source, members=members, manifest_wire=c2(manifest(members)), snapshot_wire=c2(snapshot), **changes)


def with_backup_at_tail(world):
    source = world.proof.source
    if decode(source.snapshot_wire)["state_version"] != world.objects["target"]["after_checkpoint"]["state_version"]:
        raise AssertionError("tail backup requires an actually aligned source")
    checkpoint = world.objects["target"]["after_checkpoint"]
    receipt = world.world.objects["receipt"]
    backup = record("backup_state", identity=world.world.request["intent"]["identity"], checkpoint=checkpoint,
                    governed_results=[world.world.request[receipt["decision"].lower()]["result"]],
                    receipt_wires=[source.opening.receipt_wire.hex(), c2(receipt).hex()],
                    audit_wires=[source.opening.audit_wire.hex(), c2(world.world.objects["audit"]).hex()], captured_at=1900)
    context = decode(world.proof.context_wire)
    context.update(restore_start_checkpoint=checkpoint, restore_source_state_digest=sha(c2(backup)))
    world.world.sign(context)
    return replace(world.proof, backup_wire=c2(backup), context_wire=c2(context), expected_backup_checkpoint_wire=c2(checkpoint))


def genesis_only_source(world):
    old = world.proof.source
    checkpoint = decode(old.chain_boundary.start_checkpoint_wire)
    inv = decode(old.inventory_wire)
    inv["entries"] = [row for row in inv["entries"] if row["operation_id"] == decode(old.opening.authorization_wire)["opening_id"]]
    auth_reg, core_reg = registry(world.world.pin), registry(world.world.pin, world.world.deployment)
    history = HistoryEvidence((), c2(auth_reg), (CoreHistory(world.world.deployment.runtime_principal, c2(core_reg)),))
    profile = {"history_version": 2, "profile": "ALIGNED_OPENING", "authority_tip": checkpoint["authority_ref"],
               "actual_core_audit_tip": checkpoint["audit_ref"], "actual_core_state_version": checkpoint["state_version"], "completion_digest": None}
    static = {"SOURCE_DEPLOYMENT", "SOURCE_FENCING", "SIGNED_ORIGIN", "AUTHORITY_PIN", "ROOT_PUBLIC_KEY", "RECEIPT_PUBLIC_KEY",
              "DEPLOYMENT_ADMISSION", "RECOVERY_COMPONENT", "TLS_SPKI_DER", "OPENING_AUTHORIZATION", "OPENING_PREPARE", "INITIALIZER_ADMISSION",
              "INITIALIZER_COMPONENT", "GENESIS_ATTEMPT", "GENESIS_ATTEMPT_EVENT"}
    pairs = [(row.role, row.raw) for row in old.members if row.role in static]
    pairs.extend([("AUTHORITY_RECEIPT", old.opening.receipt_wire), ("CORE_AUDIT", old.opening.audit_wire), ("OPERATION_INVENTORY", c2(inv)),
                  ("SOURCE_PROFILE", c2(profile)), ("AUTHORITY_REGISTRY", c2(auth_reg)), ("CORE_REGISTRY", c2(core_reg)),
                  ("REGISTRY_HEADER", c2(auth_reg["header"])), ("REGISTRY_HEADER", c2(core_reg["header"]))])
    counts, members = {}, []
    for role, wire in pairs:
        counts[role] = counts.get(role, 0) + 1
        members.append(ArchiveMember(role, counts[role], wire))
    snapshot = decode(old.snapshot_wire)
    snapshot.update(authority_tip=checkpoint["authority_ref"], audit_tip=checkpoint["audit_ref"], state_version=0, operation_inventory_digest=h2(inv))
    return replace_source_parts(old, members=members, snapshot=snapshot, inventory_wire=c2(inv), history=history,
        chain_boundary=replace(old.chain_boundary, expected_end_checkpoint_wire=c2(checkpoint)),
        source_deployment_observation=replace(old.source_deployment_observation, state_version=0,
            authority_tip_wire=c2(checkpoint["authority_ref"]), audit_tip_wire=c2(checkpoint["audit_ref"])),
        source_fencing_observation=replace(old.source_fencing_observation,
            authority_tip_wire=c2(checkpoint["authority_ref"]), audit_tip_wire=c2(checkpoint["audit_ref"])))


def lineage_source(previous, kind="GENERATION_RESTORE", *, offset=0, fault=None):
    """Build a new opening from separately verified complete prior raw evidence."""
    source = previous.source
    prior = decode(source.snapshot_wire)
    pin = deepcopy(previous.pin)
    if kind == "GENERATION_RESTORE":
        pin.update(authority_generation=pin["authority_generation"]+1, authority_instance_id=uid(6000+offset))
        material = DeploymentEvidence("generation-core-"+str(offset), uid(6001+offset), uid(6002+offset), uid(6003+offset),
                                      b"synthetic generation deployment"+str(offset).encode(), b"synthetic generation recovery", previous.deployments[0].tls_spki_der)
        deployments = (*previous.deployments, material)
    else:
        material = previous.deployments[0]
        deployments = previous.deployments
    trust = FixedTrust(c2(pin), previous.trust.root_public_key)
    def sign(value):
        key_name = "root_signature" if "root_signature" in value else "receipt_signature"
        from app.control_plane.r1_validation_codec import s2
        value[key_name] = (previous.root if key_name == "root_signature" else previous.receipt_key).sign(s2(value)).hex()
        return value
    issued = prior["captured_at"]+100
    component = b"synthetic generation initializer"
    auth = obj("opening_authorization", opening_id=uid(6010+offset), opening_kind=kind, identity=prior["identity"], source_snapshot=prior,
        target_authority_domain_id=pin["authority_domain_id"], target_authority_instance_id=pin["authority_instance_id"], target_authority_generation=pin["authority_generation"],
        target_storage_generation_id=material.storage_generation_id, target_control_plane_generation_id=material.control_plane_generation_id,
        core_installation_id=material.core_installation_id, initializer_principal="synthetic-initializer", initializer_artifact_digest=sha(component),
        initial_or_current_owner_identity=prior["owner_identity"], **{key: prior[key] for key in ("owner_version", "continuity_epoch", "state_version", "signed_origin_digest")},
        deployment_admission_digest=sha(material.deployment_bytes), trust_config_digest=h2(pin), receipt_key_id=pin["receipt_key_id"],
        tls_origin=pin["https_origin"], tls_spki_sha256=pin["server_spki_sha256"], operator_root_key_id=pin["operator_root_key_id"],
        issued_at=issued, expires_at=issued+100000, reason="Synthetic explicit lineage opening", root_signature="0"*128)
    if fault == "owner":
        auth["initial_or_current_owner_identity"] = "different-owner"
    sign(auth)
    common = {"opening_id": auth["opening_id"], "opening_kind": kind, "identity_digest": h2(prior["identity"]),
              "opening_authorization_digest": h2(auth), "source_snapshot_digest": h2(prior), "state_version": auth["state_version"],
              "owner_identity": auth["initial_or_current_owner_identity"], "owner_version": auth["owner_version"], "continuity_epoch": auth["continuity_epoch"]}
    candidate = obj("opening_audit_content", **common, audit_sequence=prior["audit_tip"]["audit_sequence"]+1, previous_audit_ref=prior["audit_tip"])
    if fault == "audit_reset":
        candidate["audit_sequence"] = 1
    ack = sign(obj("opening_prepare", opening_id=auth["opening_id"], opening_authorization_digest=h2(auth), audit_candidate_digest=h2(candidate),
        genesis_attempt_digest=None, target_authority_domain_id=pin["authority_domain_id"], target_authority_instance_id=pin["authority_instance_id"],
        target_authority_generation=pin["authority_generation"], prepared_at=issued+10, receipt_key_id=pin["receipt_key_id"], receipt_signature="0"*128))
    sequence = 1 if kind == "GENERATION_RESTORE" else prior["authority_tip"]["authority_sequence"]+1
    receipt = sign(obj("opening_receipt", **common, opening_prepare_digest=h2(ack),
        **{key: pin[key] for key in ("authority_domain_id", "authority_instance_id", "authority_generation")}, authority_sequence=sequence,
        previous_authority_ref=prior["authority_tip"], audit_candidate_digest=h2(candidate), decided_at=issued+20,
        receipt_key_id=pin["receipt_key_id"], receipt_signature="0"*128))
    audit = obj("audit_record", candidate=candidate, receipt_digest=h2(receipt))
    checkpoint = obj("local_checkpoint", state_version=auth["state_version"],
        authority_ref=obj("authority_ref", wire_version=2, authority_generation=pin["authority_generation"], authority_sequence=sequence, receipt_hash=h2(receipt)),
        audit_ref=obj("audit_ref", wire_version=2, audit_sequence=candidate["audit_sequence"], audit_hash=h2(audit)))
    binding = record("initializer_binding", opening_id=auth["opening_id"], runtime_principal=auth["initializer_principal"], core_installation_id=material.core_installation_id,
        initializer_artifact_digest=sha(component), deployment_admission_digest=sha(material.deployment_bytes), trust_config_digest=h2(pin),
        purpose="LIFECYCLE_OPENING", registration_state="ACTIVE", admitted_at=issued, expires_at=issued+100000)
    opening = OpeningEvidence(c2(auth), c2(ack), c2(receipt), c2(audit), c2(binding), component, previous_source=source, previous_trust=previous.trust)
    inv = obj("source_operation_inventory", authority_domain_id=pin["authority_domain_id"], authority_generation=pin["authority_generation"],
        entries=[{"operation_id": auth["opening_id"], "wire_version": 2, "request_raw_sha256": sha(c2(auth)), "authorization_raw_sha256": sha(c2(auth)),
                  "terminal_ref": checkpoint["authority_ref"], "audit_ref": checkpoint["audit_ref"], "state": "COMMITTED"}])
    auth_reg, core_reg = registry(pin), registry(pin, material)
    history = HistoryEvidence((), c2(auth_reg), (CoreHistory(material.runtime_principal, c2(core_reg)),))
    boundary = ChainBoundary(c2(prior["identity"]), c2(checkpoint), c2(checkpoint), prior["owner_identity"], prior["owner_version"], prior["continuity_epoch"],
        material.storage_generation_id, material.control_plane_generation_id, source.chain_boundary.trust_domain_id)
    profile = {"history_version": 2, "profile": "ALIGNED_OPENING", "authority_tip": checkpoint["authority_ref"], "actual_core_audit_tip": checkpoint["audit_ref"],
               "actual_core_state_version": checkpoint["state_version"], "completion_digest": None}
    origin = next(row.raw for row in source.members if row.role == "SIGNED_ORIGIN")
    deployment_raw, fencing_raw = b"synthetic lineage inspected source", b"synthetic lineage isolated writers"
    pairs = [("SOURCE_DEPLOYMENT", deployment_raw), ("SOURCE_FENCING", fencing_raw), ("SIGNED_ORIGIN", origin), ("AUTHORITY_PIN", trust.pin_wire),
        ("ROOT_PUBLIC_KEY", trust.root_public_key), ("RECEIPT_PUBLIC_KEY", bytes.fromhex(pin["receipt_public_key"])),
        ("DEPLOYMENT_ADMISSION", material.deployment_bytes), ("RECOVERY_COMPONENT", material.component_bytes), ("TLS_SPKI_DER", material.tls_spki_der),
        ("OPENING_AUTHORIZATION", c2(auth)), ("OPENING_PREPARE", c2(ack)), ("AUTHORITY_RECEIPT", c2(receipt)), ("CORE_AUDIT", c2(audit)),
        ("INITIALIZER_ADMISSION", c2(binding)), ("INITIALIZER_COMPONENT", component), ("OPERATION_INVENTORY", c2(inv)), ("SOURCE_PROFILE", c2(profile)),
        ("AUTHORITY_REGISTRY", c2(auth_reg)), ("CORE_REGISTRY", c2(core_reg)), ("REGISTRY_HEADER", c2(auth_reg["header"])), ("REGISTRY_HEADER", c2(core_reg["header"]))]
    counts, members = {}, []
    for role, wire in pairs:
        counts[role] = counts.get(role, 0)+1
        members.append(ArchiveMember(role, counts[role], wire))
    members = tuple(sorted(members, key=lambda row: (row.role, row.index)))
    snapshot = obj("source_snapshot", source_kind="V2_GENERATION_RESTORE", identity=prior["identity"],
        **{"source_"+key: pin[key] for key in ("authority_domain_id", "authority_instance_id", "authority_generation")},
        authority_tip=checkpoint["authority_ref"], audit_tip=checkpoint["audit_ref"], state_version=checkpoint["state_version"],
        owner_identity=prior["owner_identity"], owner_version=prior["owner_version"], continuity_epoch=prior["continuity_epoch"],
        storage_generation_id=material.storage_generation_id, control_plane_generation_id=material.control_plane_generation_id,
        signed_origin_digest=prior["signed_origin_digest"], history_archive_digest=h2(manifest(members)), operation_inventory_digest=h2(inv),
        source_deployment_digest=sha(deployment_raw), source_fencing_evidence_digest=sha(fencing_raw), captured_at=issued+100)
    deployment_observation = SourceDeploymentObservation(sha(deployment_raw), c2(prior["identity"]), trust.pin_wire, material.core_installation_id,
        material.storage_generation_id, material.control_plane_generation_id, prior["owner_identity"], prior["owner_version"], prior["continuity_epoch"],
        prior["state_version"], c2(checkpoint["authority_ref"]), c2(checkpoint["audit_ref"]), sha(material.deployment_bytes))
    result = SourceEvidence(c2(snapshot), c2(manifest(members)), c2(inv), members, history, boundary, opening, observed_origin=source.observed_origin,
        source_deployment_observation=deployment_observation, source_fencing_observation=SourceFencingObservation(sha(fencing_raw), sha(deployment_raw),
        c2(checkpoint["authority_ref"]), c2(checkpoint["audit_ref"]), issued+99, "synthetic lineage inspector", "ISOLATED", "ISOLATED"))
    return SimpleNamespace(source=result, trust=trust, deployments=deployments, pin=pin, root=previous.root, receipt_key=previous.receipt_key, after=checkpoint)


def restored_final_source(world, *, completed=True):
    """Re-export the actual restore target, retaining its original restore proof."""
    old = world.proof.source
    checkpoint = decode(world.boundary.expected_end_checkpoint_wire if completed else world.boundary.start_checkpoint_wire)
    if not completed:
        core = deepcopy(world.objects["core"])
        final = core["events"].pop()
        if final["event_kind"] != "APPLY":
            raise AssertionError("synthetic restore APPLY must be final")
        local_use = core["records"][final["input_digest"]]
        discarded = {final["input_digest"], final["output_digest"], local_use["action_input_digest"], local_use["target_digest"]}
        core["records"] = {key: value for key, value in core["records"].items() if key not in discarded}
        history = replace(world.history, core_histories=(*world.history.core_histories[:-1], CoreHistory(world.target.runtime_principal, c2(core))))
        world = replace(world, history=history, objects={**world.objects, "core": core})
    inventory = decode(old.inventory_wire)
    for row in inventory["entries"]:
        if row["operation_id"] == world.world.request["intent"]["operation_id"]:
            row["audit_ref"] = checkpoint["audit_ref"] if completed else None
    terminal = decode(world.boundary.expected_end_checkpoint_wire)
    profile = {"history_version": 2, "profile": "ALIGNED_OPENING" if completed else "HISTORY_ONLY_TAIL", "authority_tip": terminal["authority_ref"],
               "actual_core_audit_tip": checkpoint["audit_ref"], "actual_core_state_version": checkpoint["state_version"],
               "completion_digest": raw(world.objects["completion"]) if completed else None}
    deployment_raw, fencing_raw = b"synthetic re-exported restore target", b"synthetic restored target isolated writers"
    excluded = {"AUTHORITY_REGISTRY", "CORE_REGISTRY", "REGISTRY_HEADER", "REGISTRY_EVENT", "REGISTRY_INPUT", "REGISTRY_OUTPUT",
                "SOURCE_PROFILE", "OPERATION_INVENTORY", "SOURCE_DEPLOYMENT", "SOURCE_FENCING"}
    pairs = [("CORE_AUDIT" if row.role == "DERIVED_AUDIT" and completed else row.role, row.raw) for row in old.members if row.role not in excluded]
    if not completed:
        pairs.append(("DERIVED_AUDIT", c2(world.world.objects["audit"])))
    pairs += [("SOURCE_DEPLOYMENT", deployment_raw), ("SOURCE_FENCING", fencing_raw), ("SOURCE_PROFILE", c2(profile)),
              ("OPERATION_INVENTORY", c2(inventory)), ("RESTORATION_CONTEXT", world.proof.context_wire),
              ("RESTORE_SOURCE_STATE", world.proof.backup_wire), ("ARCHIVE_MANIFEST", old.manifest_wire),
              ("DEPLOYMENT_ADMISSION", world.target.deployment_bytes), ("RECOVERY_COMPONENT", world.target.component_bytes),
              ("TLS_SPKI_DER", world.target.tls_spki_der)]
    registries = [("AUTHORITY_REGISTRY", decode(world.history.authority_history)), *[("CORE_REGISTRY", decode(core.raw)) for core in world.history.core_histories]]
    for role, reg in registries:
        pairs.extend(((role, c2(reg)), ("REGISTRY_HEADER", c2(reg["header"]))))
        for entry in reg["events"]:
            pairs.extend((("REGISTRY_EVENT", c2(entry)), ("REGISTRY_INPUT", c2(reg["records"][entry["input_digest"]]))))
            if entry["output_digest"] is not None:
                pairs.append(("REGISTRY_OUTPUT", c2(reg["records"][entry["output_digest"]])))
    for name, role in (("policy", "RECOVERY_POLICY"), ("permit", "FINISH_PERMIT"), ("target", "FINISH_TARGET"), ("completion", "COMPLETION_RECORD")):
        if name == "completion" and not completed:
            continue
        pairs.append((role, c2(world.objects[name])))
    authority, core = world.objects["authority"], world.objects["core"]
    for reg, kind, role in ((authority, "PERMIT_ISSUED", "ISSUANCE_SNAPSHOT"), (core, "APPLY", "LOCAL_USE")):
        for entry in reg["events"]:
            if entry["event_kind"] == kind:
                pairs.append((role, c2(reg["records"][entry["input_digest"]])))
    counts, members, seen = {}, [], set()
    for role, wire in pairs:
        if (role, wire) in seen:
            continue
        seen.add((role, wire)); counts[role] = counts.get(role, 0)+1
        members.append(ArchiveMember(role, counts[role], wire))
    snapshot = decode(old.snapshot_wire)
    snapshot.update(audit_tip=checkpoint["audit_ref"], state_version=checkpoint["state_version"],
                    storage_generation_id=world.target.storage_generation_id, control_plane_generation_id=world.target.control_plane_generation_id,
                    source_deployment_digest=sha(deployment_raw), source_fencing_evidence_digest=sha(fencing_raw), captured_at=3000,
                    operation_inventory_digest=h2(inventory))
    source = replace_source_parts(old, members=members, snapshot=snapshot, inventory_wire=c2(inventory), history=world.history,
        restoration_evidence=(world.proof,), source_deployment_observation=replace(old.source_deployment_observation,
            source_deployment_digest=sha(deployment_raw), core_installation_id=world.target.core_installation_id,
            storage_generation_id=world.target.storage_generation_id, control_plane_generation_id=world.target.control_plane_generation_id,
            deployment_admission_digest=sha(world.target.deployment_bytes), audit_tip_wire=c2(checkpoint["audit_ref"]), state_version=checkpoint["state_version"]),
        source_fencing_observation=replace(old.source_fencing_observation, source_deployment_digest=sha(deployment_raw),
            source_fencing_evidence_digest=sha(fencing_raw), observed_at=2999, audit_tip_wire=c2(checkpoint["audit_ref"])))
    return SimpleNamespace(source=source, trust=world.world.trust, deployments=world.deployments, pin=world.world.pin,
                           root=world.world.root, receipt_key=world.world.receipt_key, after=checkpoint)
