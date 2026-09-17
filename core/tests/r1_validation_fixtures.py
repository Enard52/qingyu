"""Test-owned real-signature histories for the product validation kernel.

These synthetic histories make no claim to real source admission. Construction
uses only the product wire codec, never its semantic verifier or the old design
reference executable. Expectations in the tests are independent relationships.
Ed25519 private keys are generated in memory and are never serialized.
"""
from copy import deepcopy
from dataclasses import dataclass, field
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.control_plane.r1_validation import CoreHistory, DeploymentEvidence, HistoryEvidence
from app.control_plane.r1_validation_codec import ACTIONS, SCHEMA, c2, h2, obj, record, s2, sha
from app.control_plane.r1_validation_crypto import FixedTrust


def uid(number):
    return str(UUID(int=number))


def raw(value):
    return sha(c2(value))


def public(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@dataclass(repr=False)
class World:
    request: dict
    authority: dict
    core: dict
    pin: dict
    deployment: DeploymentEvidence
    trust: FixedTrust
    objects: dict
    root: object = field(repr=False)
    receipt_key: object = field(repr=False)
    contexts: tuple = ()

    def evidence(self):
        return HistoryEvidence((c2(self.request),), c2(self.authority),
                               (CoreHistory(self.deployment.runtime_principal, c2(self.core)),),
                               tuple(c2(value) for value in self.contexts),
                               source_admission_wires=(c2(self.objects["source_admission"]),))

    def sign(self, value):
        field_name = "root_signature" if "root_signature" in value else "receipt_signature"
        key = self.root if field_name == "root_signature" else self.receipt_key
        value[field_name] = key.sign(s2(value)).hex()
        return value


def registry(pin, material=None):
    scope = {"registry_kind": "CORE_LOCAL" if material else "AUTHORITY_QUALIFICATION",
             **{name: pin[name] for name in ("authority_domain_id", "authority_instance_id", "authority_generation")},
             **{name: getattr(material, name) if material else None for name in
                ("core_installation_id", "storage_generation_id", "control_plane_generation_id")}}
    header = record("registry_header", history_version=2,
                    registry_id=str(UUID(bytes=bytes.fromhex(sha(b"QINGYU-R1-SCOPED-REGISTRY-V2\0" + c2(scope)))[:16])),
                    **scope, provenance_digest=sha(material.deployment_bytes) if material else h2(pin))
    return {"header": header, "events": [], "records": {}}


def position(reg):
    return {"history_version": 2, "registry_digest": raw(reg["header"]), "event_sequence": len(reg["events"]) + 1}


def put(reg, value):
    digest = h2(value) if value.get("type") in SCHEMA else raw(value)
    reg["records"][digest] = deepcopy(value)
    return digest


def event(reg, kind, at, inp, out=None):
    reg["records"][raw(inp)] = deepcopy(inp)
    # Typed input observations use H2, while event inputs always use RAW256.
    put(reg, inp)
    value = record("registry_event", history_version=2, position=position(reg), recorded_at=at,
                   event_kind=kind, input_digest=raw(inp), output_digest=put(reg, out) if out else None)
    reg["events"].append(value)
    return value


def observe(core, authority, kind, original, at):
    digest = h2(original) if original.get("type") in SCHEMA else raw(original)
    source = next(item for item in authority["events"] if
                  item["output_digest"] == digest or item["input_digest"] == raw(original))
    value = record("local_observation", history_version=2, authority_position=source["position"],
                   authority_event_digest=raw(source), object_digest=digest)
    event(core, kind, at, value)


def request_branch(intent, source, decision):
    scope = intent["scope"]
    value = {"payload": deepcopy(intent["payload"]), "capability": "core_governance",
             "requested_decision": intent["requested_decision"]}
    effect = obj("business_effect", entries=[{"mutation_id": intent["mutation_id"], "value": value}] if decision == "COMMIT" else [])
    result = obj("mutation_result", mutation_id=intent["mutation_id"], result_state="COMMITTED" if decision == "COMMIT" else "ABORTED",
                 state_version=scope["expected_state_version"] + (1 if decision == "COMMIT" else 0),
                 effect_digest=h2(effect), value=value if decision == "COMMIT" else None)
    audit = obj("audit_content", operation_id=intent["operation_id"], mutation_id=intent["mutation_id"],
                identity_digest=h2(intent["identity"]), scope_digest=h2(scope), intent_digest=h2(intent),
                source_decision_digest=h2(source), payload_digest=h2(obj("business_payload", value=intent["payload"])),
                decision=decision, result_state=result["result_state"], state_version=result["state_version"],
                effect_digest=h2(effect), result_digest=h2(result), audit_sequence=scope["expected_audit_ref"]["audit_sequence"] + 1,
                previous_audit_ref=scope["expected_audit_ref"], created_at=intent["created_at"])
    return obj("branch_bundle", decision=decision, effect=effect, result=result, audit_candidate=audit)


def build_world(decision="COMMIT", override=False, complete=True, faults=None, times=None,
                *, parent=None, id_offset=0, time_offset=0, initial_checkpoint=None, identity=None,
                actor_identity="caller-test"):
    """Build a new signed dependency graph. A phase fault precedes all consumers.

    Faults map phase names to field updates or callables. Every later digest,
    signature, event pointer and observation is constructed from that bad phase,
    so semantic negatives do not rely on stale hashes or invalid signatures.
    """
    faults, times = faults or {}, times or {}
    objects = {}
    def uid(number):
        return str(UUID(int=number + id_offset))
    def alter(name, value):
        fault = faults.get(name)
        if callable(fault):
            fault(value)
        elif fault:
            value.update(deepcopy(fault))
        objects[name] = value
        return value
    def tm(name, default):
        return times.get(name, default + time_offset)

    root, receipt_key, tls = (Ed25519PrivateKey.generate() for _ in range(3))
    der = tls.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    pin = obj("authority_pin", authority_domain_id=uid(1), authority_instance_id=uid(2), authority_generation=1,
              receipt_public_key=public(receipt_key).hex(), receipt_key_id=sha(public(receipt_key)), api_version=2,
              https_origin="https://authority.test", server_spki_sha256=sha(der), operator_root_key_id=sha(public(root)))
    deployment = DeploymentEvidence("test-core", uid(3), uid(4), uid(5), b"synthetic-deployment", b"synthetic-component", der)
    if parent is not None:
        root, receipt_key, pin, deployment = parent.root, parent.receipt_key, parent.pin, parent.deployment
    ident = obj("identity", qingyu_identity_id=uid(6), continuity_id=uid(7), genesis_operation_id=uid(8))
    if identity is not None:
        ident = deepcopy(identity)
    elif parent is not None:
        ident = deepcopy(parent.request["intent"]["identity"])
    scope = obj("requested_scope", trust_domain_id=parent.request["intent"]["scope"]["trust_domain_id"] if parent else uid(9), **{name: pin[name] for name in
                ("authority_domain_id", "authority_instance_id", "authority_generation")},
                actor_identity=actor_identity, owner_version=1, continuity_epoch=1, expected_state_version=4,
                storage_generation_id=deployment.storage_generation_id, control_plane_generation_id=deployment.control_plane_generation_id,
                lease_id=uid(10), lease_generation=1, caller_runtime_id=uid(11), session_id=uid(12), capability="core_governance",
                expected_authority_ref=obj("authority_ref", wire_version=2, authority_generation=1, authority_sequence=4, receipt_hash="a"*64),
                expected_audit_ref=obj("audit_ref", wire_version=2, audit_sequence=4, audit_hash="b"*64))
    previous = initial_checkpoint if initial_checkpoint is not None else (parent.objects["after"] if parent else None)
    if previous is not None:
        scope.update(expected_state_version=previous["state_version"], expected_authority_ref=deepcopy(previous["authority_ref"]),
                     expected_audit_ref=deepcopy(previous["audit_ref"]))
    intent = obj("business_intent", operation_id=uid(13), mutation_id="test-mutation" + ("-" + str(id_offset) if id_offset else ""), local_commit_id=uid(14),
                 identity=ident, scope=scope, payload={"amount": 17, "message": "\u6674\u96e8", "list": [None, True, -7]},
                 requested_decision=decision, created_at=900 + time_offset, reason="Synthetic caller evidence")
    source = obj("source_decision", authorization_id=uid(15), authorization_kind="CALLER_INTENT", intent_digest=h2(intent),
                 identity_digest=h2(ident), scope_digest=h2(scope), authorization_principal=scope["actor_identity"],
                 requested_decision=decision, created_at=intent["created_at"])
    request = obj("mutation_request", intent=intent, source_decision=source,
                  commit=request_branch(intent, source, "COMMIT"), abort=request_branch(intent, source, "ABORT"))
    authority, core = (deepcopy(parent.authority), deepcopy(parent.core)) if parent else (registry(pin), registry(pin, deployment))
    world = World(request, authority, core, pin, deployment, FixedTrust(c2(pin), public(root)), objects, root, receipt_key)
    def signed(name, kind, **values):
        value = obj(kind, **values)
        alter(name, value)
        return world.sign(value)
    common = {"operation_id": intent["operation_id"], "request_digest": h2(request), "source_decision_digest": h2(source)}
    authority_fields = {name: pin[name] for name in ("authority_domain_id", "authority_instance_id", "authority_generation")}
    policy = signed("policy", "recovery_policy", policy_id=uid(20), deployment_admission_digest=sha(deployment.deployment_bytes),
                    **authority_fields, **{name: ident[name] for name in ("continuity_id", "qingyu_identity_id", "genesis_operation_id")},
                    **{name: getattr(deployment, name) for name in ("core_installation_id", "storage_generation_id", "control_plane_generation_id", "runtime_principal")},
                    component_artifact_digest=sha(deployment.component_bytes), trust_config_digest=h2(pin), restoration_context_digest=None,
                    capabilities=list(ACTIONS), allowed_operation_type="MUTATION", issued_at=800 + time_offset, expires_at=100000 + time_offset,
                    operator_root_key_id=pin["operator_root_key_id"], root_signature="0"*128)
    # The original caller admission is distinct from the recovery session/lease
    # created later below. These are synthetic original source bytes, not a
    # trusted-source adapter or a claim that local OS admission has happened.
    alter("source_admission", record("source_admission", operation_id=intent["operation_id"],
          intent_digest=h2(intent), source_decision_digest=h2(source), identity_digest=h2(ident), scope_digest=h2(scope),
          **{name: scope[name] for name in ("actor_identity", "caller_runtime_id", "session_id", "lease_id", "lease_generation")},
          admitted_at=900 + time_offset, session_issued_at=850 + time_offset, session_expires_at=950 + time_offset,
          lease_issued_at=850 + time_offset, lease_expires_at=950 + time_offset,
          normal_business_admission=True, core_installation_id=deployment.core_installation_id,
          deployment_admission_digest=sha(deployment.deployment_bytes), component_artifact_digest=sha(deployment.component_bytes),
          trust_config_digest=h2(pin)))
    enrollment = record("enrollment", **{name: policy[name] for name in ("runtime_principal", "core_installation_id", "restoration_context_digest",
                        "authority_domain_id", "authority_instance_id", "authority_generation", "storage_generation_id", "control_plane_generation_id",
                        "deployment_admission_digest", "component_artifact_digest", "trust_config_digest")},
                        policy_digest=h2(policy), context_kind="INTACT_ADMITTED", purpose="MUTATION_RECOVERY", identity_digest=h2(ident))
    alter("enrollment", enrollment)
    session = alter("session", record("session_binding", history_version=2, session_id=uid(21), enrollment=enrollment,
                    issued_at=tm("register", 1000), expires_at=50000 + time_offset))
    inventory = alter("inventory", obj("recovery_inventory", inventory_id=uid(22), policy_digest=h2(policy),
                      core_installation_id=deployment.core_installation_id, runtime_principal=deployment.runtime_principal,
                      session_id=session["session_id"], entries=[{**common, "local_commit_id": intent["local_commit_id"]}]))
    fences = record("fences", **authority_fields, identity=ident, owner_identity=scope["actor_identity"], owner_version=1,
                    continuity_epoch=1, state_version=scope["expected_state_version"], storage_generation_id=scope["storage_generation_id"],
                    control_plane_generation_id=scope["control_plane_generation_id"], authority_ref=scope["expected_authority_ref"], audit_ref=scope["expected_audit_ref"])
    before = obj("local_checkpoint", state_version=scope["expected_state_version"], authority_ref=scope["expected_authority_ref"], audit_ref=scope["expected_audit_ref"])
    objects["before"] = before
    event(authority, "FENCES_SET", 900 + time_offset, record("fence_state", history_version=2, operation_id=intent["operation_id"], fences=fences,
                                           barrier_operation_id=intent["operation_id"], unresolved_operation_ids=[intent["operation_id"]]))
    for kind, value in (("POLICY_REGISTER", policy), ("SESSION_CREATE", session), ("INVENTORY_ACCEPT", inventory)):
        event(authority, kind, tm("register", 1000), value)
    lease = alter("lease", record("operation_lease", history_version=2, lease_id=uid(23), lease_generation=1,
                  operation_id=intent["operation_id"], request_digest=h2(request), runtime_principal=deployment.runtime_principal,
                  session_id=session["session_id"], issued_at=tm("grant", 1000), expires_at=30000 + time_offset))
    event(authority, "LEASE_CREATE", tm("grant", 1000), lease)
    binding = {"runtime_principal": deployment.runtime_principal, "session_id": session["session_id"],
               "policy_digest": h2(policy), "inventory_digest": h2(inventory)}
    def issue(name, kind, body, target):
        body = {"type": kind, "version": 2, "contract_revision": 2, **body}
        alter(name, body)
        put(authority, target)
        snap = record("issuance_snapshot", history_version=2, position=position(authority), issued_at=body["issued_at"],
                      issuance_kind="GRANT" if kind == "execution_grant" else "PERMIT", issuer_key_id=body["receipt_key_id"],
                      **{key: body[key] for key in (*binding.keys(), *common.keys())},
                      restoration_context_digest=body.get("restoration_context_digest"), issue_body_digest=raw(body), fences_or_target_digest=raw(target))
        alter(name + "_issuance", snap)
        body.update(issuance_digest=raw(snap), receipt_signature="0"*128)
        world.sign(body)
        event(authority, "GRANT_ISSUED" if kind == "execution_grant" else "PERMIT_ISSUED", body["issued_at"], snap, body)
        return body
    grant = issue("grant", "execution_grant", {"grant_id": uid(24), "grant_sequence": 1, **binding, **common, **authority_fields,
                  **{name: ident[name] for name in ("continuity_id", "qingyu_identity_id", "genesis_operation_id")},
                  "owner_identity": scope["actor_identity"], "owner_version": 1, "continuity_epoch": 1, "expected_state_version": scope["expected_state_version"],
                  "storage_generation_id": scope["storage_generation_id"], "control_plane_generation_id": scope["control_plane_generation_id"],
                  "lease_id": lease["lease_id"], "lease_generation": lease["lease_generation"], "issued_at": tm("grant", 1000), "expires_at": 20000 + time_offset,
                  "receipt_key_id": pin["receipt_key_id"]}, fences)
    def payload(name, ack=None, auth=None, proposal=None, publication=None):
        return alter(name, record("action_input", history_version=2, **common, ack_digest=h2(ack) if ack else None,
                     authorization_digest=h2(auth) if auth else None, proposal_digest=raw(proposal) if proposal else None,
                     publication_digest=raw(publication) if publication else None))
    def execution(name, at, action, inp):
        put(authority, inp)
        return alter(name, record("execution_snapshot", history_version=2, position=position(authority), checked_at=at, action=action,
                     **binding, **common, grant_digest=h2(grant), action_input_digest=raw(inp), fences=fences,
                     barrier_operation_id=intent["operation_id"], unresolved_operation_ids=[intent["operation_id"]],
                     remote_phase="ABSENT" if action == "PREPARE_EXISTING" else "PREPARED"))
    prepare = execution("prepare", tm("prepare", 1100), "PREPARE_EXISTING", payload("prepare_input"))
    ack = signed("ack", "prepare_ack", contract_revision=2, **authority_fields, receipt_key_id=pin["receipt_key_id"], **common,
                 identity_digest=h2(ident), commit_candidate_digest=h2(request["commit"]), abort_candidate_digest=h2(request["abort"]),
                 prepare_execution_grant_digest=h2(grant), prepare_execution_digest=raw(prepare), authority_predecessor=scope["expected_authority_ref"],
                 prepared_at=tm("prepare", 1100), receipt_signature="0"*128)
    event(authority, "PREPARE", tm("prepare", 1100), prepare, ack)
    stage = obj("staged_evidence", operation_id=intent["operation_id"], local_commit_id=intent["local_commit_id"], request_digest=h2(request),
                ack_digest=h2(ack), commit_candidate_digest=h2(request["commit"]), abort_candidate_digest=h2(request["abort"]))
    objects["stage"] = stage
    actual = "ABORT" if override else decision
    selected = request[actual.lower()]
    if override:
        auth = signed("authorization", "abort_override", override_id=uid(25), **common, supersedes_authorization_id=source["authorization_id"],
                      previous_authorization_digest=h2(source), identity_digest=h2(ident), scope_digest=h2(scope), authorized_decision="ABORT",
                      abort_candidate_digest=h2(request["abort"]), reason="Synthetic scoped forward abort", issued_at=tm("override_issued", 1150),
                      expires_at=tm("override_expires", 10000), operator_root_key_id=pin["operator_root_key_id"], root_signature="0"*128)
    else:
        auth = alter("authorization", obj("terminal_authorization", authorization_id=uid(26), **common, local_commit_id=intent["local_commit_id"],
                     ack_digest=h2(ack), decision=actual, candidate_digest=h2(selected), staging_evidence_digest=h2(stage),
                     no_local_business_commit=actual == "ABORT", created_at=tm("proposal", 1200)))
    for kind, value in (("POLICY_OBSERVED", policy), ("SESSION_OBSERVED", session), ("INVENTORY_OBSERVED", inventory)):
        observe(core, authority, kind, value, tm("observe", 1100))
    event(core, "LOCAL_PROTECTION", tm("observe", 1100), record("local_protection", history_version=2, policy_digest=h2(policy),
          component_valid=True, policy_active=True, context_kind=enrollment["context_kind"]))
    def local(name, at, action, target, inp):
        put(core, target); put(core, inp)
        return alter(name, record("local_snapshot", history_version=2, position=position(core), checked_at=at, action=action,
                     **binding, **common, target_digest=raw(target), action_input_digest=raw(inp)))
    proposal = alter("proposal", record("dispatch_record", history_version=2, proposal_position=position(core), kind="OPERATOR_ABORT" if override else "NORMAL",
                    **common, local_commit_id=intent["local_commit_id"], ack_digest=h2(ack), staging_evidence_digest=h2(stage),
                    semantic_authorization_digest=h2(auth), runtime_principal=deployment.runtime_principal, session_id=session["session_id"],
                    core_installation_id=deployment.core_installation_id, created_at=tm("proposal", 1200), no_local_business_commit=actual == "ABORT", before_checkpoint=before))
    put(core, auth)
    prop_snap = local("proposal_snapshot", tm("proposal", 1200), "PROPOSE_DISPATCH", before, payload("proposal_input", ack, auth))
    event(core, "PROPOSAL", tm("proposal", 1200), prop_snap, proposal)
    put(authority, proposal); put(authority, auth)
    fix_snap = execution("fix", tm("fix", 1200), "FIX_ORIGINAL_DISPATCH", payload("fix_input", ack, auth, proposal))
    fix = alter("fix_acceptance", record("fix_acceptance", history_version=2, proposal_digest=raw(proposal), execution_digest=raw(fix_snap),
                accepted_at=tm("fix", 1200), kind=proposal["kind"]))
    event(authority, "FIX_ACCEPTED", tm("fix", 1200), fix_snap, fix)
    put(core, fix)
    pub_snap = local("publication_snapshot", tm("publication", 1250), "PUBLISH_DISPATCH", before, payload("publication_input", ack, auth, proposal))
    publication = alter("publication", record("dispatch_publication", history_version=2, position=position(core), published_at=tm("publication", 1250),
                        proposal_digest=raw(proposal), fix_acceptance_digest=raw(fix)))
    event(core, "PUBLICATION", tm("publication", 1250), pub_snap, publication)
    put(authority, publication)
    terminal_snap = execution("terminal", tm("terminal", 1300), "TERMINATE_ORIGINAL", payload("terminal_input", ack, auth, proposal, publication))
    receipt = signed("receipt", "terminal_receipt", contract_revision=2, **authority_fields, receipt_key_id=pin["receipt_key_id"], **common,
                     operation_type="MUTATION", identity_digest=h2(ident), ack_digest=h2(ack), authorization_kind=proposal["kind"],
                     semantic_authorization_digest=h2(auth), execution_grant_digest=h2(grant), decision=actual, result_state=selected["result"]["result_state"],
                     candidate_digest=h2(selected), effect_digest=h2(selected["effect"]), result_digest=h2(selected["result"]),
                     audit_candidate_digest=h2(selected["audit_candidate"]), state_before=scope["expected_state_version"], state_after=selected["result"]["state_version"],
                     audit_sequence=scope["expected_audit_ref"]["audit_sequence"] + 1,
                     authority_sequence=scope["expected_authority_ref"]["authority_sequence"] + 1, previous_authority_ref=scope["expected_authority_ref"], decided_at=tm("terminal", 1300),
                     fix_execution_digest=raw(fix_snap), terminal_execution_digest=raw(terminal_snap), receipt_signature="0"*128)
    event(authority, "TERMINAL", tm("terminal", 1300), terminal_snap, receipt)
    audit = obj("audit_record", candidate=selected["audit_candidate"], receipt_digest=h2(receipt))
    objects["audit"] = audit
    after = obj("local_checkpoint", state_version=selected["result"]["state_version"],
                authority_ref=obj("authority_ref", wire_version=2, authority_generation=pin["authority_generation"], authority_sequence=receipt["authority_sequence"], receipt_hash=h2(receipt)),
                audit_ref=obj("audit_ref", wire_version=2, audit_sequence=receipt["audit_sequence"], audit_hash=h2(audit)))
    objects["after"] = after
    if complete:
        target = alter("target", record("finish_target", history_version=2, identity_digest=h2(ident), authority_pin_digest=h2(pin),
                       **{name: policy[name] for name in ("core_installation_id", "storage_generation_id", "control_plane_generation_id", "restoration_context_digest")},
                       **common, terminal_digest=h2(receipt), before_checkpoint=before, after_checkpoint=after))
        permit = issue("permit", "local_finish_permit", {"permit_id": uid(27), "permit_sequence": 1, **binding, **common,
                       "restoration_context_digest": None, "core_installation_id": deployment.core_installation_id,
                       "terminal_digest": h2(receipt), "before_checkpoint": before, "after_checkpoint": after,
                       "issued_at": tm("permit", 1400), "expires_at": tm("permit_expires", 15000), "receipt_key_id": pin["receipt_key_id"]}, target)
        observe(core, authority, "PERMIT_OBSERVED", permit, tm("permit_observe", 1450))
        local_target = alter("local_target", deepcopy(target))
        content = {"effect_digest": h2(selected["effect"]), "result_digest": h2(selected["result"]), "audit_record_digest": h2(audit)}
        use = alter("use_input", record("use_input", history_version=2, permit_digest=h2(permit), issuance_digest=permit["issuance_digest"],
                    target_digest=raw(local_target), terminal_digest=h2(receipt), **content))
        use_snap = local("use_snapshot", tm("apply", 1500), "APPLY_VERIFIED_TERMINAL", local_target, use)
        completion = alter("completion", record("completion_record", history_version=2, position=position(core), completed_at=tm("apply", 1500),
                           permit_digest=h2(permit), issuance_digest=permit["issuance_digest"], local_use_digest=raw(use_snap), **common,
                           terminal_digest=h2(receipt), target_digest=raw(local_target), before_checkpoint=before, after_checkpoint=after, **content))
        event(core, "APPLY", tm("apply", 1500), use_snap, completion)
    return world
