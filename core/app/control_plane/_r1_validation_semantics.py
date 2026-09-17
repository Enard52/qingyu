"""Internal relation checks over supplied history; never an admission authority.

Local replay state is a calculation, not authenticated registry storage. The
public r1_validation entry verifies real signatures separately and deliberately
reports source provenance UNVERIFIED. No producer, fixture, database, clock,
current-query authorization or business-write operation is exported here.
"""
from __future__ import annotations
import copy
import hashlib
from uuid import UUID
from dataclasses import dataclass
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
from .r1_validation_codec import (
    MAX, A_KINDS, C_KINDS, PRODUCING_ACTIONS, RESTORE_ACTIONS, SCHEMA, STRUCT,
    RECORD, ContractError, require, c2, decode, h2, sha, validate, validate_fields,
    match, obj, record, eq_fields,
)

@dataclass(frozen=True, slots=True)
class DeploymentEvidence:
    """Explicit opaque deployment evidence, without a provenance attestation.

    These values must ultimately come from a protected source adapter. This
    slice only checks their content against signed policy and fixed pin; it
    cannot establish deployment admission or local OS protection.
    """
    runtime_principal: str
    core_installation_id: str
    storage_generation_id: str
    control_plane_generation_id: str
    deployment_bytes: bytes
    component_bytes: bytes
    tls_spki_der: bytes

    def validate(self):
        match(self.runtime_principal, "text")
        for name in ("core_installation_id", "storage_generation_id", "control_plane_generation_id"):
            match(getattr(self, name), "uuid")
        for name in ("deployment_bytes", "component_bytes", "tls_spki_der"):
            require(type(getattr(self, name)) is bytes and bool(getattr(self, name)), "missing exact deployment evidence bytes")

def validate_pin_material(pin, material):
    validate(pin)
    require(type(material) is DeploymentEvidence, "explicit deployment evidence required")
    material.validate()
    require(sha(material.tls_spki_der) == pin["server_spki_sha256"], "TLS SPKI content does not match fixed pin")
    try:
        key = load_der_public_key(material.tls_spki_der)
        encoded = key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
        raise ContractError("invalid TLS SPKI DER") from exc
    require(encoded == material.tls_spki_der, "TLS SPKI must be exact complete DER")

def validate_policy_material(policy, pin, material):
    validate(policy)
    validate_pin_material(pin, material)
    require(policy["type"] == "recovery_policy", "policy type")
    eq_fields(policy, {
        "trust_config_digest": h2(pin), "operator_root_key_id": pin["operator_root_key_id"],
        "deployment_admission_digest": sha(material.deployment_bytes),
        "component_artifact_digest": sha(material.component_bytes),
        **{k: pin[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation")},
        **{k: getattr(material, k) for k in ("runtime_principal", "core_installation_id", "storage_generation_id", "control_plane_generation_id")},
    }, "policy deployment/pin content mismatch")


def verify_source_admission(admission, request, pin, material):
    """Bind original business admission, separately from later recovery actors.

    Matching this supplied record does not authenticate its source. The public
    result retains UNVERIFIED provenance even after these relations hold.
    """
    validate_fields(admission, RECORD["source_admission"])
    intent, scope, source = request["intent"], request["intent"]["scope"], request["source_decision"]
    eq_fields(admission, {
        "operation_id": intent["operation_id"], "intent_digest": h2(intent),
        "source_decision_digest": h2(source), "identity_digest": h2(intent["identity"]),
        "scope_digest": h2(scope), "admitted_at": intent["created_at"],
        "normal_business_admission": True, "core_installation_id": material.core_installation_id,
        "deployment_admission_digest": sha(material.deployment_bytes),
        "component_artifact_digest": sha(material.component_bytes), "trust_config_digest": h2(pin),
        **{k: scope[k] for k in ("actor_identity", "caller_runtime_id", "session_id", "lease_id", "lease_generation")},
    }, "original source admission mismatch")
    at = admission["admitted_at"]
    require(admission["session_issued_at"] <= at < admission["session_expires_at"]
            and admission["lease_issued_at"] <= at < admission["lease_expires_at"],
            "original source was not live when admitted")
    verify_request(request, pin, admission["actor_identity"])

def header(pin, material=None):
    if material is not None:
        validate_pin_material(pin, material)
    scope = {"registry_kind": "CORE_LOCAL" if material is not None else "AUTHORITY_QUALIFICATION",
        **{k: pin[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation")},
        **{k: getattr(material, k) if material is not None else None for k in ("core_installation_id", "storage_generation_id", "control_plane_generation_id")}}
    digest = hashlib.sha256(b"QINGYU-R1-SCOPED-REGISTRY-V2\0" + c2(scope)).digest()
    return record("registry_header", history_version=2, registry_id=str(UUID(bytes=digest[:16])),
        **scope, provenance_digest=sha(material.deployment_bytes) if material is not None else h2(pin))


def branch(intent, source, decision):
    require(decision in ("COMMIT", "ABORT"), "decision")
    scope = intent["scope"]
    after = scope["expected_state_version"] + (decision == "COMMIT")
    require(after <= MAX and scope["expected_audit_ref"]["audit_sequence"] < MAX, "counter overflow")
    value = {"payload": copy.deepcopy(intent["payload"]), "capability": "core_governance",
             "requested_decision": intent["requested_decision"]}
    effect = obj("business_effect", entries=[{"mutation_id": intent["mutation_id"], "value": value}] if decision == "COMMIT" else [])
    outcome = "COMMITTED" if decision == "COMMIT" else "ABORTED"
    result = obj("mutation_result", mutation_id=intent["mutation_id"], result_state=outcome,
                 state_version=after, effect_digest=h2(effect), value=value if decision == "COMMIT" else None)
    audit = obj("audit_content", operation_id=intent["operation_id"], mutation_id=intent["mutation_id"],
                identity_digest=h2(intent["identity"]), scope_digest=h2(scope), intent_digest=h2(intent),
                source_decision_digest=h2(source), payload_digest=h2(obj("business_payload", value=intent["payload"])),
                decision=decision, result_state=outcome, state_version=after, effect_digest=h2(effect), result_digest=h2(result),
                audit_sequence=scope["expected_audit_ref"]["audit_sequence"] + 1,
                previous_audit_ref=scope["expected_audit_ref"], created_at=intent["created_at"])
    return obj("branch_bundle", decision=decision, effect=effect, result=result, audit_candidate=audit)

def verify_request(request, pin, expected_actor, expected_request_digest=None):
    validate(request)
    require(request["type"] == "mutation_request", "request type")
    intent, source = request["intent"], request["source_decision"]
    scope = intent["scope"]
    require(scope["actor_identity"] == source["authorization_principal"] == expected_actor, "source actor relation differs")
    for field in ("authority_domain_id", "authority_instance_id", "authority_generation"):
        require(scope[field] == pin[field], "Authority tuple differs")
    for field, expected in (("intent_digest", h2(intent)), ("identity_digest", h2(intent["identity"])),
                            ("scope_digest", h2(scope)), ("requested_decision", intent["requested_decision"])):
        require(source[field] == expected, "source decision differs: " + field)
    require(source["created_at"] == intent["created_at"], "source creation time differs")
    for name, decision in (("commit", "COMMIT"), ("abort", "ABORT")):
        require(c2(request[name]) == c2(branch(intent, source, decision)), "independent semantic derivation mismatch: " + name)
    if expected_request_digest is not None:
        require(h2(request) == expected_request_digest, "same operation content conflict")
    return request

def verify_grant_bindings(grant, request, policy, inventory, *, now, current_sequence, authenticated_principal, authenticated_session):
    for value in (grant, request, policy, inventory):
        validate(value)
    intent, scope = request["intent"], request["intent"]["scope"]
    expected = {"operation_id": intent["operation_id"], "request_digest": h2(request),
                "source_decision_digest": h2(request["source_decision"]), "policy_digest": h2(policy),
                "inventory_digest": h2(inventory), "owner_identity": scope["actor_identity"],
                **{key: scope[key] for key in ("authority_domain_id", "authority_instance_id", "authority_generation",
                   "owner_version", "continuity_epoch", "expected_state_version", "storage_generation_id", "control_plane_generation_id")},
                **{key: intent["identity"][key] for key in ("qingyu_identity_id", "continuity_id", "genesis_operation_id")}}
    require(all(grant[k] == v for k, v in expected.items()), "grant rebinds immutable request fence")
    require(grant["grant_sequence"] == current_sequence, "superseded execution grant")
    require(grant["runtime_principal"] == policy["runtime_principal"] == authenticated_principal
            and grant["session_id"] == authenticated_session, "grant caller is not current authenticated subject")
    require(grant["issued_at"] <= now < grant["expires_at"] <= policy["expires_at"], "grant/policy interval")
    require(inventory["policy_digest"] == h2(policy) and inventory["runtime_principal"] == authenticated_principal
            and inventory["session_id"] == authenticated_session and inventory["core_installation_id"] == policy["core_installation_id"],
            "inventory source scope")
    entry = {"operation_id": intent["operation_id"], "request_digest": h2(request),
             "source_decision_digest": h2(request["source_decision"]), "local_commit_id": intent["local_commit_id"]}
    require(entry in inventory["entries"], "operation absent from frozen recovery inventory")

def verify_prepare_ack_bindings(ack, request, pin):
    """Original PREPARE output semantics, separate from execution qualification."""
    validate(ack)
    require(ack["type"] == "prepare_ack", "original Ack type")
    intent, source, scope = request["intent"], request["source_decision"], request["intent"]["scope"]
    eq_fields(ack, {"operation_id": intent["operation_id"], "identity_digest": h2(intent["identity"]),
        "request_digest": h2(request), "source_decision_digest": h2(source),
        "commit_candidate_digest": h2(request["commit"]), "abort_candidate_digest": h2(request["abort"]),
        "authority_predecessor": scope["expected_authority_ref"],
        **{k: pin[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation", "receipt_key_id")}},
        "original Ack request/candidate/pin binding")

def verify_override_bindings(authorization, request, pin):
    """Original Root exception semantics; current execution qualification is separate."""
    validate(authorization)
    require(authorization["type"] == "abort_override", "override authorization type")
    verify_request(request, pin, request["intent"]["scope"]["actor_identity"])
    intent, source = request["intent"], request["source_decision"]
    expected = {"operation_id": intent["operation_id"], "request_digest": h2(request),
                "source_decision_digest": h2(source), "previous_authorization_digest": h2(source),
                "supersedes_authorization_id": source["authorization_id"], "identity_digest": h2(intent["identity"]),
                "scope_digest": h2(intent["scope"]), "abort_candidate_digest": h2(request["abort"]),
                "operator_root_key_id": pin["operator_root_key_id"]}
    require(all(authorization[k] == v for k, v in expected.items()), "operator ABORT scope mismatch")

def verify_normal_authorization_bindings(authorization, request, ack, pin):
    """Exact NORMAL semantics at the original dispatch, independent of producer."""
    validate(authorization)
    require(authorization["type"] == "terminal_authorization", "normal authorization type")
    verify_request(request, pin, request["intent"]["scope"]["actor_identity"])
    verify_prepare_ack_bindings(ack, request, pin)
    intent, source = request["intent"], request["source_decision"]
    decision = intent["requested_decision"]
    stage = obj("staged_evidence", operation_id=intent["operation_id"], local_commit_id=intent["local_commit_id"],
        request_digest=h2(request), ack_digest=h2(ack), commit_candidate_digest=h2(request["commit"]),
        abort_candidate_digest=h2(request["abort"]))
    eq_fields(authorization, {"operation_id": intent["operation_id"], "local_commit_id": intent["local_commit_id"],
        "request_digest": h2(request), "source_decision_digest": h2(source), "ack_digest": h2(ack),
        "decision": decision, "candidate_digest": h2(request[decision.lower()]),
        "staging_evidence_digest": h2(stage), "no_local_business_commit": decision == "ABORT"},
        "normal authorization original binding")
    require(authorization["authorization_id"] != source["authorization_id"], "normal authorization reuses source ID")
    require(ack["prepared_at"] <= authorization["created_at"], "normal authorization precedes original Ack")

def verify_override_proposal(proposal, request, ack, authorization, pin):
    """Bind either existing dispatch kind; retain the prior helper name for callers."""
    validate_fields(proposal, RECORD["dispatch_record"])
    validate(authorization)
    require((proposal["kind"] == "OPERATOR_ABORT") == (authorization["type"] == "abort_override"),
            "proposal authorization kind mismatch")
    if proposal["kind"] == "NORMAL":
        verify_normal_authorization_bindings(authorization, request, ack, pin)
        require(authorization["created_at"] == proposal["created_at"], "normal proposal authorization time")
    else:
        verify_override_bindings(authorization, request, pin)
    verify_prepare_ack_bindings(ack, request, pin)
    intent, source = request["intent"], request["source_decision"]
    stage = obj("staged_evidence", operation_id=intent["operation_id"], local_commit_id=intent["local_commit_id"],
        request_digest=h2(request), ack_digest=h2(ack), commit_candidate_digest=h2(request["commit"]),
        abort_candidate_digest=h2(request["abort"]))
    eq_fields(proposal, {"operation_id": intent["operation_id"], "local_commit_id": intent["local_commit_id"],
        "request_digest": h2(request), "source_decision_digest": h2(source), "ack_digest": h2(ack),
        "staging_evidence_digest": h2(stage), "semantic_authorization_digest": h2(authorization),
        "no_local_business_commit": proposal["kind"] == "OPERATOR_ABORT" or intent["requested_decision"] == "ABORT",
        "before_checkpoint": before_checkpoint(request)}, "proposal original binding")
    require(ack["prepared_at"] <= proposal["created_at"], "proposal precedes original Ack")
    if proposal["kind"] == "OPERATOR_ABORT":
        require(authorization["issued_at"] <= proposal["created_at"] < authorization["expires_at"],
                "override interval at original proposal")

def verify_terminal_bindings(receipt, request, ack, authorization, grant, pin):
    for value in (receipt, ack, authorization, grant, pin):
        validate(value)
    verify_request(request, pin, request["intent"]["scope"]["actor_identity"])
    intent, source, scope = request["intent"], request["source_decision"], request["intent"]["scope"]
    decision = receipt["decision"]
    selected = request["commit" if decision == "COMMIT" else "abort"]
    verify_prepare_ack_bindings(ack, request, pin)
    if receipt["authorization_kind"] == "NORMAL":
        require(authorization["type"] == "terminal_authorization" and decision == intent["requested_decision"] == authorization["decision"], "normal dispatch changed decision")
        verify_normal_authorization_bindings(authorization, request, ack, pin)
        require(authorization["created_at"] <= receipt["decided_at"], "terminal precedes normal authorization")
    else:
        require(authorization["type"] == "abort_override" and decision == "ABORT", "override cannot COMMIT")
        verify_override_bindings(authorization, request, pin)
    expected = {"operation_id": intent["operation_id"], "identity_digest": h2(intent["identity"]), "request_digest": h2(request),
                "source_decision_digest": h2(source), "ack_digest": h2(ack), "semantic_authorization_digest": h2(authorization),
                "execution_grant_digest": h2(grant), "candidate_digest": h2(selected), "effect_digest": h2(selected["effect"]),
                "result_digest": h2(selected["result"]), "audit_candidate_digest": h2(selected["audit_candidate"]),
                "result_state": selected["result"]["result_state"], "state_before": scope["expected_state_version"],
                "state_after": selected["result"]["state_version"], "audit_sequence": selected["audit_candidate"]["audit_sequence"],
                "authority_sequence": scope["expected_authority_ref"]["authority_sequence"] + 1,
                "previous_authority_ref": scope["expected_authority_ref"],
                **{k: pin[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation", "receipt_key_id")}}
    require(all(receipt[k] == v for k, v in expected.items()), "terminal binding mismatch")
    return obj("audit_record", candidate=selected["audit_candidate"], receipt_digest=h2(receipt))

def expected_fences(request):
    s = request["intent"]["scope"]
    return record("fences", **{k: s[k] for k in ("authority_domain_id", "authority_instance_id", "authority_generation",
                   "owner_version", "continuity_epoch", "storage_generation_id", "control_plane_generation_id")},
                  identity=request["intent"]["identity"], owner_identity=s["actor_identity"], state_version=s["expected_state_version"],
                  authority_ref=s["expected_authority_ref"], audit_ref=s["expected_audit_ref"])

def before_checkpoint(request):
    s = request["intent"]["scope"]
    return obj("local_checkpoint", state_version=s["expected_state_version"], audit_ref=s["expected_audit_ref"], authority_ref=s["expected_authority_ref"])

def receipt_ref(receipt):
    return obj("authority_ref", wire_version=2, authority_generation=receipt["authority_generation"],
               authority_sequence=receipt["authority_sequence"], receipt_hash=h2(receipt))

def audit_ref(audit):
    return obj("audit_ref", wire_version=2, audit_sequence=audit["candidate"]["audit_sequence"], audit_hash=h2(audit))

def after_checkpoint(receipt, audit):
    return obj("local_checkpoint", state_version=receipt.get("state_after", receipt.get("state_version")),
               audit_ref=audit_ref(audit), authority_ref=receipt_ref(receipt))

def verify_finish_inventory(policy,inventory,terminal):
    intent=terminal["request"]["intent"]
    require(all(policy[k]==intent["identity"][k] for k in ("qingyu_identity_id","continuity_id","genesis_operation_id")),"finish policy immutable identity differs")
    entry={"operation_id":intent["operation_id"],"request_digest":h2(terminal["request"]),"source_decision_digest":h2(terminal["request"]["source_decision"]),"local_commit_id":intent["local_commit_id"]}
    require(entry in inventory["entries"],"finish terminal absent from exact frozen inventory")

def rawhash(value):
    return sha(c2(value))

def position(reg, number=None):
    return {"history_version":2,"registry_digest":rawhash(reg["header"]),
            "event_sequence":len(reg["events"])+1 if number is None else number}

def registry_structure(reg,pin,material=None):
    require(set(reg)=={"header","events","records"},"registry exact fields")
    require(reg["header"]==header(pin,material),"registry source/header does not equal independently supplied expected scope")
    validate_fields(reg["header"],RECORD["registry_header"])
    require(type(reg["events"])is list and type(reg["records"])is dict,"registry container")
    for key,value in reg["records"].items():
        match(key,"hash");require(type(value)is dict,"registry original record must be object")
        raw=rawhash(value)
        allowed={raw,h2(value)} if value.get("type") in SCHEMA else {raw}
        require(key in allowed,"registry upstream key does not hash actual canonical preimage")
    kinds=C_KINDS if material is not None else A_KINDS
    last=0
    used=set()
    for i,e in enumerate(reg["events"],1):
        validate_fields(e,RECORD["registry_event"])
        require(e["position"]==position(reg,i) and e["event_kind"] in kinds,"registry event position/kind")
        require(e["recorded_at"]>=last,"registry time backdating");last=e["recorded_at"]
        require(e["input_digest"] in reg["records"],"UNKNOWN missing registry input")
        require(rawhash(reg["records"][e["input_digest"]])==e["input_digest"],"registry input content mismatch")
        used.add(e["input_digest"])
        if e["output_digest"] is not None:
            require(e["output_digest"] in reg["records"],"UNKNOWN missing registry output")
            o=reg["records"][e["output_digest"]]
            require((h2(o) if o.get("type") in SCHEMA else rawhash(o))==e["output_digest"],"registry output content mismatch")
            used.add(e["output_digest"])
    require(used<=set(reg["records"]),"registry record missing")
    return reg

def event_at(reg,pos,kind=None):
    validate_fields(pos,STRUCT["position"])
    n=pos["event_sequence"]
    require(pos==position(reg,n) and 1<=n<=len(reg["events"]),"UNKNOWN missing/wrong registry position")
    e=reg["events"][n-1]
    require(kind is None or e["event_kind"]==kind,"wrong event kind at bound position")
    return e,reg["records"][e["input_digest"]],None if e["output_digest"] is None else reg["records"][e["output_digest"]]

def empty_state():
    return {"policy_ids":{},"inventory_ids":{},"policies":{},"policy_active":{},"sessions":{},"session_active":{},"inventories":{},"leases":{},"lease_active":{},
            "grants":{},"grant_active":{},"grant_pointer":{},"permits":{},"permit_active":{},"permit_pointer":{},
            "fences":{},"phase":{},"acks":{},"fixes":{},"terminals":{}}

def immutable_registration(state, pin, value):
    """Register full C2 bytes in the existing domain and object-kind ID namespace.

    Return False for an exact repeat. An exact repeat is not an activation,
    issuance, pointer update, or replacement of the original history position.
    """
    kind = "policy" if value["type"] == "recovery_policy" else "inventory"
    key = (pin["authority_domain_id"], value[kind + "_id"])
    table = state[kind + "_ids"]
    encoded = c2(value)
    if key in table:
        require(table[key] == encoded, "immutable " + kind + " ID content conflict")
        return False
    table[key] = encoded
    return True

def subject_from(state,policy_digest,inventory_digest,session_id):
    require(policy_digest in state["policies"] and inventory_digest in state["inventories"]
            and session_id in state["sessions"],"subject did not exist at bound prefix")
    p=state["policies"][policy_digest]; inv=state["inventories"][inventory_digest];s=state["sessions"][session_id]
    return {"policy":p,"inventory":inv,"session":s,"enrollment":s["enrollment"]}

def check_subject(state,subject,pin,material,at,actions,context=None):
    p,inv,s,en=(subject[k] for k in ("policy","inventory","session","enrollment"))
    validate_policy_material(p,pin,material);validate(inv)
    validate_fields(s,RECORD["session_binding"]);validate_fields(en,RECORD["enrollment"])
    require(s["enrollment"]==en and en["purpose"]=="MUTATION_RECOVERY","subject enrollment/purpose")
    require(state["policies"].get(h2(p))==p and state["policy_active"].get(h2(p)) is True,"policy not active at bound prefix")
    require(state["sessions"].get(s["session_id"])==s and state["session_active"].get(s["session_id"]) is True,"session not active at bound prefix")
    require(state["inventories"].get(h2(inv))==inv,"inventory not accepted before action")
    require(p["issued_at"]<=at<p["expires_at"] and s["issued_at"]<=at<s["expires_at"],"policy/session action interval")
    expected={k:p[k] for k in ("runtime_principal","core_installation_id","restoration_context_digest","authority_domain_id","authority_instance_id","authority_generation","storage_generation_id","control_plane_generation_id","deployment_admission_digest","component_artifact_digest","trust_config_digest")}
    identity=obj("identity",**{k:p[k] for k in ("qingyu_identity_id","continuity_id","genesis_operation_id")})
    eq_fields(en,{**expected,"policy_digest":h2(p),"identity_digest":h2(identity)},"enrollment policy target mismatch")
    eq_fields(inv,{"policy_digest":h2(p),"core_installation_id":p["core_installation_id"],"runtime_principal":p["runtime_principal"],"session_id":s["session_id"]},"inventory subject mismatch")
    require(set(actions)<=set(p["capabilities"]),"policy action denied")
    if en["context_kind"]=="INTACT_ADMITTED":
        require(context is None and p["restoration_context_digest"] is None,"ordinary context mismatch")
    else:
        require(en["context_kind"]=="MANUAL_RESTORE_ADMITTED" and context is not None,"UNKNOWN/conflict or missing restore context")
        validate(context)
        require(h2(context)==p["restoration_context_digest"] and set(actions)<=set(RESTORE_ACTIONS),"restore action denied")
        require(set(p["capabilities"])<=set(RESTORE_ACTIONS),"restore policy broadens capabilities")
        require(context["issued_at"]<=at<context["expires_at"],"restore context interval")
        eq_fields(context,{"identity":identity,"target_core_installation_id":p["core_installation_id"],"target_storage_generation_id":p["storage_generation_id"],"target_control_plane_generation_id":p["control_plane_generation_id"],"target_authority_pin_digest":h2(pin),"operator_root_key_id":pin["operator_root_key_id"]},"restore target mismatch")
    return subject

def projection(body):
    return {k:v for k,v in body.items() if k not in ("issuance_digest","receipt_signature")}

def record_by(reg,digest,kind=None):
    require(digest in reg["records"],"UNKNOWN missing bound original bytes")
    v=reg["records"][digest]
    if kind is not None:
        validate_fields(v,RECORD[kind]);require(rawhash(v)==digest,"bound nonwire preimage requires exact RAW256 domain")
    else:
        expected=h2(v) if v.get("type") in SCHEMA else rawhash(v)
        require(expected==digest,"bound upstream preimage requires exact H2/RAW256 domain")
    return v

def replay_authority(reg,pin,materials,requests,contexts=None,stop=None):
    registry_structure(reg,pin)
    state=empty_state()
    limit=len(reg["events"]) if stop is None else stop
    require(0<=limit<=len(reg["events"]),"invalid strict prefix")
    contexts=contexts or {}
    for e in reg["events"][:limit]:
        _authority_event(reg,e,state,pin,materials,requests,contexts)
    return state


def _authority_event(reg,e,state,pin,materials,requests,contexts):
    """Internal transition; caller verifies original registry structure first."""
    k,t=e["event_kind"],e["recorded_at"];x=reg["records"][e["input_digest"]]
    out=None if e["output_digest"] is None else reg["records"][e["output_digest"]]
    require(k in ("GRANT_ISSUED","PERMIT_ISSUED","PREPARE","FIX_ACCEPTED","TERMINAL") or out is None,"state event unexpected output")
    if k=="POLICY_REGISTER":
        validate(x);require(x["type"]=="recovery_policy","policy event payload")
        if not immutable_registration(state,pin,x):
            return
        d=h2(x);require(x["issued_at"]<=t<x["expires_at"],"policy registration interval")
        require(x["runtime_principal"] in materials,"UNKNOWN policy deployment")
        validate_policy_material(x,pin,materials[x["runtime_principal"]])
        state["policies"][d]=x;state["policy_active"][d]=True
    elif k=="SESSION_CREATE":
        validate_fields(x,RECORD["session_binding"]);sid=x["session_id"];pd=x["enrollment"]["policy_digest"]
        require(sid not in state["sessions"] and state["policy_active"].get(pd) is True,"session created without current policy")
        require(x["issued_at"]==t and t<x["expires_at"]<=state["policies"][pd]["expires_at"],"session creation interval")
        p = state["policies"][pd]
        identity = obj("identity", **{key: p[key] for key in
            ("qingyu_identity_id", "continuity_id", "genesis_operation_id")})
        eq_fields(x["enrollment"], {
            **{key: p[key] for key in ("runtime_principal", "core_installation_id", "restoration_context_digest",
                "authority_domain_id", "authority_instance_id", "authority_generation", "storage_generation_id",
                "control_plane_generation_id", "deployment_admission_digest", "component_artifact_digest", "trust_config_digest")},
            "policy_digest": pd, "identity_digest": h2(identity), "purpose": "MUTATION_RECOVERY",
            "context_kind": "INTACT_ADMITTED" if p["restoration_context_digest"] is None else "MANUAL_RESTORE_ADMITTED",
        }, "session enrollment differs from its original policy target")
        require(p["issued_at"] <= t < p["expires_at"], "session created outside policy interval")
        state["sessions"][sid]=x;state["session_active"][sid]=True
    elif k=="INVENTORY_ACCEPT":
        validate(x);require(x["type"]=="recovery_inventory","inventory event payload")
        if not immutable_registration(state,pin,x):
            return
        sid=x["session_id"];pd=x["policy_digest"]
        require(state["session_active"].get(sid) is True and state["policy_active"].get(pd) is True,"inventory missing active source")
        p=state["policies"][pd];s=state["sessions"][sid]
        require(s["enrollment"]["policy_digest"]==pd and s["enrollment"]["runtime_principal"]==x["runtime_principal"]==p["runtime_principal"]
                and x["core_installation_id"]==p["core_installation_id"] and s["issued_at"]<=t<s["expires_at"],"inventory authenticated mapping")
        state["inventories"][h2(x)]=x
    elif k=="LEASE_CREATE":
        validate_fields(x,RECORD["operation_lease"]);sid=x["session_id"]
        require(state["session_active"].get(sid) is True and x["issued_at"]==t<x["expires_at"]
                and x["runtime_principal"]==state["sessions"][sid]["enrollment"]["runtime_principal"],"lease subject/interval")
        sess=state["sessions"][sid];pd=sess["enrollment"]["policy_digest"]
        inventories=[inv for inv in state["inventories"].values() if inv["session_id"]==sid and inv["policy_digest"]==pd
            and any(row["operation_id"]==x["operation_id"] and row["request_digest"]==x["request_digest"] for row in inv["entries"])]
        require(inventories and x["expires_at"]<=sess["expires_at"],"lease requires prior exact inventory and bounded session")
        check_subject(state,subject_from(state,pd,h2(inventories[0]),sid),pin,materials[x["runtime_principal"]],t,PRODUCING_ACTIONS)
        require(x["lease_id"] not in state["leases"],"lease ID reused")
        state["leases"][x["lease_id"]]=x;state["lease_active"][x["lease_id"]]=True
    elif k in ("POLICY_REVOKE","SESSION_REVOKE","LEASE_REVOKE","GRANT_REVOKE","PERMIT_REVOKE"):
        validate_fields(x,RECORD["revocation"]);d=x["object_digest"]
        group={"POLICY_REVOKE":"policy","SESSION_REVOKE":"session","LEASE_REVOKE":"lease","GRANT_REVOKE":"grant","PERMIT_REVOKE":"permit"}[k]
        if group in ("session","lease"):
            values=state[group+"s"];found=[key for key,v in values.items() if rawhash(v)==d]
            require(len(found)==1,"revoked unknown session/lease");d=found[0]
        require(d in state[group+"_active"],"revoked unknown object")
        state[group+"_active"][d]=False
    elif k=="FENCES_SET":
        validate_fields(x,RECORD["fence_state"])
        require(x["operation_id"] in requests,"unknown operation fence source")
        state["fences"][x["operation_id"]]=x
        state["phase"].setdefault(x["operation_id"],"ABSENT")
    elif k in ("GRANT_ISSUED","PERMIT_ISSUED"):
        verify_issuance_at(reg,e,x,out,state,pin,materials,requests,contexts)
        d=h2(out);op=out["operation_id"];group="grant" if k=="GRANT_ISSUED" else "permit"
        state[group+"s"][d]=out;state[group+"_active"][d]=True;state[group+"_pointer"][op]=d
    elif k in ("PREPARE","FIX_ACCEPTED","TERMINAL"):
        verify_execution_at(reg,e,x,out,state,pin,materials,requests)
        op=x["operation_id"]
        if k=="PREPARE":state["acks"][op]=out;state["phase"][op]="PREPARED"
        elif k=="FIX_ACCEPTED":
            key=(op,out["kind"])
            require(key not in state["fixes"],"second FIX acceptance")
            state["fixes"][key]=out
        else:
            require(op not in state["terminals"],"second terminal")
            state["terminals"][op]=out;state["phase"][op]=out["result_state"]
            fs=copy.deepcopy(state["fences"][op]);fs["fences"]["state_version"]=out["state_after"]
            fs["fences"]["authority_ref"]=receipt_ref(out)
            fs["fences"]["audit_ref"]=audit_ref(obj("audit_record",candidate=requests[op][out["decision"].lower()]["audit_candidate"],receipt_digest=h2(out)))
            fs["unresolved_operation_ids"]=[];state["fences"][op]=fs
    else: raise ContractError("unhandled Authority event")

def verify_issuance_at(reg,event,snap,body,state,pin,materials,requests,contexts):
    validate_fields(snap,RECORD["issuance_snapshot"]);validate(body)
    kind="GRANT" if event["event_kind"]=="GRANT_ISSUED" else "PERMIT"
    require(body["type"]==("execution_grant" if kind=="GRANT" else "local_finish_permit"),"issuance output type")
    require(snap["position"]==event["position"] and snap["issued_at"]==event["recorded_at"]==body["issued_at"]
            and snap["issuance_kind"]==kind and body["issuance_digest"]==rawhash(snap),"issuance event/body/time binding")
    require(rawhash(projection(body))==snap["issue_body_digest"],"issuance body projection differs")
    eq_fields(snap,{k:body[k] for k in ("runtime_principal","session_id","policy_digest","inventory_digest","operation_id","request_digest","source_decision_digest")},"issuance subject/input differs")
    require(snap["issuer_key_id"]==body["receipt_key_id"]==pin["receipt_key_id"],"issuance issuer key")
    subject=subject_from(state,body["policy_digest"],body["inventory_digest"],body["session_id"])
    p=subject["policy"];ctx=contexts.get(p["restoration_context_digest"])
    actions=PRODUCING_ACTIONS if kind=="GRANT" else set(RESTORE_ACTIONS)
    check_subject(state,subject,pin,materials[p["runtime_principal"]],event["recorded_at"],actions,ctx)
    require(body["runtime_principal"]==subject["enrollment"]["runtime_principal"],"issuance actual admitted principal")
    require(snap["restoration_context_digest"]==p["restoration_context_digest"],"issuance context binding")
    request=requests.get(body["operation_id"])
    require(request is not None and h2(request)==body["request_digest"] and h2(request["source_decision"])==body["source_decision_digest"],"issuance original request")
    verify_finish_inventory(p,subject["inventory"],{"request":request})
    require(body["issued_at"]<body["expires_at"]<=min(p["expires_at"],subject["session"]["expires_at"])
            and body["expires_at"]-body["issued_at"]<=30_000,"issuance bounded deadline")
    if kind=="GRANT":
        require(p["restoration_context_digest"] is None and subject["enrollment"]["context_kind"]=="INTACT_ADMITTED","grant needs ordinary source")
        op=body["operation_id"];fs=state["fences"].get(op)
        require(fs is not None and fs["fences"]==expected_fences(request) and fs["barrier_operation_id"]==op
                and fs["unresolved_operation_ids"]==[op] and state["phase"].get(op) in ("ABSENT","PREPARED"),"grant issuance fence/phase/barrier")
        target=record_by(reg,snap["fences_or_target_digest"],"fences")
        require(target==fs["fences"],"grant issuance fence digest")
        lease=state["leases"].get(body["lease_id"])
        require(lease is not None and state["lease_active"].get(body["lease_id"]) is True,"grant lease not created/active before issue")
        eq_fields(lease,{k:body[k] for k in ("lease_id","lease_generation","operation_id","request_digest","runtime_principal","session_id")},"issuance lease mapping")
        require(lease["issued_at"]<=body["issued_at"]<body["expires_at"]<=lease["expires_at"],"grant lease deadline")
        prior=state["grant_pointer"].get(op)
        require(body["grant_sequence"]==(1 if prior is None else state["grants"][prior]["grant_sequence"]+1),"grant sequence issuance")
        verify_grant_bindings(body,request,p,subject["inventory"],now=body["issued_at"],current_sequence=body["grant_sequence"],
                              authenticated_principal=p["runtime_principal"],authenticated_session=subject["session"]["session_id"])
    else:
        op=body["operation_id"];terminal=state["terminals"].get(op)
        require(terminal is not None and h2(terminal)==body["terminal_digest"],"permit issue lacks verified earlier terminal")
        target=record_by(reg,snap["fences_or_target_digest"],"finish_target")
        audit=obj("audit_record",candidate=request[terminal["decision"].lower()]["audit_candidate"],receipt_digest=h2(terminal))
        expected=finish_target(request,terminal,audit,p,pin)
        require(target==expected and body["before_checkpoint"]==target["before_checkpoint"] and body["after_checkpoint"]==target["after_checkpoint"],"permit issue target/checkpoints")
        eq_fields(body,{k:p[k] for k in ("core_installation_id","restoration_context_digest")},"permit issue subject target")
        if ctx is not None:
            require(body["expires_at"]<=ctx["expires_at"] and ctx["identity"]==request["intent"]["identity"],"restore issuance scope/deadline")
            require(ctx["source_snapshot"]["authority_tip"]["authority_sequence"]>=terminal["authority_sequence"],"restore terminal beyond fixed tail")
        else:
            s=request["intent"]["scope"]
            require(p["storage_generation_id"]==s["storage_generation_id"] and p["control_plane_generation_id"]==s["control_plane_generation_id"],"ordinary permit target generations")
        prior=state["permit_pointer"].get(op)
        require(body["permit_sequence"]==(1 if prior is None else state["permits"][prior]["permit_sequence"]+1),"permit sequence issuance")

def verify_execution_at(reg,event,snap,out,state,pin,materials,requests):
    validate_fields(snap,RECORD["execution_snapshot"])
    names={"PREPARE":"PREPARE_EXISTING","FIX_ACCEPTED":"FIX_ORIGINAL_DISPATCH","TERMINAL":"TERMINATE_ORIGINAL"}
    require(snap["action"]==names[event["event_kind"]] and snap["position"]==event["position"]
            and snap["checked_at"]==event["recorded_at"],"execution event position/action/time")
    op=snap["operation_id"];request=requests.get(op)
    require(request is not None and h2(request)==snap["request_digest"] and h2(request["source_decision"])==snap["source_decision_digest"],"execution original source")
    subject=subject_from(state,snap["policy_digest"],snap["inventory_digest"],snap["session_id"])
    check_subject(state,subject,pin,materials[snap["runtime_principal"]],snap["checked_at"],PRODUCING_ACTIONS)
    verify_finish_inventory(subject["policy"],subject["inventory"],{"request":request})
    require(subject["enrollment"]["context_kind"]=="INTACT_ADMITTED" and snap["runtime_principal"]==subject["enrollment"]["runtime_principal"],"execution actor/context")
    gd=snap["grant_digest"];g=state["grants"].get(gd)
    require(g is not None and state["grant_active"].get(gd) is True and state["grant_pointer"].get(op)==gd,"current grant differs at execution prefix")
    require(state["lease_active"].get(g["lease_id"]) is True,"execution lease revoked")
    verify_grant_bindings(g,request,subject["policy"],subject["inventory"],now=snap["checked_at"],current_sequence=g["grant_sequence"],
                          authenticated_principal=snap["runtime_principal"],authenticated_session=snap["session_id"])
    fs=state["fences"].get(op)
    require(fs is not None and snap["fences"]==fs["fences"]==expected_fences(request)
            and snap["barrier_operation_id"]==fs["barrier_operation_id"]==op
            and snap["unresolved_operation_ids"]==fs["unresolved_operation_ids"]==[op],"execution fences differ from replay")
    require(snap["remote_phase"]==state["phase"].get(op)==("ABSENT" if event["event_kind"]=="PREPARE" else "PREPARED"),"execution phase differs from replay")
    payload=record_by(reg,snap["action_input_digest"],"action_input")
    eq_fields(payload,{"operation_id":op,"request_digest":h2(request),"source_decision_digest":h2(request["source_decision"])},"action input source")
    if event["event_kind"]=="PREPARE":
        require(payload["ack_digest"] is None and payload["authorization_digest"] is None and payload["proposal_digest"] is None and payload["publication_digest"] is None,"PREPARE input references future evidence")
        verify_prepare_ack_bindings(out,request,pin)
        eq_fields(out,{"prepare_execution_grant_digest":gd,"prepare_execution_digest":rawhash(snap),
                       "prepared_at":snap["checked_at"]},"Ack execution binding")
    elif event["event_kind"]=="FIX_ACCEPTED":
        validate_fields(out,RECORD["fix_acceptance"])
        proposal=record_by(reg,payload["proposal_digest"],"dispatch_record")
        auth=record_by(reg,payload["authorization_digest"])
        ack=state["acks"].get(op)
        require(ack is not None and payload["ack_digest"]==h2(ack)==proposal["ack_digest"]
                and payload["publication_digest"] is None,"FIX original Ack/no future publication")
        require(proposal["semantic_authorization_digest"]==h2(auth) and proposal["request_digest"]==h2(request),"FIX proposal binding")
        verify_override_proposal(proposal,request,ack,auth,pin)
        require(proposal["created_at"] <= snap["checked_at"], "FIX precedes original proposal")
        require(out==record("fix_acceptance",history_version=2,proposal_digest=rawhash(proposal),execution_digest=rawhash(snap),accepted_at=snap["checked_at"],kind=proposal["kind"]),"FIX acceptance output")
        if auth["type"]=="abort_override":
            require(auth["issued_at"]<=out["accepted_at"]<auth["expires_at"],"override interval at original FIX")
    else:
        validate(out)
        auth=record_by(reg,payload["authorization_digest"])
        proposal=record_by(reg,payload["proposal_digest"],"dispatch_record")
        pub=record_by(reg,payload["publication_digest"],"dispatch_publication")
        acceptance=record_by(reg,pub["fix_acceptance_digest"],"fix_acceptance")
        require(state["fixes"].get((op,acceptance["kind"]))==acceptance and acceptance["proposal_digest"]==payload["proposal_digest"],"terminal lacks original accepted FIX")
        require(pub["proposal_digest"]==payload["proposal_digest"] and proposal["semantic_authorization_digest"]==h2(auth)
                and proposal["kind"]==acceptance["kind"]==out["authorization_kind"],"terminal original FIX authorization")
        ack=state["acks"][op]
        require(payload["ack_digest"]==h2(ack) and out["fix_execution_digest"]==acceptance["execution_digest"]
                and out["terminal_execution_digest"]==rawhash(snap) and out["decided_at"]==snap["checked_at"],"receipt execution positions")
        verify_override_proposal(proposal,request,ack,auth,pin)
        verify_terminal_bindings(out,request,ack,auth,g,pin)
        if auth["type"]=="abort_override":
            require(auth["issued_at"]<=out["decided_at"]<auth["expires_at"],"override interval at original terminal")

def completion_content(request, receipt):
    """Recompute the selected immutable content, not claims in a use proof."""
    selected = request[receipt["decision"].lower()]
    audit = obj("audit_record", candidate=selected["audit_candidate"], receipt_digest=h2(receipt))
    return {"effect_digest":h2(selected["effect"]), "result_digest":h2(selected["result"]),
            "audit_record_digest":h2(audit)}

def finish_target(request,receipt,audit,policy,pin):
    return record("finish_target",history_version=2,identity_digest=h2(request["intent"]["identity"]),authority_pin_digest=h2(pin),
        **{k:policy[k] for k in ("core_installation_id","storage_generation_id","control_plane_generation_id","restoration_context_digest")},
        operation_id=request["intent"]["operation_id"],request_digest=h2(request),source_decision_digest=h2(request["source_decision"]),
        terminal_digest=h2(receipt),before_checkpoint=before_checkpoint(request),after_checkpoint=after_checkpoint(receipt,audit))

def _verified_permit_target(authority,verified_authority,permit,request,pin):
    """Internal join from a completed Authority replay, never caller target claims.

    replay_authority validates issuance at its own strict prefix and preserves
    immutable original policy/terminal records even after later revocation.
    This only joins the supplied evidence. Source authenticity remains unverified
    at the public boundary. No current QUERY policy or permit liveness is used.
    """
    require(verified_authority["permits"].get(h2(permit))==permit,"historical permit lacks verified issuance")
    op=request["intent"]["operation_id"]
    eq_fields(permit,{"operation_id":op,"request_digest":h2(request),
        "source_decision_digest":h2(request["source_decision"])},"historical permit original request differs")
    receipt=verified_authority["terminals"].get(op)
    require(receipt is not None and h2(receipt)==permit["terminal_digest"],"historical permit original terminal differs")
    policy=verified_authority["policies"].get(permit["policy_digest"])
    require(policy is not None,"historical permit original policy absent")
    issuance=record_by(authority,permit["issuance_digest"],"issuance_snapshot")
    _,actual,output=event_at(authority,issuance["position"],"PERMIT_ISSUED")
    require(actual==issuance and output==permit,"historical permit exact issuance event differs")
    audit=obj("audit_record",candidate=request[receipt["decision"].lower()]["audit_candidate"],receipt_digest=h2(receipt))
    expected=finish_target(request,receipt,audit,policy,pin)
    require(record_by(authority,issuance["fences_or_target_digest"],"finish_target")==expected,
        "historical issuance full target differs")
    return expected

def local_subject(state,subject,pin,material,at,actions,context):
    check_subject(state,subject,pin,material,at,actions,context)
    protect=state["protection"].get(h2(subject["policy"]))
    require(protect is not None and protect["component_valid"] is True and protect["policy_active"] is True
            and protect["context_kind"]==subject["enrollment"]["context_kind"],"current protected local component/policy unavailable")
    return subject

def replay_core(core,authority,pin,material,materials,requests,contexts=None,stop=None):
    registry_structure(core,pin,material);registry_structure(authority,pin)
    contexts=contexts or {};state=empty_state()
    state.update(protection={},proposals={},publications={},completions={},observed={})
    limit=len(core["events"]) if stop is None else stop
    require(0<=limit<=len(core["events"]),"invalid local prefix")
    verified_authority=None
    authority_at=lambda stop: replay_authority(authority,pin,materials,requests,contexts,stop=stop)
    for e in core["events"][:limit]:
        verified_authority=_core_event(core,authority,e,state,pin,material,materials,requests,contexts,
                                       authority_at,verified_authority)
    return state


def _core_event(core,authority,e,state,pin,material,materials,requests,contexts,
                authority_at,verified_authority):
    """Internal transition; authority_at returns an already verified prefix fact."""
    k,t=e["event_kind"],e["recorded_at"];x=core["records"][e["input_digest"]]
    out=None if e["output_digest"] is None else core["records"][e["output_digest"]]
    if k.endswith("_OBSERVED"):
        validate_fields(x,RECORD["local_observation"])
        ae,ai,ao=event_at(authority,x["authority_position"])
        require(rawhash(ae)==x["authority_event_digest"],"observation exact event bytes")
        d=x["object_digest"];o=ao if ae["output_digest"]==d else ai
        require((h2(o) if o.get("type") in SCHEMA else rawhash(o))==d,"observation actual output/input")
        expected={"POLICY_OBSERVED":"POLICY_REGISTER","SESSION_OBSERVED":"SESSION_CREATE","INVENTORY_OBSERVED":"INVENTORY_ACCEPT","PERMIT_OBSERVED":"PERMIT_ISSUED"}
        require(k=="REVOCATION_OBSERVED" and ae["event_kind"].endswith("_REVOKE") or expected.get(k)==ae["event_kind"],"observation kind mismatch")
        token=(ae["event_kind"].split("_")[0],o.get("operation_id",o.get("session_id",d)))
        if k=="REVOCATION_OBSERVED":
            revoked=record_by(authority,o["object_digest"])
            token=(ae["event_kind"].split("_")[0],revoked.get("operation_id",revoked.get("session_id",o["object_digest"])))
        require(ae["position"]["event_sequence"]>=state["observed"].get(token,0),"observed pointer regresses")
        state["observed"][token]=ae["position"]["event_sequence"]
        if k in ("POLICY_OBSERVED","INVENTORY_OBSERVED"):
            original=authority_at(ae["position"]["event_sequence"])
            immutable_registration(state,pin,o)
            if k=="POLICY_OBSERVED":
                require(original["policies"].get(d)==o,"observation lacks original policy registration")
                state["policies"][d]=o
                state["policy_active"][d]=state["policy_active"].get(d,True) and original["policy_active"][d]
            else:
                require(original["inventories"].get(d)==o,"observation lacks original inventory registration")
                state["inventories"][d]=o
        elif k=="SESSION_OBSERVED":state["sessions"][o["session_id"]]=o;state["session_active"].setdefault(o["session_id"],True)
        elif k=="PERMIT_OBSERVED":
            state["permits"][d]=o;state["permit_active"].setdefault(d,True);state["permit_pointer"][o["operation_id"]]=d
        else:
            group=ae["event_kind"].split("_")[0].lower();rd=o["object_digest"]
            if group in ("session","lease"):
                keys=[key for key,v in state[group+"s"].items() if rawhash(v)==rd]
                require(len(keys)==1,"unknown observed revoked object");rd=keys[0]
            state[group+"_active"][rd]=False
    elif k=="LOCAL_PROTECTION":
        validate_fields(x,RECORD["local_protection"]);require(x["policy_digest"] in state["policies"],"protection before policy admission")
        state["protection"][x["policy_digest"]]=x
    elif k=="LOCAL_SESSION_REVOKE":
        validate_fields(x,RECORD["revocation"])
        keys=[key for key,v in state["sessions"].items() if rawhash(v)==x["object_digest"]]
        require(len(keys)==1,"unknown local session");state["session_active"][keys[0]]=False
    else:
        validate_fields(x,RECORD["local_snapshot"])
        require(x["position"]==e["position"] and x["checked_at"]==t,"local action time/position")
        expected={"PROPOSAL":"PROPOSE_DISPATCH","PUBLICATION":"PUBLISH_DISPATCH","APPLY":"APPLY_VERIFIED_TERMINAL"}
        require(expected.get(k)==x["action"],"local event/action mismatch")
        subject=subject_from(state,x["policy_digest"],x["inventory_digest"],x["session_id"])
        p=subject["policy"];ctx=contexts.get(p["restoration_context_digest"])
        actions={"PERSIST_COORDINATION","FIX_ORIGINAL_DISPATCH"} if k=="PROPOSAL" else {"QUERY_EXISTING","PERSIST_COORDINATION"} if k=="PUBLICATION" else {"APPLY_VERIFIED_TERMINAL","PERSIST_COORDINATION"}
        local_subject(state,subject,pin,material,t,actions,ctx)
        require(x["runtime_principal"]==p["runtime_principal"],"local runtime principal mismatch")
        request=requests.get(x["operation_id"])
        require(request is not None and h2(request)==x["request_digest"] and h2(request["source_decision"])==x["source_decision_digest"],"local original source")
        verify_finish_inventory(p,subject["inventory"],{"request":request})
        payload=record_by(core,x["action_input_digest"])
        if k=="PROPOSAL":
            require(ctx is None and subject["enrollment"]["context_kind"]=="INTACT_ADMITTED","restore cannot propose mutation/exception")
            validate_fields(out,RECORD["dispatch_record"])
            validate_fields(payload,RECORD["action_input"])
            eq_fields(payload,{"operation_id":x["operation_id"],"request_digest":h2(request),
                "source_decision_digest":h2(request["source_decision"])},"proposal action original source")
            require(out["proposal_position"]==e["position"] and out["created_at"]==t and out["request_digest"]==h2(request)
                    and out["source_decision_digest"]==h2(request["source_decision"]) and out["before_checkpoint"]==before_checkpoint(request),"proposal original position/source")
            eq_fields(out,{"runtime_principal":p["runtime_principal"],"session_id":subject["session"]["session_id"],"core_installation_id":p["core_installation_id"]},"proposal original subject")
            require(payload["authorization_digest"]==out["semantic_authorization_digest"] and payload["ack_digest"]==out["ack_digest"]
                    and payload["proposal_digest"] is None and payload["publication_digest"] is None,"proposal acyclic input")
            require(x["target_digest"]==rawhash(before_checkpoint(request)),"proposal target")
            auth=record_by(core,payload["authorization_digest"])
            ack=record_by(authority,payload["ack_digest"])
            require(ack.get("type")=="prepare_ack","proposal original Ack type")
            prepare=record_by(authority,ack["prepare_execution_digest"],"execution_snapshot")
            original=authority_at(prepare["position"]["event_sequence"])
            require(original["acks"].get(x["operation_id"])==ack,"proposal original accepted Ack")
            verify_override_proposal(out,request,ack,auth,pin)
            key=(x["operation_id"],out["kind"]);require(key not in state["proposals"],"immutable proposal replaced")
            state["proposals"][key]=out
        elif k=="PUBLICATION":
            require(ctx is None and subject["enrollment"]["context_kind"]=="INTACT_ADMITTED","publication requires ordinary current subject")
            validate_fields(out,RECORD["dispatch_publication"]);validate_fields(payload,RECORD["action_input"])
            eq_fields(payload,{"operation_id":x["operation_id"],"request_digest":h2(request),
                "source_decision_digest":h2(request["source_decision"])},"publication action original source")
            require(out["position"]==e["position"] and out["published_at"]==t and out["proposal_digest"]==payload["proposal_digest"],"publication position/input")
            acceptance=record_by(core,out["fix_acceptance_digest"],"fix_acceptance")
            require(acceptance["proposal_digest"]==out["proposal_digest"],"publication original acceptance")
            ae,_,ao=event_at(authority,record_by(authority,acceptance["execution_digest"],"execution_snapshot")["position"],"FIX_ACCEPTED")
            require(ao==acceptance,"publication lacks actual Authority acceptance")
            # Validate the original acceptance at its own prefix. Later expiry,
            # revocation or renewed credentials cannot rewrite this fact.
            original=authority_at(ae["position"]["event_sequence"])
            require(original["fixes"].get((x["operation_id"],acceptance["kind"]))==acceptance,
                    "publication lacks verified original FIX")
            proposal=state["proposals"].get((x["operation_id"],acceptance["kind"]))
            require(proposal is not None and rawhash(proposal)==out["proposal_digest"],"publication lacks original local proposal")
            require(payload["authorization_digest"]==proposal["semantic_authorization_digest"] and payload["ack_digest"]==proposal["ack_digest"]
                    and payload["publication_digest"] is None and x["target_digest"]==rawhash(before_checkpoint(request)),"publication target/original input")
            key=(x["operation_id"],acceptance["kind"]);require(key not in state["publications"],"publication replaced")
            state["publications"][key]=out
        else:
            validate_fields(payload,RECORD["use_input"]);validate_fields(out,RECORD["completion_record"])
            permit=state["permits"].get(payload["permit_digest"])
            require(permit is not None and state["permit_active"].get(h2(permit)) is True
                    and state["permit_pointer"].get(x["operation_id"])==h2(permit),"current observed permit pointer/revocation")
            eq_fields(permit,{"policy_digest":x["policy_digest"],"inventory_digest":x["inventory_digest"],"session_id":x["session_id"],"runtime_principal":x["runtime_principal"]},"permit original local use subject")
            require(permit["issued_at"]<=t and t+1_000<permit["expires_at"],"first use conservative deadline")
            target=record_by(core,x["target_digest"],"finish_target")
            # Independent APPLY reception needs verified original issuance,
            # not an arbitrary self-consistent object in authority.records.
            # This dependency is one-way: Authority replay never calls Core.
            if verified_authority is None:
                verified_authority=replay_authority(authority,pin,materials,requests,contexts)
            expected_target=_verified_permit_target(authority,verified_authority,permit,request,pin)
            require(target==expected_target,"historical APPLY full target differs")
            require(payload["target_digest"]==x["target_digest"] and payload["issuance_digest"]==permit["issuance_digest"]
                    and payload["terminal_digest"]==permit["terminal_digest"],"use issuance/target source")
            require(target["before_checkpoint"]==permit["before_checkpoint"] and target["after_checkpoint"]==permit["after_checkpoint"]
                    and target["core_installation_id"]==p["core_installation_id"] and target["storage_generation_id"]==p["storage_generation_id"]
                    and target["control_plane_generation_id"]==p["control_plane_generation_id"] and target["restoration_context_digest"]==p["restoration_context_digest"],"local target generations")
            content=completion_content(request,verified_authority["terminals"][x["operation_id"]])
            eq_fields(payload,content,"historical APPLY selected terminal content")
            require(out==record("completion_record",history_version=2,position=e["position"],completed_at=t,permit_digest=h2(permit),
                issuance_digest=permit["issuance_digest"],local_use_digest=rawhash(x),operation_id=x["operation_id"],request_digest=h2(request),
                source_decision_digest=h2(request["source_decision"]),terminal_digest=permit["terminal_digest"],target_digest=x["target_digest"],
                before_checkpoint=permit["before_checkpoint"],after_checkpoint=permit["after_checkpoint"],
                **content),"completion exact use binding")
            require(x["operation_id"] not in state["completions"],"second local consume")
            state["completions"][x["operation_id"]]=out
    return verified_authority

def verify_causality(authority,cores):
    registries=[authority]+list(cores)
    nodes={};producers={};records={}
    for reg in registries:
        records.update(reg["records"])
        for e in reg["events"]:
            n=(e["position"]["registry_digest"],e["position"]["event_sequence"])
            require(n not in nodes,"duplicate registry event identity")
            nodes[n]=set()
            if n[1]>1:nodes[n].add((n[0],n[1]-1))
            if e["output_digest"] is not None:
                d=e["output_digest"]
                require(d not in producers,"same output has multiple producers")
                producers[d]=n
    def references(value,seen):
        result=set()
        if isinstance(value,dict):
            if set(value)==set(STRUCT["position"]):result.add((value["registry_digest"],value["event_sequence"]))
            for v in value.values():result.update(references(v,seen))
        elif isinstance(value,list):
            for v in value:result.update(references(v,seen))
        elif isinstance(value,str) and value not in seen:
            seen.add(value)
            if value in producers:result.add(producers[value])
            elif value in records:result.update(references(records[value],seen))
        return result
    for reg in registries:
        for e in reg["events"]:
            n=(e["position"]["registry_digest"],e["position"]["event_sequence"])
            inp=reg["records"][e["input_digest"]]
            deps=references(inp,set())
            if e["output_digest"] is not None:
                deps.update(references(reg["records"][e["output_digest"]],set()))
            # Own position is allocation metadata, not an observation of own event.
            if inp.get("position")==e["position"]:deps.discard(n)
            nodes[n].update(deps)
    # Same complete graph relation with linear topological traversal. Repeated
    # scanning of all unresolved nodes made a long original event sequence
    # quadratic even though each edge and provider was already explicit.
    from collections import deque
    successors={node:[] for node in nodes}
    degree={node:len(deps) for node,deps in nodes.items()}
    for node,deps in nodes.items():
        for dependency in deps:
            require(dependency in nodes,"event causal cycle or missing cross-domain producer")
            successors[dependency].append(node)
    ready=deque(node for node,count in degree.items() if count==0)
    completed=0
    while ready:
        node=ready.popleft();completed+=1
        for successor in successors[node]:
            degree[successor]-=1
            if degree[successor]==0:ready.append(successor)
    require(completed==len(nodes),"event causal cycle or missing cross-domain producer")
    return completed
