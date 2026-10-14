"""Scoped V2 canonical bytes and exact schemas.

C2 is the accepted restricted format, not RFC 8785 JCS. V1 remains in
r1_protocol and is never reencoded or accepted through this module.
Derived from the accepted 8913fd31 reference tables; no evidence dependency,
fixture, synthetic signature or I/O exists in the runtime module.
"""
from __future__ import annotations
import hashlib
import ipaddress
import json
import re
from uuid import UUID
from urllib.parse import urlsplit

MAX = 9_007_199_254_740_991


H_PREFIX = b"QINGYU-R1-SCOPED-V2/"

S_PREFIX = b"QINGYU-R1-SCOPED-SIGN-V2/"

ROLES = tuple(sorted("AUTHORITY_RECEIPT CORE_AUDIT AUDIT_CANDIDATE GENESIS_ATTEMPT GENESIS_ATTEMPT_EVENT GENESIS_ATTEMPT_EVIDENCE OPERATION_INVENTORY REQUEST SOURCE_REQUEST SIGNED_ORIGIN SOURCE_DEPLOYMENT SOURCE_FENCING TERMINAL_AUTHORIZATION PREPARE_ACK STAGED_EVIDENCE EXECUTION_GRANT RECOVERY_POLICY RECOVERY_INVENTORY AUTHORITY_PIN SOURCE_ADMISSION SESSION_BINDING POLICY_REGISTRATION GRANT_POINTER OPERATION_LEASE EXECUTION_SNAPSHOT DISPATCH_RECORD DEPLOYMENT_ADMISSION RECOVERY_COMPONENT INITIALIZER_COMPONENT INITIALIZER_ADMISSION RESTORE_SOURCE_STATE RECEIPT_PUBLIC_KEY ROOT_PUBLIC_KEY TLS_SPKI_DER OPENING_AUTHORIZATION OPENING_PREPARE RESTORATION_CONTEXT ARCHIVE_MANIFEST".split()))

ACTIONS = tuple(sorted("QUERY_EXISTING PREPARE_EXISTING FIX_ORIGINAL_DISPATCH TERMINATE_ORIGINAL APPLY_VERIFIED_TERMINAL PERSIST_COORDINATION".split()))

RESTORE_ACTIONS = ["APPLY_VERIFIED_TERMINAL", "PERSIST_COORDINATION", "QUERY_EXISTING"]

PRODUCING_ACTIONS = {"PREPARE_EXISTING", "FIX_ORIGINAL_DISPATCH", "TERMINATE_ORIGINAL"}

class ContractError(ValueError):
    pass

def require(condition, reason):
    if not condition:
        raise ContractError(reason)

def check_json(value, depth=0):
    require(depth <= 32, "JSON nesting limit")
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        require(-MAX <= value <= MAX, "integer outside safe53")
        return
    if type(value) is str:
        require("\x00" not in value and all(not 0xD800 <= ord(c) <= 0xDFFF for c in value),
                "non-scalar or NUL string")
        return
    if type(value) is list:
        require(len(value) <= 4096, "container element limit")
        for child in value:
            check_json(child, depth + 1)
        return
    if type(value) is dict:
        require(len(value) <= 4096, "container element limit")
        for key, child in value.items():
            require(type(key) is str, "non-string key")
            check_json(key, depth + 1)
            check_json(child, depth + 1)
        return
    raise ContractError("unsupported JSON type (including float)")

def c2(value):
    check_json(value)
    wire = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    require(len(wire) <= 1_048_576, "C2 object exceeds 1 MiB")
    return wire

def decode(raw):
    require(type(raw) is bytes and len(raw) <= 1_048_576, "wire must be bytes <= 1 MiB")

    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ContractError("non-JSON number")))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ContractError("invalid UTF8/JSON") from exc
    require(c2(value) == raw, "noncanonical C2 wire")
    return value

def sha(raw):
    require(type(raw) is bytes, "SHA256 input is exact bytes")
    return hashlib.sha256(raw).hexdigest()

def fields(spec):
    return dict(part.split(":", 1) for part in spec.split())

SCHEMA = {}

STRUCT = {
    "value": fields("payload:json capability:=core_governance requested_decision:=COMMIT|ABORT"),
    "effect_entry": fields("mutation_id:text256 value:#value"),
    "inventory_entry": fields("operation_id:uuid request_digest:hash source_decision_digest:hash local_commit_id:uuid"),
    "archive_entry": fields("role:role index:u byte_length:u sha256:hash"),
    "source_entry": fields("operation_id:uuid wire_version:=1|2 request_raw_sha256:hash authorization_raw_sha256:?hash terminal_ref:?@authority_ref audit_ref:?@audit_ref state:=INTENT|PREPARED|COMMITTED|ABORTED"),
}

def register(name, spec):
    SCHEMA[name] = fields(spec)

register("identity", "qingyu_identity_id:uuid continuity_id:uuid genesis_operation_id:uuid")

register("authority_ref", "wire_version:=1|2 authority_generation:p authority_sequence:u receipt_hash:hash")

register("audit_ref", "wire_version:=1|2 audit_sequence:u audit_hash:hash")

register("authority_pin", "authority_domain_id:uuid authority_instance_id:uuid authority_generation:p receipt_public_key:key receipt_key_id:hash api_version:p https_origin:text server_spki_sha256:hash operator_root_key_id:hash")

register("requested_scope", "trust_domain_id:uuid authority_domain_id:uuid authority_instance_id:uuid authority_generation:p actor_identity:text256 owner_version:p continuity_epoch:p expected_state_version:u storage_generation_id:uuid control_plane_generation_id:uuid lease_id:uuid lease_generation:p caller_runtime_id:uuid session_id:uuid capability:=core_governance expected_authority_ref:@authority_ref expected_audit_ref:@audit_ref")

register("business_intent", "operation_id:uuid mutation_id:text256 local_commit_id:uuid identity:@identity scope:@requested_scope payload:json requested_decision:=COMMIT|ABORT created_at:u reason:text")

register("business_payload", "value:json")

register("source_decision", "authorization_id:uuid authorization_kind:=CALLER_INTENT intent_digest:hash identity_digest:hash scope_digest:hash authorization_principal:text256 requested_decision:=COMMIT|ABORT created_at:u")

register("business_effect", "entries:[]#effect_entry")

register("mutation_result", "mutation_id:text256 result_state:=COMMITTED|ABORTED state_version:u effect_digest:hash value:?#value")

register("audit_content", "operation_id:uuid mutation_id:text256 identity_digest:hash scope_digest:hash intent_digest:hash source_decision_digest:hash payload_digest:hash decision:=COMMIT|ABORT result_state:=COMMITTED|ABORTED state_version:u effect_digest:hash result_digest:hash audit_sequence:p previous_audit_ref:@audit_ref created_at:u")

register("branch_bundle", "decision:=COMMIT|ABORT effect:@business_effect result:@mutation_result audit_candidate:@audit_content")

register("mutation_request", "intent:@business_intent source_decision:@source_decision commit:@branch_bundle abort:@branch_bundle")

register("prepare_ack", "authority_domain_id:uuid authority_instance_id:uuid authority_generation:p operation_id:uuid identity_digest:hash request_digest:hash source_decision_digest:hash commit_candidate_digest:hash abort_candidate_digest:hash prepare_execution_grant_digest:hash authority_predecessor:@authority_ref prepared_at:u receipt_key_id:hash receipt_signature:sig")

register("staged_evidence", "operation_id:uuid local_commit_id:uuid request_digest:hash ack_digest:hash commit_candidate_digest:hash abort_candidate_digest:hash")

register("terminal_authorization", "authorization_id:uuid operation_id:uuid local_commit_id:uuid request_digest:hash source_decision_digest:hash ack_digest:hash decision:=COMMIT|ABORT candidate_digest:hash staging_evidence_digest:hash no_local_business_commit:bool created_at:u")

register("terminal_receipt", "authority_domain_id:uuid authority_instance_id:uuid authority_generation:p operation_id:uuid operation_type:=MUTATION identity_digest:hash request_digest:hash source_decision_digest:hash ack_digest:hash authorization_kind:=NORMAL|OPERATOR_ABORT semantic_authorization_digest:hash execution_grant_digest:hash decision:=COMMIT|ABORT result_state:=COMMITTED|ABORTED candidate_digest:hash effect_digest:hash result_digest:hash audit_candidate_digest:hash state_before:u state_after:u audit_sequence:p authority_sequence:p previous_authority_ref:@authority_ref decided_at:u receipt_key_id:hash receipt_signature:sig")

register("audit_record", "candidate:@audit_content|opening_audit_content receipt_digest:hash")

register("recovery_policy", "policy_id:uuid deployment_admission_digest:hash authority_domain_id:uuid authority_instance_id:uuid authority_generation:p continuity_id:uuid qingyu_identity_id:uuid genesis_operation_id:uuid core_installation_id:uuid storage_generation_id:uuid control_plane_generation_id:uuid runtime_principal:text component_artifact_digest:hash trust_config_digest:hash restoration_context_digest:?hash capabilities:[]action allowed_operation_type:=MUTATION issued_at:u expires_at:u operator_root_key_id:hash root_signature:sig")

register("recovery_inventory", "inventory_id:uuid policy_digest:hash core_installation_id:uuid runtime_principal:text session_id:uuid entries:[]#inventory_entry")

register("execution_grant", "grant_id:uuid grant_sequence:p policy_digest:hash inventory_digest:hash operation_id:uuid request_digest:hash source_decision_digest:hash authority_domain_id:uuid authority_instance_id:uuid authority_generation:p continuity_id:uuid qingyu_identity_id:uuid genesis_operation_id:uuid owner_identity:text owner_version:p continuity_epoch:p expected_state_version:u storage_generation_id:uuid control_plane_generation_id:uuid runtime_principal:text session_id:uuid lease_id:uuid lease_generation:p issued_at:u expires_at:u receipt_key_id:hash receipt_signature:sig")

register("local_checkpoint", "state_version:u audit_ref:@audit_ref authority_ref:@authority_ref")

register("local_finish_permit", "permit_id:uuid permit_sequence:p policy_digest:hash inventory_digest:hash restoration_context_digest:?hash core_installation_id:uuid runtime_principal:text session_id:uuid operation_id:uuid request_digest:hash source_decision_digest:hash terminal_digest:hash before_checkpoint:@local_checkpoint after_checkpoint:@local_checkpoint issued_at:u expires_at:u receipt_key_id:hash receipt_signature:sig")

register("abort_override", "override_id:uuid operation_id:uuid request_digest:hash source_decision_digest:hash supersedes_authorization_id:uuid previous_authorization_digest:hash identity_digest:hash scope_digest:hash authorized_decision:=ABORT abort_candidate_digest:hash reason:text issued_at:u expires_at:u operator_root_key_id:hash root_signature:sig")

register("archive_manifest", "entries:[]#archive_entry")

register("source_operation_inventory", "authority_domain_id:uuid authority_generation:p entries:[]#source_entry")

register("source_snapshot", "source_kind:=V1_OFFLINE_UPGRADE|V2_GENERATION_RESTORE identity:@identity source_authority_domain_id:uuid source_authority_instance_id:uuid source_authority_generation:p authority_tip:@authority_ref audit_tip:@audit_ref state_version:u owner_identity:text256 owner_version:p continuity_epoch:p storage_generation_id:uuid control_plane_generation_id:uuid signed_origin_digest:hash history_archive_digest:hash operation_inventory_digest:hash source_deployment_digest:hash source_fencing_evidence_digest:hash captured_at:u")

register("opening_authorization", "opening_id:uuid opening_kind:=NEW_GENESIS|V1_TO_V2|GENERATION_RESTORE identity:@identity source_snapshot:?@source_snapshot target_authority_domain_id:uuid target_authority_instance_id:uuid target_authority_generation:p target_storage_generation_id:uuid target_control_plane_generation_id:uuid core_installation_id:uuid initializer_principal:text256 initializer_artifact_digest:hash initial_or_current_owner_identity:text256 owner_version:p continuity_epoch:p state_version:u signed_origin_digest:hash deployment_admission_digest:hash trust_config_digest:hash receipt_key_id:hash tls_origin:text tls_spki_sha256:hash operator_root_key_id:hash issued_at:u expires_at:u reason:text root_signature:sig")

for kind in ("authority_origin", "audit_origin"):
    register(kind, "identity_digest:hash opening_authorization_digest:hash signed_origin_digest:hash trust_config_digest:hash")

register("opening_audit_content", "opening_id:uuid opening_kind:=NEW_GENESIS|V1_TO_V2|GENERATION_RESTORE identity_digest:hash opening_authorization_digest:hash source_snapshot_digest:?hash state_version:u owner_identity:text256 owner_version:p continuity_epoch:p audit_sequence:p previous_audit_ref:@audit_ref")

register("opening_prepare", "opening_id:uuid opening_authorization_digest:hash audit_candidate_digest:hash genesis_attempt_digest:?hash target_authority_domain_id:uuid target_authority_instance_id:uuid target_authority_generation:p prepared_at:u receipt_key_id:hash receipt_signature:sig")

register("opening_receipt", "opening_id:uuid opening_kind:=NEW_GENESIS|V1_TO_V2|GENERATION_RESTORE identity_digest:hash opening_authorization_digest:hash opening_prepare_digest:hash source_snapshot_digest:?hash authority_domain_id:uuid authority_instance_id:uuid authority_generation:p authority_sequence:p previous_authority_ref:@authority_ref audit_candidate_digest:hash state_version:u owner_identity:text256 owner_version:p continuity_epoch:p decided_at:u receipt_key_id:hash receipt_signature:sig")

register("genesis_attempt", "attempt_id:uuid opening_id:uuid opening_authorization_digest:hash identity_digest:hash attempt_number:p previous_attempt_digest:?hash created_at:u")

register("genesis_attempt_event", "event_id:uuid attempt_id:uuid previous_event_digest:?hash state:=PREPARED|GENESIS_ATTEMPT_ABORTED|SUCCEEDED reason_code:text evidence_digest:hash created_at:u")

register("restoration_context", "context_id:uuid identity:@identity source_snapshot:@source_snapshot target_core_installation_id:uuid target_storage_generation_id:uuid target_control_plane_generation_id:uuid target_authority_pin_digest:hash restore_start_checkpoint:@local_checkpoint restore_source_state_digest:hash allowed_actions:[]restore_action issued_at:u expires_at:u reason:text operator_root_key_id:hash root_signature:sig")

RECORD = {
    "initializer_binding": fields("opening_id:uuid runtime_principal:text256 core_installation_id:uuid initializer_artifact_digest:hash deployment_admission_digest:hash trust_config_digest:hash purpose:=LIFECYCLE_OPENING registration_state:=ACTIVE|REVOKED admitted_at:u expires_at:u"),
    "source_admission": fields("operation_id:uuid intent_digest:hash source_decision_digest:hash identity_digest:hash scope_digest:hash actor_identity:text256 caller_runtime_id:uuid session_id:uuid lease_id:uuid lease_generation:p admitted_at:u session_issued_at:u session_expires_at:u lease_issued_at:u lease_expires_at:u normal_business_admission:bool core_installation_id:uuid deployment_admission_digest:hash component_artifact_digest:hash trust_config_digest:hash"),
    "enrollment": fields("runtime_principal:text core_installation_id:uuid policy_digest:hash context_kind:=INTACT_ADMITTED|MANUAL_RESTORE_ADMITTED|UNKNOWN|CONFLICT restoration_context_digest:?hash purpose:=MUTATION_RECOVERY|LIFECYCLE_OPENING identity_digest:hash authority_domain_id:uuid authority_instance_id:uuid authority_generation:p storage_generation_id:uuid control_plane_generation_id:uuid deployment_admission_digest:hash component_artifact_digest:hash trust_config_digest:hash"),
    "session_binding": fields("session_id:uuid enrollment:#enrollment issued_at:u expires_at:u"),
    "policy_registration": fields("event_sequence:p effective_at:u policy_id:uuid policy_digest:hash status:=ACTIVE|REVOKED"),
    "grant_pointer": fields("event_sequence:p effective_at:u operation_id:uuid grant_id:uuid grant_digest:hash grant_sequence:p status:=ACTIVE|REVOKED"),
    "operation_lease": fields("lease_id:uuid lease_generation:p operation_id:uuid request_digest:hash runtime_principal:text session_id:uuid issued_at:u expires_at:u"),
    "lease_event": fields("event_sequence:p effective_at:u lease_id:uuid lease_generation:p status:=ACTIVE|REVOKED"),
    "fences": fields("authority_domain_id:uuid authority_instance_id:uuid authority_generation:p identity:@identity owner_identity:text256 owner_version:p continuity_epoch:p state_version:u storage_generation_id:uuid control_plane_generation_id:uuid authority_ref:@authority_ref audit_ref:@audit_ref"),
    "execution_snapshot": fields("operation_id:uuid checked_at:u action:action runtime_principal:text session_id:uuid policy_digest:hash inventory_digest:hash grant_digest:hash fences:#fences barrier_operation_id:uuid unresolved_operation_ids:[]uuid remote_phase:=ABSENT|PREPARED"),
    "dispatch_record": fields("kind:=NORMAL|OPERATOR_ABORT operation_id:uuid local_commit_id:uuid request_digest:hash source_decision_digest:hash ack_digest:hash staging_evidence_digest:hash semantic_authorization_digest:hash runtime_principal:text session_id:uuid core_installation_id:uuid created_at:u no_local_business_commit:bool before_checkpoint:@local_checkpoint"),
    "genesis_failure": fields("attempt_digest:hash opening_prepare_digest:hash checked_at:u authority_sequence:u audit_sequence:u terminal_observation:=ABSENT|UNKNOWN proposal_observation:=NONE_COMMITTABLE|UNKNOWN transaction_outcome:=ROLLED_BACK|QUALIFICATION_REJECTED|UNKNOWN cause_code:text observed_by:text256"),
    "backup_state": fields("identity:@identity checkpoint:@local_checkpoint governed_results:[]@mutation_result receipt_wires:[]wirehex audit_wires:[]wirehex captured_at:u"),
}

STRUCT.update(RECORD)

def match(value, spec):
    if spec.startswith("?"):
        if value is None:
            return
        return match(value, spec[1:])
    if spec.startswith("[]"):
        require(type(value) is list, "expected list")
        for entry in value:
            match(entry, spec[2:])
        return
    if spec.startswith("@"):
        require(type(value) is dict and value.get("type") in spec[1:].split("|"), "wrong nested type")
        return validate(value)
    if spec.startswith("#"):
        return validate_fields(value, STRUCT[spec[1:]])
    if spec.startswith("="):
        alternatives = [int(v) if v.isdigit() else v for v in spec[1:].split("|")]
        require(any(type(value) is type(v) and value == v for v in alternatives), "unknown enum/literal")
        return
    if spec == "json":
        check_json(value)
    elif spec in ("u", "p"):
        require(type(value) is int and (1 if spec == "p" else 0) <= value <= MAX, "invalid safe53 counter")
    elif spec == "bool":
        require(type(value) is bool, "expected boolean")
    elif spec in ("hash", "key", "sig"):
        require(type(value) is str and re.fullmatch("[0-9a-f]{%d}" % (128 if spec == "sig" else 64), value) is not None, "invalid hex")
    elif spec == "uuid":
        try:
            valid = type(value) is str and str(UUID(value)) == value
        except (ValueError, TypeError, AttributeError):
            valid = False
        require(valid, "noncanonical UUID")
    elif spec == "wirehex":
        require(type(value) is str and len(value) <= 2_097_152 and len(value) % 2 == 0
                and re.fullmatch("[0-9a-f]*", value) is not None, "invalid archived wire hex")
    elif spec in ("text", "text256"):
        require(type(value) is str and 0 < len(value) <= (256 if spec == "text256" else 4096), "invalid text")
        check_json(value)
    elif spec in ("role", "action", "restore_action"):
        choices = ROLES if spec == "role" else ACTIONS if spec == "action" else ("APPLY_VERIFIED_TERMINAL", "VERIFY_HISTORY")
        require(value in choices, "unknown registered role/action")
    else:
        raise ContractError("unregistered specification " + spec)

def validate_fields(value, definition):
    require(type(value) is dict and set(value) == set(definition), "missing/extra fields")
    for field, spec in definition.items():
        match(value[field], spec)

def validate(value):
    check_json(value)
    c2(value)  # Enforce total wire size as well as structural resource limits.
    require(type(value) is dict and value.get("type") in SCHEMA, "unknown protocol type/domain")
    name = value["type"]
    require(type(value.get("version")) is int and value["version"] == 2, "wrong protocol version")
    validate_fields(value, {"type": "=" + name, "version": "=2", **SCHEMA[name]})
    if "issued_at" in value:
        require(value["issued_at"] < value["expires_at"], "empty authorization interval")
    if name == "authority_pin":
        require(value["receipt_key_id"] == sha(bytes.fromhex(value["receipt_public_key"])), "receipt key identity mismatch")
        canonical_https_origin(value["https_origin"])
    if name == "business_effect":
        require(len(value["entries"]) <= 1, "effect is empty or one governed record")
    if name == "recovery_policy":
        require(value["capabilities"] == sorted(set(value["capabilities"])), "capability ordering/duplicates")
        if value["restoration_context_digest"] is not None:
            require(set(value["capabilities"]) <= set(RESTORE_ACTIONS), "restore policy cannot create terminals")
    if name == "restoration_context":
        require(value["allowed_actions"] == ["APPLY_VERIFIED_TERMINAL", "VERIFY_HISTORY"], "restore action set is fixed")
    if name in ("recovery_inventory", "source_operation_inventory"):
        ids = [e["operation_id"] for e in value["entries"]]
        require(ids == sorted(set(ids)), "inventory ordering/duplicates")
    if name == "archive_manifest":
        keys = [(e["role"], e["index"]) for e in value["entries"]]
        require(keys == sorted(set(keys)), "archive ordering/duplicates")
    return value

def obj(name, **values):
    return validate({"type": name, "version": 2, **values})

def h2(value):
    validate(value)
    return sha(H_PREFIX + value["type"].encode("ascii") + b"\x00" + c2(value))

def s2(value):
    validate(value)
    signatures = [key for key in ("root_signature", "receipt_signature") if key in value]
    require(len(signatures) == 1, "not an exactly signed type")
    unsigned = {key: val for key, val in value.items() if key != signatures[0]}
    return S_PREFIX + value["type"].encode("ascii") + b"\x00" + c2(unsigned)

def canonical_https_origin(value):
    # Same origin syntax as the retained V1 protocol; no network lookup.
    try:
        origin = urlsplit(value)
        host, port = origin.hostname, origin.port
    except (ValueError, TypeError) as exc:
        raise ContractError("invalid HTTPS origin") from exc
    require(origin.scheme == "https" and host and not origin.username and not origin.password
            and not origin.path and not origin.query and not origin.fragment
            and not origin.netloc.endswith(":") and value == "https://" + origin.netloc,
            "invalid HTTPS origin")
    if ":" in host:
        require("%" not in host, "scoped IPv6 origin")
        try:
            require(str(ipaddress.IPv6Address(host)) == host, "noncanonical IPv6")
        except ValueError as exc:
            raise ContractError("invalid IPv6") from exc
        expected = "[" + host + "]"
    else:
        require(all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in host.split(".")), "invalid DNS label")
        expected = host
    if port is not None:
        require(1 <= port <= 65535, "invalid port")
        expected += ":" + str(port)
    require(origin.netloc == expected, "noncanonical HTTPS authority")

def record(name, **values):
    validate_fields(values, RECORD[name])
    check_json(values)
    return values

def eq_fields(actual, expected, reason):
    require(all(k in actual and actual[k] == value for k, value in expected.items()), reason)

for _name in ("execution_grant", "prepare_ack", "terminal_receipt", "local_finish_permit"):
    SCHEMA[_name]["contract_revision"] = "=2"

SCHEMA["execution_grant"]["issuance_digest"] = "hash"

SCHEMA["local_finish_permit"]["issuance_digest"] = "hash"

SCHEMA["prepare_ack"]["prepare_execution_digest"] = "hash"

SCHEMA["terminal_receipt"].update(fix_execution_digest="hash", terminal_execution_digest="hash")

STRUCT["position"] = fields("history_version:=2 registry_digest:hash event_sequence:u")

RECORD["registry_header"] = fields("history_version:=2 registry_id:uuid registry_kind:=AUTHORITY_QUALIFICATION|CORE_LOCAL authority_domain_id:uuid authority_instance_id:uuid authority_generation:p core_installation_id:?uuid storage_generation_id:?uuid control_plane_generation_id:?uuid provenance_digest:hash")

RECORD["registry_event"] = fields("history_version:=2 position:#position recorded_at:u event_kind:text input_digest:hash output_digest:?hash")

RECORD["session_binding"]["history_version"] = "=2"

RECORD["operation_lease"]["history_version"] = "=2"

RECORD["execution_snapshot"].update(history_version="=2", position="#position", request_digest="hash", source_decision_digest="hash", action_input_digest="hash")

RECORD["issuance_snapshot"] = fields("history_version:=2 position:#position issued_at:u issuance_kind:=GRANT|PERMIT issuer_key_id:hash runtime_principal:text session_id:uuid policy_digest:hash inventory_digest:hash restoration_context_digest:?hash operation_id:uuid request_digest:hash source_decision_digest:hash issue_body_digest:hash fences_or_target_digest:hash")

RECORD["finish_target"] = fields("history_version:=2 identity_digest:hash authority_pin_digest:hash core_installation_id:uuid storage_generation_id:uuid control_plane_generation_id:uuid restoration_context_digest:?hash operation_id:uuid request_digest:hash source_decision_digest:hash terminal_digest:hash before_checkpoint:@local_checkpoint after_checkpoint:@local_checkpoint")

RECORD["fix_acceptance"] = fields("history_version:=2 proposal_digest:hash execution_digest:hash accepted_at:u kind:=NORMAL|OPERATOR_ABORT")

RECORD["dispatch_record"].update(history_version="=2", proposal_position="#position")

RECORD["dispatch_publication"] = fields("history_version:=2 position:#position published_at:u proposal_digest:hash fix_acceptance_digest:hash")

RECORD["local_snapshot"] = fields("history_version:=2 position:#position checked_at:u action:=PROPOSE_DISPATCH|PUBLISH_DISPATCH|APPLY_VERIFIED_TERMINAL runtime_principal:text session_id:uuid policy_digest:hash inventory_digest:hash operation_id:uuid request_digest:hash source_decision_digest:hash target_digest:hash action_input_digest:hash")

RECORD["completion_record"] = fields("history_version:=2 position:#position completed_at:u permit_digest:hash issuance_digest:hash local_use_digest:hash operation_id:uuid request_digest:hash source_decision_digest:hash terminal_digest:hash target_digest:hash before_checkpoint:@local_checkpoint after_checkpoint:@local_checkpoint effect_digest:hash result_digest:hash audit_record_digest:hash")

RECORD["revocation"] = fields("history_version:=2 object_digest:hash")

RECORD["fence_state"] = fields("history_version:=2 operation_id:uuid fences:#fences barrier_operation_id:uuid unresolved_operation_ids:[]uuid")

RECORD["local_observation"] = fields("history_version:=2 authority_position:#position authority_event_digest:hash object_digest:hash")

RECORD["local_protection"] = fields("history_version:=2 policy_digest:hash component_valid:bool policy_active:bool context_kind:=INTACT_ADMITTED|MANUAL_RESTORE_ADMITTED")

RECORD["action_input"] = fields("history_version:=2 operation_id:uuid request_digest:hash source_decision_digest:hash ack_digest:?hash authorization_digest:?hash proposal_digest:?hash publication_digest:?hash")

RECORD["use_input"] = fields("history_version:=2 permit_digest:hash issuance_digest:hash target_digest:hash terminal_digest:hash effect_digest:hash result_digest:hash audit_record_digest:hash")

for _obsolete in ("policy_registration", "grant_pointer", "lease_event"):
    RECORD.pop(_obsolete)
    STRUCT.pop(_obsolete)

STRUCT.update(RECORD)

A_KINDS = ("POLICY_REGISTER","POLICY_REVOKE","SESSION_CREATE","SESSION_REVOKE","INVENTORY_ACCEPT","LEASE_CREATE","LEASE_REVOKE","FENCES_SET","GRANT_ISSUED","GRANT_REVOKE","PREPARE","FIX_ACCEPTED","TERMINAL","PERMIT_ISSUED","PERMIT_REVOKE")

C_KINDS = ("POLICY_OBSERVED","SESSION_OBSERVED","INVENTORY_OBSERVED","PERMIT_OBSERVED","REVOCATION_OBSERVED","LOCAL_PROTECTION","LOCAL_SESSION_REVOKE","PROPOSAL","PUBLICATION","APPLY")

ROLES = tuple(sorted(set(ROLES) | {"AUTHORITY_REGISTRY","CORE_REGISTRY","REGISTRY_HEADER","REGISTRY_EVENT","REGISTRY_INPUT","REGISTRY_OUTPUT","ISSUANCE_SNAPSHOT","FIX_ACCEPTANCE","DISPATCH_PUBLICATION","LOCAL_USE","COMPLETION_RECORD","FINISH_PERMIT","FINISH_TARGET"}))

ROLES = tuple(sorted(set(ROLES)|{"SOURCE_PROFILE","DERIVED_AUDIT"}))

ROLES = tuple(r for r in ROLES if r not in ("POLICY_REGISTRATION","GRANT_POINTER"))
