"""Pure verification of supplied source archives, backups and restore scope.

No archive extraction or source discovery occurs here. Opaque deployment and
fencing evidence is content-bound, not promoted to real-world admission. Fixed
trust and the chain/backup boundaries are separately supplied by the caller.
"""
from __future__ import annotations

from dataclasses import dataclass
from contextvars import ContextVar

from .r1_validation_codec import (
    RECORD, SCHEMA, c2, decode, eq_fields, h2, obj, require, sha, validate, validate_fields,
)
from .r1_validation_crypto import FixedTrust, verify_signed
from . import _r1_validation_semantics as semantics


@dataclass(frozen=True, slots=True)
class ArchiveMember:
    role: str
    index: int
    raw: bytes


@dataclass(frozen=True, slots=True)
class SourceDeploymentObservation:
    """Separately supplied source inspector facts; their origin is unverified."""
    source_deployment_digest: str
    identity_wire: bytes
    authority_pin_wire: bytes
    core_installation_id: str
    storage_generation_id: str
    control_plane_generation_id: str
    owner_identity: str
    owner_version: int
    continuity_epoch: int
    state_version: int
    authority_tip_wire: bytes
    audit_tip_wire: bytes
    deployment_admission_digest: str


@dataclass(frozen=True, slots=True)
class SourceFencingObservation:
    """Supplied inspector facts bound to the original opaque fencing artifact."""
    source_fencing_evidence_digest: str
    source_deployment_digest: str
    authority_tip_wire: bytes
    audit_tip_wire: bytes
    observed_at: int
    observed_by: str
    authority_writer_state: str
    core_writer_state: str
    pending_operation_ids: tuple[str, ...] = ()
    uncommitted_proposal_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class OpeningEvidence:
    authorization_wire: bytes
    prepare_wire: bytes
    receipt_wire: bytes
    audit_wire: bytes
    initializer_binding_wire: bytes
    initializer_component_bytes: bytes
    attempt_wires: tuple[bytes, ...] = ()
    attempt_event_wires: tuple[bytes, ...] = ()
    attempt_evidence_wires: tuple[bytes, ...] = ()
    previous_source: SourceEvidence | None = None
    previous_trust: FixedTrust | None = None


@dataclass(frozen=True, slots=True)
class SourceEvidence:
    snapshot_wire: bytes
    manifest_wire: bytes
    inventory_wire: bytes
    members: tuple[ArchiveMember, ...]
    history: object
    chain_boundary: object
    opening: OpeningEvidence | None
    observed_origin: object | None = None
    legacy: object | None = None
    source_deployment_observation: SourceDeploymentObservation | None = None
    source_fencing_observation: SourceFencingObservation | None = None
    restoration_evidence: tuple[RestoreEvidence, ...] = ()


@dataclass(frozen=True, slots=True)
class RestoreEvidence:
    context_wire: bytes
    backup_wire: bytes
    source: SourceEvidence
    expected_backup_checkpoint_wire: bytes


@dataclass(frozen=True, slots=True)
class SourceValidation:
    snapshot: dict
    authority: dict
    cores: tuple[dict, ...]
    opening_checkpoint: dict
    canonical_checkpoints: tuple[dict, ...]
    receipt_wires: tuple[bytes, ...]
    audit_wires: tuple[bytes, ...]
    results: tuple[dict, ...]
    operation_ids: tuple[str, ...]
    actual_core_count: int
    profile: str


@dataclass(frozen=True, slots=True)
class RestoreValidation:
    context: dict
    source_snapshot: dict
    source_authority: dict
    source_cores: tuple[dict, ...]
    backup_checkpoint: dict
    source_checkpoint: dict
    allowed_operations: tuple[str, ...]
    opening_checkpoint: dict


def _typed(raw, kind):
    value = decode(raw)
    validate(value)
    require(value["type"] == kind, "wrong source object type: " + kind)
    return value


class _ArchiveRows(dict):
    def __init__(self):
        super().__init__()
        self.used = set()


def _archive(item):
    manifest = _typed(item.manifest_wire, "archive_manifest")
    require(type(item.members) is tuple and 0 < len(item.members) <= 4096, "archive member count")
    entries, rows = [], _ArchiveRows()
    total = 0
    for member in item.members:
        require(type(member) is ArchiveMember and type(member.raw) is bytes, "explicit original archive member bytes required")
        require(len(member.raw) <= 1_048_576, "archive member exceeds resource limit")
        total += len(member.raw)
        require(total <= 64 * 1_048_576, "archive aggregate exceeds 64 MiB resource limit")
        key = (member.role, member.index)
        require(key not in rows, "duplicate archive role/index")
        rows[key] = member.raw
        entries.append({"role": member.role, "index": member.index, "byte_length": len(member.raw), "sha256": sha(member.raw)})
    require(list(rows) == sorted(rows), "archive members must use declared role/index order")
    require(manifest == obj("archive_manifest", entries=entries), "archive member length/digest/list mismatch")
    return manifest, rows


def _one(rows, role):
    values = [raw for (name, _), raw in rows.items() if name == role]
    require(len(values) == 1, "exact singleton archive role required: " + role)
    rows.used.update(key for key in rows if key[0] == role)
    return values[0]


def _contains(rows, role, raw):
    require(any(name == role and value == raw for (name, _), value in rows.items()), "missing exact archive member: " + role)
    rows.used.update(key for key, value in rows.items() if key[0] == role and value == raw)


def _registry_closure(registry, opening_checkpoint):
    records = registry["records"]
    pending = [event["input_digest"] for event in registry["events"]]
    pending.extend(event["output_digest"] for event in registry["events"] if event["output_digest"] is not None)
    seen = set()
    def references(value):
        if type(value) is str and value in records:
            pending.append(value)
        elif type(value) is dict:
            for child in value.values():
                references(child)
        elif type(value) is list:
            for child in value:
                references(child)
    while pending:
        key = pending.pop()
        if key not in seen:
            seen.add(key); references(records[key])
    # An unchanged opening checkpoint can be saved locally before any APPLY;
    # its original value is independently established by the signed opening.
    preimages = {c2(records[key]) for key in seen} | {c2(opening_checkpoint)}
    require(all(c2(value) in preimages for value in records.values()), "source registry hides unreferenced original records")


def _bind_optional_original_members(rows, registries):
    """Allow named original objects already verified through the registry DAG.

    Redundant role-specific archive members are legitimate evidence. Their
    bytes must equal an actual validated preimage, never a new hidden operation.
    """
    typed_roles = {"RECOVERY_POLICY": "recovery_policy", "RECOVERY_INVENTORY": "recovery_inventory",
                   "EXECUTION_GRANT": "execution_grant", "PREPARE_ACK": "prepare_ack", "FINISH_PERMIT": "local_finish_permit",
                   "TERMINAL_AUTHORIZATION": ("terminal_authorization", "abort_override"), "AUTHORITY_RECEIPT": "terminal_receipt"}
    record_roles = {"SESSION_BINDING": "session_binding", "EXECUTION_SNAPSHOT": "execution_snapshot", "DISPATCH_RECORD": "dispatch_record",
                    "ISSUANCE_SNAPSHOT": "issuance_snapshot", "FIX_ACCEPTANCE": "fix_acceptance", "DISPATCH_PUBLICATION": "dispatch_publication",
                    "LOCAL_USE": "local_snapshot", "COMPLETION_RECORD": "completion_record", "FINISH_TARGET": "finish_target"}
    known = {}
    for registry in registries:
        for value in registry["records"].values():
            wire = c2(value)
            for role, kind in typed_roles.items():
                if value.get("type") in ((kind,) if type(kind) is str else kind):
                    known.setdefault(role, set()).add(wire)
            for role, kind in record_roles.items():
                if set(value) == set(RECORD[kind]):
                    validate_fields(value, RECORD[kind])
                    known.setdefault(role, set()).add(wire)
            known.setdefault("REGISTRY_INPUT", set()).add(wire)
    for key, wire in rows.items():
        if wire in known.get(key[0], ()):
            rows.used.add(key)


def _checkpoint(receipt, audit):
    return semantics.after_checkpoint(receipt, audit)


def _attempts(opening, auth, ack, receipt, rows, trust):
    require(type(opening.attempt_wires) is tuple and type(opening.attempt_event_wires) is tuple
            and type(opening.attempt_evidence_wires) is tuple, "attempt input tuples required")
    attempts = [_typed(raw, "genesis_attempt") for raw in opening.attempt_wires]
    events = [_typed(raw, "genesis_attempt_event") for raw in opening.attempt_event_wires]
    require(0 < len(attempts) <= 4096 and len(events) == 2 * len(attempts), "complete genesis attempt transitions required")
    evidence = {sha(raw): raw for raw in opening.attempt_evidence_wires}
    evidence[sha(opening.prepare_wire)] = opening.prepare_wire
    evidence[sha(opening.receipt_wire)] = opening.receipt_wire
    used_evidence = set()
    previous_attempt, previous_end, ids, event_ids = None, auth["issued_at"], set(), set()
    for index, attempt in enumerate(attempts):
        _contains(rows, "GENESIS_ATTEMPT", opening.attempt_wires[index])
        require(attempt["attempt_id"] not in ids, "genesis attempt ID conflict")
        ids.add(attempt["attempt_id"])
        eq_fields(attempt, {"opening_id": auth["opening_id"], "opening_authorization_digest": h2(auth),
                            "identity_digest": h2(auth["identity"]), "attempt_number": index + 1,
                            "previous_attempt_digest": previous_attempt}, "genesis attempt original plan/predecessor")
        require(previous_end <= attempt["created_at"] < auth["expires_at"], "genesis attempt chronology")
        prepared, final = events[2*index:2*index+2]
        for offset, event in enumerate((prepared, final)):
            _contains(rows, "GENESIS_ATTEMPT_EVENT", opening.attempt_event_wires[2*index+offset])
            require(event["event_id"] not in event_ids, "genesis event ID conflict")
            event_ids.add(event["event_id"])
            require(event["evidence_digest"] in evidence, "missing original genesis attempt evidence")
            used_evidence.add(event["evidence_digest"])
        prep_raw = evidence[prepared["evidence_digest"]]
        prep = _typed(prep_raw, "opening_prepare")
        verify_signed(prep_raw, trust)
        _contains(rows, "OPENING_PREPARE", prep_raw)
        eq_fields(prep, {"genesis_attempt_digest": h2(attempt), "opening_id": auth["opening_id"],
                         "opening_authorization_digest": h2(auth), "audit_candidate_digest": ack["audit_candidate_digest"],
                         **{key: ack[key] for key in ("target_authority_domain_id", "target_authority_instance_id", "target_authority_generation", "receipt_key_id")}},
                  "genesis prepare original plan")
        eq_fields(prepared, {"attempt_id": attempt["attempt_id"], "previous_event_digest": None, "state": "PREPARED",
                            "created_at": prep["prepared_at"]}, "genesis PREPARED event")
        eq_fields(final, {"attempt_id": attempt["attempt_id"], "previous_event_digest": h2(prepared)}, "genesis final event predecessor")
        require(attempt["created_at"] <= prep["prepared_at"] <= final["created_at"] < auth["expires_at"], "genesis historical event interval")
        if index == len(attempts)-1:
            require(final["state"] == "SUCCEEDED" and prep == ack and final["evidence_digest"] == sha(opening.receipt_wire)
                    and final["created_at"] == receipt["decided_at"], "last genesis attempt must establish original receipt1")
        else:
            failure_raw = evidence[final["evidence_digest"]]
            failure = decode(failure_raw)
            validate_fields(failure, RECORD["genesis_failure"])
            _contains(rows, "GENESIS_ATTEMPT_EVIDENCE", failure_raw)
            eq_fields(failure, {"attempt_digest": h2(attempt), "opening_prepare_digest": h2(prep), "authority_sequence": 0,
                                "audit_sequence": 0, "terminal_observation": "ABSENT", "proposal_observation": "NONE_COMMITTABLE"},
                      "failed genesis attempt cannot consume canonical sequence")
            require(failure["transaction_outcome"] in ("ROLLED_BACK", "QUALIFICATION_REJECTED"), "unknown genesis outcome")
            eq_fields(final, {"state": "GENESIS_ATTEMPT_ABORTED", "created_at": failure["checked_at"], "reason_code": failure["cause_code"]},
                      "genesis failed event original evidence")
        previous_attempt, previous_end = h2(attempt), final["created_at"]
    require(ack["genesis_attempt_digest"] == h2(attempts[-1]), "opening receipt must use successful attempt")
    require(set(evidence) == used_evidence, "genesis attempt contains unbound extra evidence")


def _opening(item, trust, deployments, rows, validate_history, depth):
    opening = item.opening
    require(type(opening) is OpeningEvidence, "complete original opening evidence required")
    auth = _typed(opening.authorization_wire, "opening_authorization")
    ack = _typed(opening.prepare_wire, "opening_prepare")
    receipt = _typed(opening.receipt_wire, "opening_receipt")
    audit = _typed(opening.audit_wire, "audit_record")
    for wire in (opening.authorization_wire, opening.prepare_wire, opening.receipt_wire):
        verify_signed(wire, trust)
    pin = trust.pin
    for role, wire in (("OPENING_AUTHORIZATION", opening.authorization_wire), ("OPENING_PREPARE", opening.prepare_wire),
                       ("AUTHORITY_RECEIPT", opening.receipt_wire), ("CORE_AUDIT", opening.audit_wire),
                       ("INITIALIZER_ADMISSION", opening.initializer_binding_wire), ("INITIALIZER_COMPONENT", opening.initializer_component_bytes)):
        _contains(rows, role, wire)
    materials = [value for value in deployments if value.core_installation_id == auth["core_installation_id"]
                 and value.storage_generation_id == auth["target_storage_generation_id"]
                 and value.control_plane_generation_id == auth["target_control_plane_generation_id"]]
    require(len(materials) == 1, "opening original deployment is missing or ambiguous")
    material = materials[0]
    semantics.validate_pin_material(pin, material)
    eq_fields(auth, {"target_authority_domain_id": pin["authority_domain_id"], "target_authority_instance_id": pin["authority_instance_id"],
                    "target_authority_generation": pin["authority_generation"], "trust_config_digest": h2(pin),
                    "receipt_key_id": pin["receipt_key_id"], "tls_origin": pin["https_origin"], "tls_spki_sha256": pin["server_spki_sha256"],
                    "operator_root_key_id": pin["operator_root_key_id"], "deployment_admission_digest": sha(material.deployment_bytes),
                    "initializer_artifact_digest": sha(opening.initializer_component_bytes)}, "opening fixed trust/deployment binding")
    binding = decode(opening.initializer_binding_wire)
    validate_fields(binding, RECORD["initializer_binding"])
    eq_fields(binding, {"opening_id": auth["opening_id"], "runtime_principal": auth["initializer_principal"],
                       "core_installation_id": auth["core_installation_id"], "initializer_artifact_digest": auth["initializer_artifact_digest"],
                       "deployment_admission_digest": auth["deployment_admission_digest"], "trust_config_digest": h2(pin),
                       "purpose": "LIFECYCLE_OPENING", "registration_state": "ACTIVE"}, "opening original initializer binding")
    require(auth["issued_at"] <= ack["prepared_at"] <= receipt["decided_at"] < auth["expires_at"]
            and binding["admitted_at"] <= ack["prepared_at"] <= receipt["decided_at"] < binding["expires_at"], "opening historical qualification interval")
    candidate = audit["candidate"]
    require(candidate["type"] == "opening_audit_content", "opening Audit candidate type")
    previous_source = None
    if auth["opening_kind"] == "NEW_GENESIS":
        require(auth["source_snapshot"] is None and opening.previous_source is None and opening.previous_trust is None, "genesis cannot carry a prior source")
        require(pin["authority_generation"] == 1 and auth["opening_id"] == auth["identity"]["genesis_operation_id"]
                and auth["owner_version"] == auth["continuity_epoch"] == 1 and auth["state_version"] == 0, "genesis initial identity/owner/state")
        origins = {"identity_digest": h2(auth["identity"]), "opening_authorization_digest": h2(auth),
                   "signed_origin_digest": auth["signed_origin_digest"], "trust_config_digest": h2(pin)}
        prior_a = obj("authority_ref", wire_version=2, authority_generation=1, authority_sequence=0, receipt_hash=h2(obj("authority_origin", **origins)))
        prior_c = obj("audit_ref", wire_version=2, audit_sequence=0, audit_hash=h2(obj("audit_origin", **origins)))
        sequence = 1
        _attempts(opening, auth, ack, receipt, rows, trust)
    else:
        require(type(opening.previous_trust) is FixedTrust and type(opening.previous_source) is SourceEvidence, "opening requires complete prior source and independent fixed trust")
        previous = verify_source_evidence(opening.previous_source, opening.previous_trust, deployments, validate_history, _depth=depth+1)
        previous_source = previous.snapshot
        require(previous.profile == "ALIGNED_OPENING" and auth["source_snapshot"] == previous_source, "opening source must be complete and actually aligned")
        require(previous_source["captured_at"] <= auth["issued_at"], "opening precedes original source capture")
        old_pin = opening.previous_trust.pin
        require(opening.previous_trust.root_public_key == trust.root_public_key, "opening cannot rotate fixed Root public bytes")
        for key in ("receipt_public_key", "receipt_key_id", "api_version", "https_origin", "server_spki_sha256", "operator_root_key_id", "authority_domain_id"):
            require(old_pin[key] == pin[key], "opening cannot rotate fixed keys/domain/TLS/API")
        eq_fields(auth, {"identity": previous_source["identity"], "initial_or_current_owner_identity": previous_source["owner_identity"],
                         **{key: previous_source[key] for key in ("owner_version", "continuity_epoch", "state_version", "signed_origin_digest")}},
                  "opening changes immutable identity or source state")
        prior_a, prior_c = previous_source["authority_tip"], previous_source["audit_tip"]
        if auth["opening_kind"] == "V1_TO_V2":
            require(previous_source["source_kind"] == "V1_OFFLINE_UPGRADE" and prior_a["wire_version"] == prior_c["wire_version"] == 1
                    and pin["authority_instance_id"] == old_pin["authority_instance_id"] and pin["authority_generation"] == old_pin["authority_generation"], "V1 opening version/generation/instance")
            eq_fields(auth, {"target_storage_generation_id": previous_source["storage_generation_id"],
                             "target_control_plane_generation_id": previous_source["control_plane_generation_id"]}, "V1 bridge preserves storage generations")
            sequence = prior_a["authority_sequence"] + 1
        else:
            require(auth["opening_kind"] == "GENERATION_RESTORE" and previous_source["source_kind"] == "V2_GENERATION_RESTORE"
                    and pin["authority_generation"] == old_pin["authority_generation"] + 1, "generation opening must advance exactly one generation")
            sequence = 1
        require(not opening.attempt_wires and not opening.attempt_event_wires and not opening.attempt_evidence_wires
                and ack["genesis_attempt_digest"] is None, "non-genesis opening cannot carry genesis attempts")
    common = {"opening_id": auth["opening_id"], "opening_kind": auth["opening_kind"], "identity_digest": h2(auth["identity"]),
              "opening_authorization_digest": h2(auth), "source_snapshot_digest": None if previous_source is None else h2(previous_source),
              "state_version": auth["state_version"], "owner_identity": auth["initial_or_current_owner_identity"],
              "owner_version": auth["owner_version"], "continuity_epoch": auth["continuity_epoch"]}
    require(candidate == obj("opening_audit_content", **common, audit_sequence=prior_c["audit_sequence"]+1, previous_audit_ref=prior_c), "opening independent Audit predecessor/content")
    eq_fields(ack, {"opening_id": auth["opening_id"], "opening_authorization_digest": h2(auth), "audit_candidate_digest": h2(candidate),
                   "receipt_key_id": pin["receipt_key_id"], **{key: auth[key] for key in ("target_authority_domain_id", "target_authority_instance_id", "target_authority_generation")}}, "opening PREPARE original linkage")
    eq_fields(receipt, {**common, "opening_prepare_digest": h2(ack), "audit_candidate_digest": h2(candidate),
                       "authority_sequence": sequence, "previous_authority_ref": prior_a,
                       **{key: pin[key] for key in ("authority_domain_id", "authority_instance_id", "authority_generation", "receipt_key_id")}}, "opening receipt original linkage")
    require(audit == obj("audit_record", candidate=candidate, receipt_digest=h2(receipt)), "opening final Audit receipt binding")
    return auth, receipt, audit, _checkpoint(receipt, audit)


def _lineage_graph(item):
    """Bound the complete non-wire proof graph, including callback recursion."""
    count = 0
    def visit(source, path):
        nonlocal count
        require(type(source) is SourceEvidence and id(source) not in path and len(path) <= 8, "source lineage cycle/depth limit")
        count += 1
        require(count <= 64, "source lineage aggregate node limit")
        path = (*path, id(source))
        require(type(source.restoration_evidence) is tuple and len(source.restoration_evidence) <= 32, "source restoration proof resource limit")
        if source.opening is not None and source.opening.previous_source is not None:
            visit(source.opening.previous_source, path)
        for proof in source.restoration_evidence:
            require(type(proof) is RestoreEvidence, "source original restoration proof required")
            visit(proof.source, path)
    visit(item, ())


_SOURCE_VERIFICATION = ContextVar("r1_source_verification", default=None)


def verify_source_evidence(item, trust, deployments, validate_history, *, _depth=0):
    """Keep recursion/work bounds across public callback reentry as well."""
    state = _SOURCE_VERIFICATION.get()
    token = None
    if state is None:
        state = {"path": [], "calls": 0}
        token = _SOURCE_VERIFICATION.set(state)
    try:
        require(id(item) not in state["path"] and len(state["path"]) <= 8, "source lineage cycle/depth limit")
        state["calls"] += 1
        require(state["calls"] <= 1024, "source validation work budget exceeded")
        state["path"].append(id(item))
        try:
            return _verify_source_evidence(item, trust, deployments, validate_history, _depth=_depth)
        finally:
            state["path"].pop()
    finally:
        if token is not None:
            _SOURCE_VERIFICATION.reset(token)


def _verify_source_evidence(item, trust, deployments, validate_history, *, _depth=0):
    """Validate actual supplied archive relationships, never source authenticity."""
    require(_depth <= 8, "source lineage depth exceeds eight generations")
    require(type(item) is SourceEvidence and type(trust) is FixedTrust, "explicit source evidence/fixed trust required")
    _lineage_graph(item)
    snapshot = _typed(item.snapshot_wire, "source_snapshot")
    inventory = _typed(item.inventory_wire, "source_operation_inventory")
    manifest, rows = _archive(item)
    pin = trust.pin
    eq_fields(snapshot, {"source_authority_domain_id": pin["authority_domain_id"], "source_authority_instance_id": pin["authority_instance_id"],
                         "source_authority_generation": pin["authority_generation"], "history_archive_digest": h2(manifest),
                         "operation_inventory_digest": h2(inventory)}, "source snapshot fixed pin/archive/inventory mismatch")
    eq_fields(inventory, {"authority_domain_id": pin["authority_domain_id"], "authority_generation": pin["authority_generation"]}, "source inventory fixed domain")
    require(_one(rows, "OPERATION_INVENTORY") == item.inventory_wire and _one(rows, "AUTHORITY_PIN") == trust.pin_wire,
            "source inventory/pin original bytes differ")
    require(_one(rows, "ROOT_PUBLIC_KEY") == trust.root_public_key and _one(rows, "RECEIPT_PUBLIC_KEY") == bytes.fromhex(pin["receipt_public_key"]), "archive keys cannot replace independent fixed trust")
    require(snapshot["source_deployment_digest"] == sha(_one(rows, "SOURCE_DEPLOYMENT"))
            and snapshot["source_fencing_evidence_digest"] == sha(_one(rows, "SOURCE_FENCING")), "source deployment/fencing original bytes")
    observed = item.source_deployment_observation
    require(type(observed) is SourceDeploymentObservation, "separately supplied source deployment observations required")
    require(observed.source_deployment_digest == snapshot["source_deployment_digest"] and observed.identity_wire == c2(snapshot["identity"])
            and observed.authority_pin_wire == trust.pin_wire and observed.authority_tip_wire == c2(snapshot["authority_tip"])
            and observed.audit_tip_wire == c2(snapshot["audit_tip"]), "source deployment observations raw identity/pin/checkpoint mismatch")
    for key in ("storage_generation_id", "control_plane_generation_id", "owner_identity", "owner_version", "continuity_epoch", "state_version"):
        require(type(getattr(observed, key)) is type(snapshot[key]) and getattr(observed, key) == snapshot[key], "source deployment observed scope/state mismatch: " + key)
    for key in ("source_deployment_digest", "core_installation_id", "deployment_admission_digest"):
        require(type(getattr(observed, key)) is str, "source deployment observation scalar type: " + key)
    for key in ("identity_wire", "authority_pin_wire", "authority_tip_wire", "audit_tip_wire"):
        require(type(getattr(observed, key)) is bytes, "source deployment observation requires original bytes: " + key)
    fencing = item.source_fencing_observation
    require(type(fencing) is SourceFencingObservation, "separately supplied source fencing observations required")
    require(type(fencing.source_fencing_evidence_digest) is str and type(fencing.source_deployment_digest) is str
            and fencing.source_fencing_evidence_digest == snapshot["source_fencing_evidence_digest"]
            and fencing.source_deployment_digest == snapshot["source_deployment_digest"], "source fencing observation original artifact binding")
    require(type(fencing.authority_tip_wire) is bytes and type(fencing.audit_tip_wire) is bytes
            and fencing.authority_tip_wire == c2(snapshot["authority_tip"]) and fencing.audit_tip_wire == c2(snapshot["audit_tip"]),
            "source fencing observed checkpoint differs")
    require(type(fencing.observed_at) is int and 0 <= fencing.observed_at <= snapshot["captured_at"]
            and type(fencing.observed_by) is str and 0 < len(fencing.observed_by) <= 256, "source fencing observation chronology/observer")
    require(type(fencing.authority_writer_state) is str and type(fencing.core_writer_state) is str
            and fencing.authority_writer_state == fencing.core_writer_state == "ISOLATED"
            and type(fencing.pending_operation_ids) is tuple and type(fencing.uncommitted_proposal_ids) is tuple
            and not fencing.pending_operation_ids and not fencing.uncommitted_proposal_ids, "source lacks observed isolation/quiescence")
    source_materials = [material for material in deployments if material.core_installation_id == observed.core_installation_id
                        and material.storage_generation_id == observed.storage_generation_id
                        and material.control_plane_generation_id == observed.control_plane_generation_id]
    require(len(source_materials) == 1 and observed.deployment_admission_digest == sha(source_materials[0].deployment_bytes),
            "source deployment observation differs from actual original admission bytes")
    from ._r1_validation_legacy import verify_origin
    require(item.observed_origin is not None, "source original provisioning observations required")
    origin = verify_origin(_one(rows, "SIGNED_ORIGIN"), trust, item.observed_origin)
    # The legacy helper verifies the original envelopes; the digest domain is
    # retained verbatim and is never substituted with H2 or plain file SHA.
    origin_digest = sha(b"QINGYU-CP-R1-PROVISIONING-ORIGIN\0" + _one(rows, "SIGNED_ORIGIN"))
    require(snapshot["signed_origin_digest"] == origin_digest, "source original signed provisioning origin digest")
    if snapshot["source_kind"] == "V1_OFFLINE_UPGRADE":
        from ._r1_validation_legacy import verify_legacy_source
        return verify_legacy_source(item, trust, deployments, origin)
    require(snapshot["source_kind"] == "V2_GENERATION_RESTORE", "unsupported source version/kind")
    require(item.legacy is None, "V2 source cannot contain unrelated V1 evidence")
    auth, opening_receipt, opening_audit, opening_checkpoint = _opening(item, trust, deployments, rows, validate_history, _depth)
    restored = []
    for proof in item.restoration_evidence:
        verified = verify_restore_evidence(proof, trust, deployments, validate_history, _depth=_depth+1)
        restored.append(verified)
        _contains(rows, "RESTORATION_CONTEXT", proof.context_wire)
        _contains(rows, "RESTORE_SOURCE_STATE", proof.backup_wire)
        _contains(rows, "ARCHIVE_MANIFEST", proof.source.manifest_wire)
    require(len({h2(proof.context) for proof in restored}) == len(restored), "duplicate source restoration context")
    current_restore = [proof for proof in restored if proof.context["target_core_installation_id"] == observed.core_installation_id
                       and proof.context["target_storage_generation_id"] == observed.storage_generation_id
                       and proof.context["target_control_plane_generation_id"] == observed.control_plane_generation_id]
    require(len(current_restore) <= 1, "ambiguous current source restoration context")
    if not current_restore:
        require(auth["core_installation_id"] == observed.core_installation_id, "source opening installation differs from source deployment observation")
    require(auth["signed_origin_digest"] == origin_digest and auth["identity"] == snapshot["identity"], "source opening origin/identity mismatch")
    boundary = item.chain_boundary
    from ._r1_validation_chain import decode_boundary
    decode_boundary(boundary)
    require(boundary is not None and boundary.identity_wire == c2(snapshot["identity"])
            and boundary.start_checkpoint_wire == c2(opening_checkpoint), "external source anchor differs from verified opening")
    eq_fields(snapshot, {"owner_identity": boundary.owner_identity, "owner_version": boundary.owner_version,
                        "continuity_epoch": boundary.continuity_epoch}, "source external governance scope differs")
    if not current_restore:
        eq_fields(snapshot, {"storage_generation_id": boundary.storage_generation_id,
                            "control_plane_generation_id": boundary.control_plane_generation_id}, "source external physical scope differs")
    else:
        require(current_restore[0].context["identity"] == snapshot["identity"], "restored source changes identity")
    require(auth["initial_or_current_owner_identity"] == boundary.owner_identity and auth["owner_version"] == boundary.owner_version
            and auth["continuity_epoch"] == boundary.continuity_epoch
            and auth["target_storage_generation_id"] == boundary.storage_generation_id
            and auth["target_control_plane_generation_id"] == boundary.control_plane_generation_id, "source opening does not establish external scope")
    history = item.history
    require(history is not None, "source original history required")
    require(not history.context_wires or set(history.context_wires) == {proof.context_wire for proof in item.restoration_evidence},
            "source restore contexts require complete original proofs")
    if history.request_wires:
        validate_history("TERMINAL_HISTORY", history, trust, deployments, chain_boundary=boundary, restore_evidence=item.restoration_evidence)
    else:
        # A verified opening is already a complete source even before its first
        # mutation. Still replay every supplied qualification/observation event.
        require(type(history.request_wires) is tuple and history.source_admission_wires == (), "opening-only source cannot hide admission requests")
        require(boundary.expected_end_checkpoint_wire == c2(opening_checkpoint), "opening-only external tail differs")
        empty_authority = decode(history.authority_history)
        material_map = {material.runtime_principal: material for material in deployments}
        require(len(material_map) == len(deployments), "duplicate deployment runtime")
        def inspect(value):
            if type(value) is dict:
                if "root_signature" in value or "receipt_signature" in value:
                    verify_signed(c2(value), trust)
                if "restoration_context_digest" in value:
                    require(value["restoration_context_digest"] is None, "opening-only source has restore context")
                for child in value.values():
                    inspect(child)
            elif type(value) is list:
                for child in value:
                    inspect(child)
        inspect(empty_authority)
        semantics.replay_authority(empty_authority, pin, material_map, {})
        for core in history.core_histories:
            require(core.runtime_principal in material_map, "opening-only Core deployment missing")
            empty_core = decode(core.raw); inspect(empty_core)
            semantics.replay_core(empty_core, empty_authority, pin, material_map[core.runtime_principal], material_map, {})
    authority = decode(history.authority_history)
    cores = tuple(decode(core.raw) for core in history.core_histories)
    requests = {request["intent"]["operation_id"]: request for request in map(decode, history.request_wires)}
    _contains(rows, "AUTHORITY_REGISTRY", history.authority_history)
    for core in history.core_histories:
        _contains(rows, "CORE_REGISTRY", core.raw)
    for wire in history.request_wires:
        _contains(rows, "REQUEST", wire)
    for wire in history.source_admission_wires:
        _contains(rows, "SOURCE_ADMISSION", wire)
    for material in deployments:
        # Only deployments actually represented by source policies/opening are
        # required; target restore deployment may also be supplied to the API.
        used = material.core_installation_id == auth["core_installation_id"] or any(
            value.get("type") == "recovery_policy" and value["runtime_principal"] == material.runtime_principal
            for value in authority["records"].values())
        if used:
            for role, raw in (("DEPLOYMENT_ADMISSION", material.deployment_bytes), ("RECOVERY_COMPONENT", material.component_bytes), ("TLS_SPKI_DER", material.tls_spki_der)):
                _contains(rows, role, raw)
    for registry in (authority, *cores):
        _registry_closure(registry, opening_checkpoint)
        _contains(rows, "REGISTRY_HEADER", c2(registry["header"]))
        for event in registry["events"]:
            _contains(rows, "REGISTRY_EVENT", c2(event))
            _contains(rows, "REGISTRY_INPUT", c2(registry["records"][event["input_digest"]]))
            if event["output_digest"] is not None:
                _contains(rows, "REGISTRY_OUTPUT", c2(registry["records"][event["output_digest"]]))
            if event["event_kind"] == "PERMIT_ISSUED":
                issuance = registry["records"][event["input_digest"]]
                permit = registry["records"][event["output_digest"]]
                _contains(rows, "ISSUANCE_SNAPSHOT", c2(issuance)); _contains(rows, "FINISH_PERMIT", c2(permit))
                _contains(rows, "FINISH_TARGET", c2(registry["records"][issuance["fences_or_target_digest"]]))
            if event["event_kind"] == "APPLY":
                _contains(rows, "LOCAL_USE", c2(registry["records"][event["input_digest"]]))
    terminals = [authority["records"][event["output_digest"]] for event in authority["events"] if event["event_kind"] == "TERMINAL"]
    require(len(terminals) == len(requests), "source must contain each original terminal")
    restored_prefix_ids = set()
    if current_restore:
        original_ids = [current_restore[0].source_authority["records"][event["output_digest"]]["operation_id"]
                        for event in current_restore[0].source_authority["events"] if event["event_kind"] == "TERMINAL"]
        require([receipt["operation_id"] for receipt in terminals] == original_ids, "restored source cannot add canonical operations beyond its approved history")
        restored_prefix_ids = set(original_ids) - set(current_restore[0].allowed_operations)
    checkpoints, receipt_wires, audit_wires, results, ids, derived_audits = [opening_checkpoint], [item.opening.receipt_wire], [item.opening.audit_wire], [], [], []
    expected_inventory = [{"operation_id": auth["opening_id"], "wire_version": 2, "request_raw_sha256": sha(item.opening.authorization_wire),
                           "authorization_raw_sha256": sha(item.opening.authorization_wire), "terminal_ref": semantics.receipt_ref(opening_receipt),
                           "audit_ref": semantics.audit_ref(opening_audit), "state": "COMMITTED"}]
    completion_by_op = {}
    archived_actual_operations = {core["records"][event["output_digest"]]["operation_id"]
                                  for core in cores for event in core["events"] if event["event_kind"] == "APPLY"}
    selected_cores = [core for core in cores if core["header"]["core_installation_id"] == observed.core_installation_id
                      and core["header"]["storage_generation_id"] == observed.storage_generation_id
                      and core["header"]["control_plane_generation_id"] == observed.control_plane_generation_id]
    require(len(selected_cores) == 1, "source current Core original registry missing or ambiguous")
    for core in selected_cores:
        for event in core["events"]:
            if event["event_kind"] == "APPLY":
                completion = core["records"][event["output_digest"]]
                require(completion["operation_id"] not in completion_by_op, "source operation has multiple actual Core completions")
                completion_by_op[completion["operation_id"]] = completion
    gap, actual_count, last_completion = False, 0, None
    for receipt in terminals:
        operation = receipt["operation_id"]
        request = requests[operation]
        selected = request[receipt["decision"].lower()]
        audit = obj("audit_record", candidate=selected["audit_candidate"], receipt_digest=h2(receipt))
        authorization = authority["records"].get(receipt["semantic_authorization_digest"])
        require(authorization is not None, "source lacks original terminal authorization")
        _contains(rows, "AUTHORITY_RECEIPT", c2(receipt)); _contains(rows, "TERMINAL_AUTHORIZATION", c2(authorization))
        ack = authority["records"][receipt["ack_digest"]]
        _contains(rows, "PREPARE_ACK", c2(ack))
        stage = obj("staged_evidence", operation_id=operation, local_commit_id=request["intent"]["local_commit_id"],
                    request_digest=h2(request), ack_digest=h2(ack), commit_candidate_digest=h2(request["commit"]), abort_candidate_digest=h2(request["abort"]))
        _contains(rows, "STAGED_EVIDENCE", c2(stage))
        for digest in (ack["prepare_execution_grant_digest"], receipt["execution_grant_digest"]):
            _contains(rows, "EXECUTION_GRANT", c2(authority["records"][digest]))
        fix_execution = authority["records"][receipt["fix_execution_digest"]]
        _contains(rows, "EXECUTION_GRANT", c2(authority["records"][fix_execution["grant_digest"]]))
        for decision in ("commit", "abort"):
            _contains(rows, "AUDIT_CANDIDATE", c2(request[decision]["audit_candidate"]))
        completed = operation in completion_by_op or operation in restored_prefix_ids
        if completed:
            require(not gap, "source Core completion skips an earlier canonical operation")
            actual_count += 1
            if operation in completion_by_op:
                last_completion = completion_by_op[operation]
                require(last_completion["completed_at"] < snapshot["captured_at"], "source capture precedes actual Core completion")
                _contains(rows, "COMPLETION_RECORD", c2(last_completion))
            _contains(rows, "CORE_AUDIT", c2(audit))
        else:
            gap = True
            _contains(rows, "DERIVED_AUDIT", c2(audit))
            actual_member = any(role == "CORE_AUDIT" and wire == c2(audit) for (role, _), wire in rows.items())
            require(not actual_member or operation in archived_actual_operations, "derived Audit falsely labeled as source Core saved Audit")
            if actual_member:
                # A prior installation's actual Audit can accompany a restored
                # target that still lags. Inventory/profile describe the target.
                _contains(rows, "CORE_AUDIT", c2(audit))
        expected_inventory.append({"operation_id": operation, "wire_version": 2, "request_raw_sha256": sha(c2(request)),
                                   "authorization_raw_sha256": sha(c2(authorization)), "terminal_ref": semantics.receipt_ref(receipt),
                                   "audit_ref": semantics.audit_ref(audit) if completed else None, "state": receipt["result_state"]})
        checkpoints.append(_checkpoint(receipt, audit)); receipt_wires.append(c2(receipt)); audit_wires.append(c2(audit))
        results.append(selected["result"]); ids.append(operation); derived_audits.append(audit)
    require(inventory["entries"] == sorted(expected_inventory, key=lambda row: row["operation_id"]), "source inventory differs from complete original history union")
    actual = checkpoints[actual_count]
    if current_restore:
        # The current installation may start from a verified backup prefix.
        # Prefix operations are already present there and must not be applied
        # again merely to make a new installation's local event list longer.
        restored_start = current_restore[0].backup_checkpoint
        prefix = [index for index, checkpoint in enumerate(checkpoints) if checkpoint == restored_start]
        require(len(prefix) == 1, "restored source backup prefix does not occur in original chain")
        require(set(completion_by_op) == set(ids[prefix[0]:actual_count]), "restored source completions must form the actual contiguous prefix after its backup")
    require(snapshot["authority_tip"] == checkpoints[-1]["authority_ref"] and snapshot["audit_tip"] == actual["audit_ref"]
            and snapshot["state_version"] == actual["state_version"], "source checkpoint/tail or actual Core state differs")
    require(all(receipt["decided_at"] < snapshot["captured_at"] for receipt in (opening_receipt, *terminals)), "source capture precedes canonical terminal")
    profile = "ALIGNED_OPENING" if actual_count == len(terminals) else "HISTORY_ONLY_TAIL"
    expected_profile = {"history_version": 2, "profile": profile, "authority_tip": snapshot["authority_tip"],
                        "actual_core_audit_tip": snapshot["audit_tip"], "actual_core_state_version": snapshot["state_version"],
                        "completion_digest": None if last_completion is None else semantics.rawhash(last_completion)}
    require(decode(_one(rows, "SOURCE_PROFILE")) == expected_profile, "source profile does not describe independently verified actual history")
    _bind_optional_original_members(rows, (authority, *cores))
    require(rows.used == set(rows), "archive contains extra unbound source members")
    return SourceValidation(snapshot, authority, cores, opening_checkpoint, tuple(checkpoints), tuple(receipt_wires), tuple(audit_wires),
                            tuple(results), tuple(ids), actual_count, profile)


def verify_restore_evidence(item, trust, deployments, validate_history, *, _depth=0):
    require(type(item) is RestoreEvidence, "explicit restore evidence required")
    context = _typed(item.context_wire, "restoration_context")
    verify_signed(item.context_wire, trust)
    source = verify_source_evidence(item.source, trust, deployments, validate_history, _depth=_depth)
    backup = decode(item.backup_wire)
    validate_fields(backup, RECORD["backup_state"])
    expected_backup = _typed(item.expected_backup_checkpoint_wire, "local_checkpoint")
    require(context["identity"] == source.snapshot["identity"] == backup["identity"]
            and context["source_snapshot"] == source.snapshot, "restore source/context/backup identity mismatch")
    require(context["target_authority_pin_digest"] == trust.pin_digest and context["operator_root_key_id"] == trust.operator_root_key_id,
            "restore target independent fixed trust mismatch")
    require(context["restore_source_state_digest"] == sha(item.backup_wire)
            and context["restore_start_checkpoint"] == backup["checkpoint"] == expected_backup, "restore original backup/external checkpoint binding")
    require(backup["captured_at"] <= source.snapshot["captured_at"] < context["issued_at"] < context["expires_at"], "restore source/backup approval chronology")
    require(context["allowed_actions"] == ["APPLY_VERIFIED_TERMINAL", "VERIFY_HISTORY"], "restore cannot gain mutation production capability")
    matches = [index for index, checkpoint in enumerate(source.canonical_checkpoints) if checkpoint == expected_backup]
    require(len(matches) == 1 and matches[0] <= source.actual_core_count, "backup is not a verified actual source Core prefix")
    count = matches[0]
    require(backup["receipt_wires"] == [wire.hex() for wire in source.receipt_wires[:count+1]]
            and backup["audit_wires"] == [wire.hex() for wire in source.audit_wires[:count+1]]
            and backup["governed_results"] == list(source.results[:count]), "backup original receipt/Audit/result prefix bytes differ")
    latest = decode(source.receipt_wires[count])
    require(latest["decided_at"] <= backup["captured_at"], "backup captured before its included receipt")
    targets = [value for value in deployments if value.core_installation_id == context["target_core_installation_id"]
               and value.storage_generation_id == context["target_storage_generation_id"]
               and value.control_plane_generation_id == context["target_control_plane_generation_id"]]
    require(len(targets) == 1, "restore target original deployment missing or ambiguous")
    semantics.validate_pin_material(trust.pin, targets[0])
    return RestoreValidation(context, source.snapshot, source.authority, source.cores, backup["checkpoint"], source.canonical_checkpoints[-1],
                             source.operation_ids[count:], source.opening_checkpoint)
