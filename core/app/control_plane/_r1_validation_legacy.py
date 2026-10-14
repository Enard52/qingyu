"""Original-format origin/V1 evidence checks without I/O or admission.

Historical JCS and CoreJSON remain distinct from Scoped V2 C2. Public trust and
any observations must be supplied separately; package contents never establish
their own provenance or the continuing authority of a deployment.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .r1_protocol import (
    AuthorityPin, ExpectedIntent, ProtocolError, RECEIPT_PREFIX, canonical_bytes,
    decode_canonical_wire, verify_prepare_ack_wire, verify_terminal_receipt_wire,
)
from .r1_provisioning import (
    ObservedProvisionedTarget, ProvisioningError, verify_pre_migration_target,
    verify_signed_origin,
)
from .r1_validation_codec import ContractError, c2, decode, eq_fields, obj, require, sha, validate
from .r1_validation_crypto import FixedTrust


@dataclass(frozen=True, slots=True)
class OriginEvidenceResult:
    """Valid original signatures/content, not a provenance or admission token."""

    digest: str
    intent: Mapping[str, Any]
    completion: Mapping[str, Any]
    observation_status: str


def verify_origin(
    raw: bytes,
    trust: FixedTrust,
    observed: ObservedProvisionedTarget | None = None,
) -> OriginEvidenceResult:
    """Check the original full JCS {intent, completion} under fixed Root trust.

    K-Intent envelope version 2 still uses its original provisioning prefixes
    and JCS, never Scoped V2 S2. Observed facts are compared only when separately
    supplied; no observation is reconstructed from the signed completion.
    Their authenticity, original release-byte admission and current deployment
    state remain outside this pure historical content check.
    """
    require(type(trust) is FixedTrust, "original origin requires explicit fixed trust")
    require(type(raw) is bytes and 0 < len(raw) <= 1_048_576, "original origin bytes missing or oversized")
    try:
        value = decode_canonical_wire(raw)
        require(type(value) is dict and set(value) == {"intent", "completion"},
                "original origin must contain both exact signed envelopes")
        root = Ed25519PublicKey.from_public_bytes(trust.root_public_key)
        result = verify_signed_origin(value["intent"], value["completion"], root)
        pin = trust.pin
        require(result.intent["authority_domain_id"] == pin["authority_domain_id"]
                and result.intent["operator_root_key_id"] == pin["operator_root_key_id"]
                and result.completion["receipt_key_id"] == pin["receipt_key_id"]
                and result.completion["observed_tls_origin"] == pin["https_origin"],
                "original origin differs from fixed domain/key/TLS trust")
        # A later generation's instance can differ only through an independently
        # checked opening chain. This origin result does not prove that chain.
        if pin["authority_generation"] == 1:
            require(result.intent["authority_instance_id"] == pin["authority_instance_id"],
                    "original generation-one instance differs from fixed trust")
        status = "NOT_PROVIDED"
        if observed is not None:
            require(type(observed) is ObservedProvisionedTarget,
                    "original observations require the explicit observation record")
            verify_pre_migration_target(result, observed)
            status = "CONSISTENT_WITH_SUPPLIED_OBSERVATIONS"
        return OriginEvidenceResult(result.signed_provisioning_origin_digest,
                                    result.intent, result.completion, status)
    except ContractError:
        raise
    except (ProtocolError, ProvisioningError, ValueError, TypeError, KeyError,
            OverflowError, RecursionError) as exc:
        raise ContractError("invalid original signed origin evidence") from exc


@dataclass(frozen=True, slots=True)
class LegacyGenesisEvidence:
    """Original F3 GENESIS records plus independently supplied durable intent.

    These are verification inputs, not a claimed verified flag. root_profile
    comes from the caller's fixed Root configuration, never an archive claim.
    """

    evidence_wire: bytes
    expected_intent: ExpectedIntent
    audit_wire: bytes
    result_wire: bytes
    attestation_wire: bytes
    root_profile: str


_AUDIT_FIELDS = frozenset("audit_seq trust_domain_id continuity_id continuity_epoch state_version operation_type actor_principal_id capability request_id mutation_id result_code payload_hash previous_record_hash created_at".split())


def _core_audit(raw):
    from ..canonical import canonical_json

    require(type(raw) is bytes and 0 < len(raw) <= 1_048_576, "original Core Audit bytes required")
    def pairs(items):
        value = {}
        for key, entry in items:
            require(key not in value, "duplicate original CoreJSON key")
            value[key] = entry
        return value
    value = json.loads(raw, object_pairs_hook=pairs)
    require(type(value) is dict and set(value) == _AUDIT_FIELDS and canonical_json(value) == raw,
            "original exact CoreJSON Audit required")
    from .r1_validation_codec import match
    for field in ("audit_seq", "continuity_epoch"):
        match(value[field], "p")
    match(value["state_version"], "u")
    for field in ("trust_domain_id", "continuity_id", "request_id"):
        match(value[field], "uuid")
    match(value["payload_hash"], "hash")
    match(value["previous_record_hash"], "?hash")
    for field in ("operation_type", "actor_principal_id", "capability", "result_code", "created_at"):
        require(type(value[field]) is str and bool(value[field]), "invalid original Core Audit text")
    return value


def verify_legacy_source(item, trust, deployments, origin_result):
    """Verify a complete same-generation V1 F3 source, including original GENESIS.

    No V1 bytes are converted into V2 objects for hashing. The outer snapshot,
    inventory and externally supplied boundary are existing V2 descriptions of
    the original V1 references. Origin/observations and the exact manifest are
    verified by the enclosing source validator, and checked again where used.
    """
    from .r1_admission import AdmissionError
    try:
        return _verify_legacy_source(item, trust, deployments, origin_result)
    except ContractError:
        raise
    except (AdmissionError, ProtocolError, ProvisioningError, ValueError, TypeError, KeyError, IndexError, AttributeError,
            OverflowError, RecursionError) as exc:
        raise ContractError("invalid or incomplete original V1 source evidence") from exc


def _verify_legacy_source(item, trust, deployments, origin_result):
    # The existing admission verifier is pure; this import reads only its frozen
    # public SQL artifact for a schema digest, never executes SQL or reads a pin.
    from .r1_admission import VerifiedCoreAdmission, verify_genesis_evidence
    from .r1_root_pin import OperatorRootPin, ACCEPTANCE_TEST_ONLY, PRODUCTION
    from .r1_commands import MutationIntent, CommitAuthorization, AbortAuthorization
    from ._r1_validation_chain import decode_boundary, MAX_OPERATIONS
    from ._r1_validation_restore import SourceValidation, _archive, _contains, _one
    from . import _r1_validation_semantics as semantics
    from ..canonical import canonical_json

    require(type(item.legacy) is LegacyGenesisEvidence, "V1 source requires original GENESIS durable evidence")
    require(item.history is None and item.opening is None and not item.restoration_evidence,
            "V1 source cannot substitute V2 history/opening/restoration evidence")
    legacy = item.legacy
    require(type(legacy.expected_intent) is ExpectedIntent, "independent original ExpectedIntent required")
    require(legacy.root_profile in (ACCEPTANCE_TEST_ONLY, PRODUCTION), "explicit original Root profile required")
    snapshot, inventory = decode(item.snapshot_wire), decode(item.inventory_wire)
    validate(snapshot); validate(inventory)
    require(snapshot["source_kind"] == "V1_OFFLINE_UPGRADE", "V1 source kind mismatch")
    def instant(value):
        require(type(value) is str, "original V1 timestamp required")
        stamp = datetime.fromisoformat(value)
        require(stamp.tzinfo is not None and stamp.utcoffset().total_seconds() == 0,
                "original V1 timestamps must use UTC")
        delta = stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)
        micros = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
        require(0 <= micros <= snapshot["captured_at"] * 1000, "original V1 evidence postdates source capture")
        return micros
    _, rows = _archive(item)
    identity, start, expected_end = decode_boundary(item.chain_boundary)
    boundary = item.chain_boundary
    require(identity == snapshot["identity"], "V1 source external identity differs")
    eq_fields(snapshot, {k: getattr(boundary, k) for k in ("owner_identity", "owner_version", "continuity_epoch", "storage_generation_id", "control_plane_generation_id")}, "V1 source external scope differs")
    pin_data = trust.pin
    require(pin_data["authority_generation"] == 1, "V1 source requires the supported original generation-one history")
    pin = AuthorityPin(pin_data["authority_domain_id"], pin_data["authority_instance_id"], pin_data["authority_generation"],
                       Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin_data["receipt_public_key"])), pin_data["receipt_key_id"],
                       pin_data["api_version"], pin_data["https_origin"], pin_data["server_spki_sha256"], pin_data["operator_root_key_id"])
    raw_origin = _one(rows, "SIGNED_ORIGIN")
    origin = decode_canonical_wire(raw_origin)
    root = OperatorRootPin(legacy.root_profile, legacy.root_profile == ACCEPTANCE_TEST_ONLY,
                           trust.operator_root_key_id, Ed25519PublicKey.from_public_bytes(trust.root_public_key))
    public = VerifiedCoreAdmission(pin, root, canonical_bytes(origin["intent"]), canonical_bytes(origin["completion"]), legacy.attestation_wire)
    require(public.origin.signed_provisioning_origin_digest == origin_result.digest == snapshot["signed_origin_digest"], "V1 original origin differs")
    genesis = decode_canonical_wire(legacy.evidence_wire)
    required_genesis = {"operation_id", "request_envelope", "prepare_ack", "receipt_payload", "receipt_hash", "request_envelope_hash", "staged_result_hash", "core_audit_predecessor_hash", "core_audit_candidate_hash", "genesis_operation_id", "qingyu_identity_id", "continuity_id"}
    require(type(genesis) is dict and set(genesis) == required_genesis, "original F3 GENESIS record fields")
    for field in ("request_envelope_hash", "staged_result_hash", "core_audit_predecessor_hash", "core_audit_candidate_hash"):
        require(genesis[field] == getattr(legacy.expected_intent, field), "GENESIS record differs from independent durable intent")
    verify_genesis_evidence(public, genesis, continuity_id=identity["continuity_id"],
                            identity_id=identity["qingyu_identity_id"], operation_id=identity["genesis_operation_id"])
    genesis_receipt = genesis["receipt_payload"]
    audit = _core_audit(legacy.audit_wire)
    result = decode_canonical_wire(legacy.result_wire)
    require(sha(legacy.result_wire) == genesis_receipt["result_payload_hash"], "original GENESIS result preimage differs")
    require(sha(legacy.audit_wire) == legacy.expected_intent.core_audit_candidate_hash, "original GENESIS Core Audit differs")
    eq_fields(audit, {"audit_seq": 1, "previous_record_hash": None, "request_id": identity["genesis_operation_id"],
                     "continuity_id": identity["continuity_id"], "trust_domain_id": boundary.trust_domain_id,
                     "continuity_epoch": boundary.continuity_epoch, "actor_principal_id": boundary.owner_identity,
                     "operation_type": "AUTHORITY_GENESIS_ACTIVATION", "capability": "core_governance",
                     "mutation_id": None, "result_code": "COMMITTED",
                     "state_version": genesis["request_envelope"]["expected_state_version"] + 1}, "original GENESIS Audit scope differs")
    eq_fields(genesis_receipt, {"actor_or_owner_identity": boundary.owner_identity, "continuity_epoch": boundary.continuity_epoch,
                              "owner_version": boundary.owner_version, "storage_generation_id": boundary.storage_generation_id,
                              "control_plane_generation_id": boundary.control_plane_generation_id}, "original GENESIS receipt scope differs")
    prior_time = instant(genesis_receipt["decided_at"])
    require(instant(genesis["prepare_ack"]["prepared_at"]) <= prior_time, "GENESIS receipt precedes original prepare")
    instant(audit["created_at"])
    instant(origin_result.completion["creation_event_timestamp"])
    instant(decode_canonical_wire(legacy.attestation_wire)["payload"]["observed_at"])
    def checkpoint(receipt, audit_value, audit_raw):
        return obj("local_checkpoint", state_version=audit_value["state_version"],
                   authority_ref=obj("authority_ref", wire_version=1, authority_generation=receipt["authority_generation"], authority_sequence=receipt["authority_sequence"], receipt_hash=sha(RECEIPT_PREFIX + canonical_bytes(receipt))),
                   audit_ref=obj("audit_ref", wire_version=1, audit_sequence=audit_value["audit_seq"], audit_hash=sha(audit_raw)))
    initial = checkpoint(genesis_receipt, audit, legacy.audit_wire)
    require(initial == start, "V1 source original GENESIS differs from external start checkpoint")
    _contains(rows, "SOURCE_ADMISSION", legacy.evidence_wire)
    _contains(rows, "SOURCE_ADMISSION", legacy.attestation_wire)
    _contains(rows, "REQUEST", canonical_bytes(genesis["request_envelope"]))
    _contains(rows, "PREPARE_ACK", canonical_bytes(genesis["prepare_ack"]))
    _contains(rows, "AUTHORITY_RECEIPT", canonical_bytes(genesis_receipt))
    _contains(rows, "CORE_AUDIT", legacy.audit_wire)
    # The original result is explicit nonwire evidence, archived without adding
    # a protocol domain or pretending that it was part of the signed receipt.
    _contains(rows, "REGISTRY_OUTPUT", legacy.result_wire)

    def by_raw(role, digest):
        matches = [raw for (name, _), raw in rows.items() if name == role and sha(raw) == digest]
        require(len(matches) == 1, "missing or ambiguous original V1 " + role)
        return matches[0]
    entries = inventory["entries"]
    require(0 < len(entries) <= MAX_OPERATIONS + 1, "bounded V1 source operation count")
    ordered = {}
    for entry in entries:
        require(entry["wire_version"] == 1 and entry["state"] in ("COMMITTED", "ABORTED")
                and entry["terminal_ref"] is not None and entry["audit_ref"] is not None, "V1 switch requires every operation finalized")
        sequence = entry["terminal_ref"]["authority_sequence"]
        require(sequence not in ordered, "duplicate original Authority sequence")
        ordered[sequence] = entry
    require(set(ordered) == set(range(1, len(entries)+1)), "V1 source Authority sequence gap")
    expected_first = {"operation_id": identity["genesis_operation_id"], "wire_version": 1,
                      "request_raw_sha256": sha(canonical_bytes(genesis["request_envelope"])), "authorization_raw_sha256": None,
                      "terminal_ref": initial["authority_ref"], "audit_ref": initial["audit_ref"], "state": "COMMITTED"}
    require(ordered[1] == expected_first, "original GENESIS inventory entry differs")
    cps, receipt_wires, audit_wires, results, ids = [initial], [canonical_bytes(genesis_receipt)], [legacy.audit_wire], [], []
    seen_mutations = set()
    used_sources, used_authorizations, used_acks, used_candidates, used_stages = set(), set(), {canonical_bytes(genesis["prepare_ack"])}, set(), set()
    for sequence in range(2, len(entries)+1):
        entry, prior = ordered[sequence], cps[-1]
        request_raw = by_raw("REQUEST", entry["request_raw_sha256"])
        intent = MutationIntent.from_wire(request_raw)
        request, payload = intent.envelope, intent.payload
        require(intent.operation_id == entry["operation_id"] and payload["mutation_id"] not in seen_mutations, "V1 source operation/mutation identity conflict")
        seen_mutations.add(payload["mutation_id"])
        eq_fields(request, {"qingyu_identity_id": identity["qingyu_identity_id"], "continuity_id": identity["continuity_id"],
                            "actor_or_owner_identity": boundary.owner_identity, "expected_owner_version": boundary.owner_version,
                            "expected_continuity_epoch": boundary.continuity_epoch, "expected_state_version": prior["state_version"],
                            "storage_generation_id": boundary.storage_generation_id}, "V1 request stable identity/state differs")
        eq_fields(payload, {"genesis_operation_id": identity["genesis_operation_id"], "control_plane_generation_id": boundary.control_plane_generation_id,
                            "core_audit_predecessor_hash": prior["audit_ref"]["audit_hash"]}, "V1 request original predecessors differ")
        stored_value = payload["staged_result"]["value"]
        require(type(stored_value) is dict and set(stored_value) == {"payload", "capability", "requested_decision"}
                and stored_value["capability"] == "core_governance" and stored_value["requested_decision"] in ("COMMIT", "ABORT"), "V1 original source decision/value missing")
        source = {"continuity_id": identity["continuity_id"], "continuity_epoch": boundary.continuity_epoch,
                  "lease_id": payload["lease_id"], "mutation_id": payload["mutation_id"], "actor_principal_id": boundary.owner_identity,
                  "capability": "core_governance", "payload": stored_value["payload"], "_r1_decision": stored_value["requested_decision"]}
        source_raw = canonical_bytes(source)
        _contains(rows, "SOURCE_REQUEST", source_raw); used_sources.add(source_raw)
        candidates = []
        for decision, digest in (("COMMITTED", payload["core_audit_candidate_hash"]), ("ABORTED", payload["abort_result"]["core_audit_candidate_hash"])):
            raw = by_raw("AUDIT_CANDIDATE", digest); candidate = _core_audit(raw)
            eq_fields(candidate, {"audit_seq": prior["audit_ref"]["audit_sequence"]+1, "trust_domain_id": boundary.trust_domain_id,
                                  "continuity_id": identity["continuity_id"], "continuity_epoch": boundary.continuity_epoch,
                                  "state_version": intent.result_payload(decision)["state_version"], "operation_type": "GOVERNED_MUTATION",
                                  "actor_principal_id": boundary.owner_identity, "capability": "core_governance", "request_id": intent.operation_id,
                                  "mutation_id": payload["mutation_id"], "result_code": decision, "previous_record_hash": prior["audit_ref"]["audit_hash"],
                                  "payload_hash": sha(canonical_json({"mutation_id": payload["mutation_id"], "value": stored_value["payload"], "decision": decision}))}, "V1 independent Audit/result branch differs")
            candidates.append((raw, candidate)); used_candidates.add(raw)
            instant(candidate["created_at"])
        ack_matches = [raw for (role, _), raw in rows.items() if role == "PREPARE_ACK" and decode_canonical_wire(raw).get("request_envelope_hash") == intent.request_hash]
        require(len(ack_matches) == 1, "original V1 Ack missing or ambiguous")
        ack_raw = ack_matches[0]; used_acks.add(ack_raw)
        ack = verify_prepare_ack_wire(ack_raw, request, pin, intent.expected_intent)
        auth_raw = by_raw("TERMINAL_AUTHORIZATION", entry["authorization_raw_sha256"])
        authorization = CommitAuthorization.from_wire(auth_raw) if stored_value["requested_decision"] == "COMMIT" else AbortAuthorization.from_wire(auth_raw)
        authorization.validate_for(intent); used_authorizations.add(auth_raw)
        stage = b"QINGYU-R1-CORE-STAGED-EVIDENCE-V1\0" + request_raw + ack_raw + candidates[0][0] + candidates[1][0]
        _contains(rows, "STAGED_EVIDENCE", stage); used_stages.add(stage)
        auth = decode_canonical_wire(auth_raw)
        require(auth["transaction_evidence_hash" if authorization.decision == "COMMIT" else "abort_evidence_hash"] == sha(stage), "V1 original staging evidence differs")
        receipt_matches = [raw for (role, _), raw in rows.items() if role == "AUTHORITY_RECEIPT" and sha(RECEIPT_PREFIX+raw) == entry["terminal_ref"]["receipt_hash"]]
        require(len(receipt_matches) == 1, "V1 original receipt missing or ambiguous")
        receipt_raw = receipt_matches[0]; receipt = decode_canonical_wire(receipt_raw)
        verify_terminal_receipt_wire(receipt_raw, request, pin, intent.expected_intent, expected_sequence=sequence,
                                     expected_previous_hash=prior["authority_ref"]["receipt_hash"], prepared_ack=ack)
        decided = instant(receipt["decided_at"])
        require(prior_time <= decided and instant(ack["prepared_at"]) <= decided,
                "original V1 prepare/receipt chronology differs")
        prior_time = decided
        outcome = "COMMITTED" if authorization.decision == "COMMIT" else "ABORTED"
        eq_fields(receipt, {"result_state": outcome, "result_code": outcome, "result_payload_hash": intent.result_hash(outcome),
                            "continuity_epoch": boundary.continuity_epoch, "owner_version": boundary.owner_version,
                            "control_plane_generation_id": boundary.control_plane_generation_id, "lease_generation": payload["lease_generation"]}, "V1 receipt result/fences differ")
        selected_raw, selected = candidates[0 if outcome == "COMMITTED" else 1]
        _contains(rows, "CORE_AUDIT", selected_raw)
        after = checkpoint(receipt, selected, selected_raw)
        require(entry["terminal_ref"] == after["authority_ref"] and entry["audit_ref"] == after["audit_ref"] and entry["state"] == outcome,
                "V1 inventory actual selected tail differs")
        cps.append(after); receipt_wires.append(receipt_raw); audit_wires.append(selected_raw)
        results.append(intent.result_payload(outcome)); ids.append(intent.operation_id)
    require(cps[-1] == expected_end and snapshot["authority_tip"] == expected_end["authority_ref"]
            and snapshot["audit_tip"] == expected_end["audit_ref"] and snapshot["state_version"] == expected_end["state_version"], "V1 source tail differs from external expected checkpoint")
    expected_roles = {"REQUEST": {by_raw("REQUEST", entry["request_raw_sha256"]) for entry in entries},
                      "AUTHORITY_RECEIPT": set(receipt_wires), "CORE_AUDIT": set(audit_wires), "SOURCE_REQUEST": used_sources,
                      "TERMINAL_AUTHORIZATION": used_authorizations, "PREPARE_ACK": used_acks,
                      "AUDIT_CANDIDATE": used_candidates, "STAGED_EVIDENCE": used_stages,
                      "SOURCE_ADMISSION": {legacy.evidence_wire, legacy.attestation_wire},
                      "REGISTRY_OUTPUT": {legacy.result_wire}}
    for role, expected in expected_roles.items():
        actual = [raw for (name, _), raw in rows.items() if name == role]
        require(len(actual) == len(expected) and set(actual) == expected, "V1 archive has omitted, duplicate or unaccounted " + role)
        for raw in actual:
            _contains(rows, role, raw)
    require(bool(deployments), "V1 source requires explicit deployment material")
    materials = [material for material in deployments if material.storage_generation_id == boundary.storage_generation_id
                 and material.control_plane_generation_id == boundary.control_plane_generation_id]
    require(len(materials) == 1, "V1 source deployment scope missing or ambiguous")
    material = materials[0]
    semantics.validate_pin_material(pin_data, material)
    for role, raw in (("DEPLOYMENT_ADMISSION", material.deployment_bytes), ("RECOVERY_COMPONENT", material.component_bytes),
                      ("TLS_SPKI_DER", material.tls_spki_der), ("AUTHORITY_PIN", trust.pin_wire),
                      ("ROOT_PUBLIC_KEY", trust.root_public_key), ("RECEIPT_PUBLIC_KEY", bytes.fromhex(pin_data["receipt_public_key"])),
                      ("SIGNED_ORIGIN", raw_origin), ("OPERATION_INVENTORY", item.inventory_wire)):
        _contains(rows, role, raw)
    require(sha(_one(rows, "SOURCE_DEPLOYMENT")) == snapshot["source_deployment_digest"]
            and sha(_one(rows, "SOURCE_FENCING")) == snapshot["source_fencing_evidence_digest"], "V1 source physical evidence bytes differ")
    profile = {"history_version": 2, "profile": "ALIGNED_OPENING", "authority_tip": snapshot["authority_tip"],
               "actual_core_audit_tip": snapshot["audit_tip"], "actual_core_state_version": snapshot["state_version"],
               "completion_digest": None}
    require(decode(_one(rows, "SOURCE_PROFILE")) == profile, "V1 source profile differs from actual original history")
    require(rows.used == set(rows), "V1 archive contains unbound source members")
    # SourceValidation uses empty V2 registries for V1 rather than inventing
    # V2 events. Original receipts/Audits/checkpoints remain explicit below.
    return SourceValidation(snapshot, {}, (), initial, tuple(cps), tuple(receipt_wires), tuple(audit_wires),
                            tuple(results), tuple(ids), len(ids), "ALIGNED_OPENING")
