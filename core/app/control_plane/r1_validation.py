"""Read-only Scoped V2 evidence validation for product callers.

This is a conditional proof checker, not a source-admission adapter. FixedTrust
is supplied separately by the caller's protected configuration boundary. Its
provenance, registry export completeness, authenticated sessions, trusted clocks
and database transactions are NOT established by this slice. No boolean in an
evidence body can promote these claims to trusted facts.

Multiple operations require an independent chain boundary. Restoration evidence
requires the complete source/archive/backup proof, checked against explicit trust.
Neither boundary nor source bytes establish their own deployment provenance.

REGISTRY_RELATIONS checks a supplied history prefix. TERMINAL_HISTORY additionally
requires each request's terminal and its actual Core publication. COMPLETION_HISTORY
also requires the original permit and completed local use. These operations never
evaluate a current QUERY caller, issue credentials, write an event, or apply an
effect. Trusted-history, lifecycle/source admission and all business actions fail
closed until their real source adapters are implemented.
"""

from __future__ import annotations

from dataclasses import dataclass

from .r1_validation_codec import (
    ContractError, SCHEMA, c2, decode, h2, match, require, validate,
)
from .r1_validation_crypto import FixedTrust, verify_signed
from . import _r1_validation_semantics as relations
from ._r1_validation_semantics import DeploymentEvidence
from ._r1_validation_chain import ChainBoundary, MAX_OPERATIONS, verify_operation_chain
from ._r1_validation_restore import (
    ArchiveMember, SourceDeploymentObservation, SourceFencingObservation,
    OpeningEvidence, SourceEvidence, RestoreEvidence,
)
from ._r1_validation_legacy import LegacyGenesisEvidence


class UnsupportedOperation(ContractError):
    """The requested operation is not part of this validation slice."""


class MissingTrustedContext(ContractError):
    """A required independent trust/source boundary is unavailable."""


@dataclass(frozen=True, slots=True)
class CoreHistory:
    runtime_principal: str
    raw: bytes


@dataclass(frozen=True, slots=True)
class HistoryEvidence:
    request_wires: tuple[bytes, ...]
    authority_history: bytes
    core_histories: tuple[CoreHistory, ...]
    context_wires: tuple[bytes, ...] = ()
    source_admission_wires: tuple[bytes, ...] = ()


@dataclass(frozen=True, slots=True)
class EvidenceValidation:
    """Separate evidence conclusions; never a current authorization token.

    verified_signature_count counts unique V2 signed roots in the supplied
    top-level registries and contexts. Nested source/opening/origin signatures
    are additionally checked by source validation and are not added to it.
    """
    operation: str
    protocol: str
    signatures: str
    semantics: str
    history_origin: str
    current_eligibility: str
    verified_signature_count: int
    request_digests: tuple[str, ...]
    terminal_digests: tuple[str, ...]
    completion_digests: tuple[str, ...]
    chain_boundary: str = "NOT_PROVIDED"
    restoration_context_digests: tuple[str, ...] = ()
    evidence_completeness: str = "SUPPLIED_HISTORY_ONLY"
    environment_origin: str = "NOT_OBSERVED"


@dataclass(frozen=True, slots=True)
class SourceEvidenceValidation:
    """Archive relationships, with external observations kept conditional."""
    source_snapshot_digest: str
    profile: str
    verified_checkpoint_wire: bytes
    terminal_checkpoint_wire: bytes
    restoration_context_digest: str | None = None
    signatures: str = "VALID_UNDER_EXPLICIT_PIN"
    evidence_completeness: str = "VERIFIED_DECLARED_SOURCE_MEMBERS"
    history_origin: str = "UNVERIFIED"
    environment_origin: str = "NOT_OBSERVED"
    current_eligibility: str = "NOT_EVALUATED"


def validate_source_evidence(source, trust: FixedTrust, deployments: tuple[DeploymentEvidence, ...]) -> SourceEvidenceValidation:
    """Validate a complete supplied source, including a genesis-only source.

The complete declared archive is checked; an unknown unexported tail, live clone,
physical isolation or real deployment provenance is not discovered by this API.
"""
    if type(trust) is not FixedTrust:
        raise MissingTrustedContext("source verification requires independent fixed trust")
    require(type(deployments) is tuple and len(deployments) <= 32, "source deployment tuple/resource limit")
    from ._r1_validation_restore import verify_source_evidence
    try:
        result = verify_source_evidence(source, trust, deployments, validate_evidence)
        snapshot = result.snapshot
        actual = relations.obj("local_checkpoint", state_version=snapshot["state_version"],
            authority_ref=result.canonical_checkpoints[result.actual_core_count]["authority_ref"],
            audit_ref=snapshot["audit_tip"])
        return SourceEvidenceValidation(h2(snapshot), result.profile, c2(actual), c2(result.canonical_checkpoints[-1]))
    except ContractError:
        raise
    except (KeyError, IndexError, TypeError, AttributeError, ValueError, RecursionError, OverflowError) as exc:
        raise ContractError("malformed or incomplete original source evidence") from exc


def validate_restoration_evidence(proof, trust: FixedTrust, deployments: tuple[DeploymentEvidence, ...]) -> SourceEvidenceValidation:
    """Check source/backup/context without requiring or performing APPLY.

    The verified checkpoint is the supplied backup's original checkpoint, not
    an assertion about the current state of the restoration target.
    """
    if type(trust) is not FixedTrust:
        raise MissingTrustedContext("restoration verification requires independent fixed trust")
    require(type(deployments) is tuple and len(deployments) <= 32, "restore deployment tuple/resource limit")
    from ._r1_validation_restore import verify_restore_evidence
    try:
        result = verify_restore_evidence(proof, trust, deployments, validate_evidence)
        return SourceEvidenceValidation(h2(result.source_snapshot), "RESTORATION_SCOPE",
            c2(result.backup_checkpoint), c2(result.source_checkpoint), h2(result.context))
    except ContractError:
        raise
    except (KeyError, IndexError, TypeError, AttributeError, ValueError, RecursionError, OverflowError) as exc:
        raise ContractError("malformed or incomplete original restore evidence") from exc


_SUPPORTED = frozenset({"REGISTRY_RELATIONS", "TERMINAL_HISTORY", "COMPLETION_HISTORY"})
_TRUST_REQUIRED = frozenset({
    "TRUSTED_HISTORY", "QUERY_EXISTING", "CURRENT_ELIGIBILITY", "ADMIT_SOURCE",
    "RESTORE_ADMISSION", "ACTIVE", "ADMITTED",
})


def validate_evidence(
    operation: str,
    evidence: HistoryEvidence,
    trust: FixedTrust | None,
    deployments: tuple[DeploymentEvidence, ...],
    *,
    chain_boundary: ChainBoundary | None = None,
    restore_evidence: tuple = (),
) -> EvidenceValidation:
    """Verify exact supplied bytes, real signatures and historical relations.

    A successful result explicitly leaves provenance UNVERIFIED and current
    eligibility NOT_EVALUATED. It is never a capability or authorization token.
    No input is mutated. DeploymentEvidence holds opaque source bytes and their
    claimed scope, not an assertion of OS protection or deployment admission.
    Top-level mutation histories use V2. SourceEvidence preserves original V1
    bytes and dispatches them to the existing version-specific product rules;
    V1 source archives are checked through validate_source_evidence or opening
    lineage, never reencoded as V2 mutation records.
    """
    if type(operation) is not str:
        raise UnsupportedOperation("operation must be an explicit supported name")
    if operation in _TRUST_REQUIRED:
        raise MissingTrustedContext("trusted source/current authorization adapters are not implemented")
    if operation not in _SUPPORTED:
        raise UnsupportedOperation("operation is not supported by the read-only validation kernel")
    if type(trust) is not FixedTrust:
        raise MissingTrustedContext("separately configured fixed trust is required")
    require(type(evidence) is HistoryEvidence, "explicit HistoryEvidence required")
    require(type(deployments) is tuple and len(deployments) <= 32, "explicit deployment tuple/resource limit required")
    try:
        return _validate(operation, evidence, trust, deployments, chain_boundary, restore_evidence)
    except ContractError:
        raise
    except (KeyError, IndexError, TypeError, AttributeError, ValueError, RecursionError, OverflowError) as exc:
        # Malformed untrusted structures must never leak an accidental success
        # or an implementation exception that callers might mistake for a retry.
        raise ContractError("malformed or incomplete supplied protocol evidence") from exc


def _validate(operation, evidence, trust, deployments, chain_boundary, restore_evidence):
    pin = decode(trust.pin_wire)
    validate(pin)
    materials = {}
    for item in deployments:
        require(type(item) is DeploymentEvidence, "deployment context type")
        relations.validate_pin_material(pin, item)
        require(item.runtime_principal not in materials, "duplicate deployment principal")
        materials[item.runtime_principal] = item
    require(type(evidence.request_wires) is tuple and bool(evidence.request_wires), "request wires required")
    require(len(evidence.request_wires) <= MAX_OPERATIONS * 2, "request wire resource limit")
    requests = {}
    for raw in evidence.request_wires:
        request = decode(raw)
        validate(request)
        require(request["type"] == "mutation_request", "only mutation request evidence is supported")
        relations.verify_request(request, pin, request["intent"]["scope"]["actor_identity"])
        operation_id = request["intent"]["operation_id"]
        require(operation_id not in requests or c2(requests[operation_id]) == raw,
                "same operation ID with different canonical content")
        requests[operation_id] = request
    require(len(requests) <= MAX_OPERATIONS, "operation chain resource limit")
    if len(requests) > 1 and chain_boundary is None and not restore_evidence:
        raise MissingTrustedContext("multiple operations require an external chain boundary")

    authority = decode(evidence.authority_history)
    contexts = {}
    restore_results = []
    signature_digests = set()

    def verify_object(value):
        if type(value) is not dict:
            raise ContractError("registry record must be an object")
        # Only protocol record roots are inspected here; arbitrary business
        # payload JSON may legitimately contain a field named 'type'.
        if "type" in value:
            require(value["type"] in SCHEMA, "unknown protocol record type")
            validate(value)
            if "receipt_signature" in value or "root_signature" in value:
                digest = h2(value)
                if digest not in signature_digests:
                    verify_signed(value, trust)
                    signature_digests.add(digest)
        else:
            require("root_signature" not in value and "receipt_signature" not in value,
                    "signature on unregistered record type")

    require(type(evidence.context_wires) is tuple, "context wires tuple required")
    require(type(restore_evidence) is tuple and len(restore_evidence) <= 16, "restore evidence tuple/resource limit")
    if restore_evidence:
        from ._r1_validation_restore import verify_restore_evidence
        for proof in restore_evidence:
            result = verify_restore_evidence(proof, trust, deployments, validate_evidence)
            context = result.context
            verify_object(context)
            digest = h2(context)
            require(digest not in contexts, "duplicate restoration context proof")
            contexts[digest] = context
            restore_results.append(result)
    for raw in evidence.context_wires:
        context = decode(raw)
        verify_object(context)
        require(context.get("type") == "restoration_context", "restoration context type")
        if h2(context) not in contexts:
            raise MissingTrustedContext("restore history requires complete source/archive/backup proof")
        require(context == contexts[h2(context)], "restoration context proof content conflict")
    def inspect_registry(registry, material=None):
        relations.registry_structure(registry, pin, material)
        for value in registry["records"].values():
            verify_object(value)
            declared = value.get("restoration_context_digest")
            enrollment = value.get("enrollment")
            if type(enrollment) is dict:
                declared = enrollment.get("restoration_context_digest")
                if enrollment.get("context_kind") == "MANUAL_RESTORE_ADMITTED" and declared is None:
                    raise MissingTrustedContext("restore history requires a bound restoration context")
            if value.get("type") == "restoration_context":
                declared = h2(value)
            if value.get("context_kind") == "MANUAL_RESTORE_ADMITTED" and declared is None:
                # LOCAL_PROTECTION has a policy_digest, not a context field.
                # Resolve its contractual policy link instead of demanding an
                # invented restoration_context_digest on this nonwire record.
                policy_digest = value.get("policy_digest")
                if policy_digest is not None:
                    policy = relations.record_by(authority, policy_digest)
                    require(policy.get("type") == "recovery_policy", "restore protection policy type")
                    declared = policy["restoration_context_digest"]
                if declared is None:
                    raise MissingTrustedContext("restore history requires a bound restoration context")
            if declared is not None and declared not in contexts:
                raise MissingTrustedContext("restore history requires complete source/archive/backup proof")

    inspect_registry(authority)
    require(type(evidence.core_histories) is tuple, "core histories tuple required")
    require(len(evidence.core_histories) <= 16, "Core history resource limit")
    cores = []
    for item in evidence.core_histories:
        require(type(item) is CoreHistory, "core history type")
        match(item.runtime_principal, "text")
        require(item.runtime_principal in materials, "missing deployment evidence for Core history")
        core = decode(item.raw)
        material = materials[item.runtime_principal]
        inspect_registry(core, material)
        cores.append((core, material))

    authority_state = relations.replay_authority(authority, pin, materials, requests, contexts)
    for result in restore_results:
        source_events = result.source_authority["events"]
        require(authority["header"] == result.source_authority["header"]
                and authority["events"][:len(source_events)] == source_events,
                "restore source Authority history must remain the exact original prefix")
        # Compare exact original source terminals, not only sequence numbers.
        for op in result.allowed_operations:
            require(op in requests and op in authority_state["terminals"], "restore source operation missing from target evidence")
            original = [result.source_authority["records"][event["output_digest"]]
                for event in result.source_authority["events"] if event["event_kind"] == "TERMINAL"
                and result.source_authority["records"][event["output_digest"]]["operation_id"] == op]
            require(len(original) == 1 and original[0] == authority_state["terminals"][op],
                    "restore current history differs from original source terminal")
        for permit in authority_state["permits"].values():
            if permit["restoration_context_digest"] == h2(result.context):
                require(permit["operation_id"] in result.allowed_operations,
                        "restore permit operation is outside the approved backup-to-tail interval")
    require(type(evidence.source_admission_wires) is tuple, "original source admission wires required")
    admissions = {}
    for raw in evidence.source_admission_wires:
        admission = decode(raw)
        relations.validate_fields(admission, relations.RECORD["source_admission"])
        operation_id = admission["operation_id"]
        require(operation_id in requests, "source admission references an unknown request")
        require(operation_id not in admissions or c2(admissions[operation_id]) == raw,
                "original source admission content conflict")
        admissions[operation_id] = admission
    for operation_id, request in requests.items():
        require(operation_id in admissions, "original source admission is required")
        admission = admissions[operation_id]
        ack = authority_state["acks"].get(operation_id)
        if ack is not None:
            snap = relations.record_by(authority, ack["prepare_execution_digest"], "execution_snapshot")
            policy = authority_state["policies"][snap["policy_digest"]]
            original_material = materials[policy["runtime_principal"]]
        else:
            # Prefix-only checking can precede PREPARE. Independently supplied
            # deployment scope still binds the source record; no admission is
            # inferred from that match or from the request's actor field.
            scope = request["intent"]["scope"]
            candidates = [item for item in deployments
                          if item.core_installation_id == admission["core_installation_id"]
                          and item.storage_generation_id == scope["storage_generation_id"]
                          and item.control_plane_generation_id == scope["control_plane_generation_id"]
                          and relations.sha(item.component_bytes) == admission["component_artifact_digest"]
                          and relations.sha(item.deployment_bytes) == admission["deployment_admission_digest"]]
            require(len(candidates) == 1, "original source deployment scope is missing or ambiguous")
            original_material = candidates[0]
        relations.verify_source_admission(admission, request, pin, original_material)
    local_states = [relations.replay_core(core, authority, pin, material, materials, requests, contexts)
                    for core, material in cores]
    relations.verify_causality(authority, [core for core, _ in cores])
    if chain_boundary is not None:
        verify_operation_chain(requests, authority, cores, chain_boundary, contexts)
    elif restore_results:
        # A source proof supplies its independently checked segment boundary;
        # it is never reconstructed from the target request's own claims.
        boundaries = [proof.source.chain_boundary for proof in restore_evidence]
        require(all(value == boundaries[0] for value in boundaries), "restore sources disagree on chain boundary")
        verify_operation_chain(requests, authority, cores, boundaries[0], contexts)

    terminals = []
    completions = []
    for operation_id, request in requests.items():
        terminal = authority_state["terminals"].get(operation_id)
        if operation != "REGISTRY_RELATIONS":
            require(terminal is not None, "complete terminal history is required")
            key = (operation_id, terminal["authorization_kind"])
            require(sum(key in state["publications"] for state in local_states) == 1,
                    "terminal requires one original Core publication")
        if terminal is not None:
            terminals.append(h2(terminal))
        found = [state["completions"][operation_id] for state in local_states
                 if operation_id in state["completions"]]
        if operation == "COMPLETION_HISTORY":
            require(bool(found), "an original completed local use is required")
        for completion in found:
            completions.append(relations.rawhash(completion))

    if operation == "COMPLETION_HISTORY":
        for result in restore_results:
            context = result.context
            targets = [state for (_, material), state in zip(cores, local_states)
                       if material.core_installation_id == context["target_core_installation_id"]
                       and material.storage_generation_id == context["target_storage_generation_id"]
                       and material.control_plane_generation_id == context["target_control_plane_generation_id"]]
            require(len(targets) == 1, "one restoration target Core history is required")
            for op in result.allowed_operations:
                require(op in targets[0]["completions"], "restoration target has not completed the approved tail")
                completion = targets[0]["completions"][op]
                require(authority_state["permits"][completion["permit_digest"]]["restoration_context_digest"] == h2(context),
                        "restoration target completion used a different context")

    return EvidenceValidation(
        operation=operation,
        protocol="VALID_SCOPED_V2",
        signatures="VALID_UNDER_EXPLICIT_PIN" if signature_digests else "NO_SIGNED_OBJECTS",
        semantics="CONSISTENT_WITH_SUPPLIED_HISTORY",
        history_origin="UNVERIFIED",
        current_eligibility="NOT_EVALUATED",
        verified_signature_count=len(signature_digests),
        request_digests=tuple(sorted(h2(value) for value in requests.values())),
        terminal_digests=tuple(sorted(terminals)),
        completion_digests=tuple(sorted(completions)),
        chain_boundary="MATCHED_EXPLICIT_BOUNDARY" if chain_boundary is not None or restore_results else "NOT_PROVIDED",
        restoration_context_digests=tuple(sorted(contexts)),
        evidence_completeness="VERIFIED_DECLARED_SOURCE_MEMBERS" if restore_results else "SUPPLIED_HISTORY_ONLY",
    )
