from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .canonical import sha256_hex
from .errors import CoreError

B1_FOUNDATION_CHECKPOINT_COMMIT = "ebcd8588e21ab28556e7d4f70fba095f3082cd28"
B1_FOUNDATION_CHECKPOINT_TAG = "r1/dev-b1-foundation-stage-01-20260918"
B1_FOUNDATION_CANDIDATE_MANIFEST_SHA256 = "a3c4379d703236c509d2ace661538d2f8a9d5fbe43a7815306ad610be46d7cb3"
B2_INTENT_SCHEMA_VERSION = "qingyu-b2-signed-migration-intent-v1"
B2_PLAN_SCHEMA_VERSION = "qingyu-b2-activation-plan-v1"
PRODUCTION_AUTHORITY_DECISION = "MISSING_AND_BLOCKS_ACTIVATION"

REHEARSAL_FORBIDDEN_MARKERS = (
    "B1_FOUNDATION_CANDIDATE_REHEARSAL",
    "foundation_rehearsal_authority_state",
    "PostgresAuthorityStateStore",
    "PersistentRehearsalAuthority",
    "r1-b1-foundation-",
    "postgres-rehearsal-authority",
    "foundation-rehearsal-authority",
    "qingyu-foundation-rehearsal-authority-state-v1",
)


class B2ActivationState(StrEnum):
    B1_CLOSED = "B1_CLOSED"
    B2_PREPARATION = "B2_PREPARATION"
    PRE_ACTIVATION_READY = "PRE_ACTIVATION_READY"
    INDEPENDENT_REVIEW_PASS = "INDEPENDENT_REVIEW_PASS"
    OWNER_APPROVED = "OWNER_APPROVED"
    ACTIVATION_EXECUTING = "ACTIVATION_EXECUTING"
    GENESIS_DURABLE = "GENESIS_DURABLE"
    ACCEPTANCE_VERIFYING = "ACCEPTANCE_VERIFYING"
    IMPLEMENTATION_GATE_PASS = "IMPLEMENTATION_GATE_PASS"


ALLOWED_STATE_TRANSITIONS: dict[B2ActivationState, tuple[B2ActivationState, ...]] = {
    B2ActivationState.B1_CLOSED: (B2ActivationState.B2_PREPARATION,),
    B2ActivationState.B2_PREPARATION: (B2ActivationState.PRE_ACTIVATION_READY,),
    B2ActivationState.PRE_ACTIVATION_READY: (B2ActivationState.INDEPENDENT_REVIEW_PASS,),
    B2ActivationState.INDEPENDENT_REVIEW_PASS: (B2ActivationState.OWNER_APPROVED,),
    B2ActivationState.OWNER_APPROVED: (B2ActivationState.ACTIVATION_EXECUTING,),
    B2ActivationState.ACTIVATION_EXECUTING: (B2ActivationState.GENESIS_DURABLE,),
    B2ActivationState.GENESIS_DURABLE: (B2ActivationState.ACCEPTANCE_VERIFYING,),
    B2ActivationState.ACCEPTANCE_VERIFYING: (B2ActivationState.IMPLEMENTATION_GATE_PASS,),
    B2ActivationState.IMPLEMENTATION_GATE_PASS: (),
}


class B2Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProductionTargetContract(B2Model):
    target_reference: str = Field(min_length=1)
    environment_identity: str = Field(min_length=1)
    environment_class: Literal["production"]
    host_reference: str = Field(min_length=1)
    database_reference: str = Field(min_length=1)
    postgres_version_major: int = Field(ge=16)
    schema_owner_reference: str = Field(min_length=1)
    expected_pre_activation_state: Literal["EMPTY_PRE_GENESIS"]
    migration_version: str = Field(min_length=1)
    allowed_network_boundary: str = Field(min_length=1)
    backup_recovery_reference: str = Field(min_length=1)
    signer_trust_reference: str = Field(min_length=1)
    authority_reference: str = Field(min_length=1)
    audit_destination_reference: str = Field(min_length=1)
    activation_lock_reference: str = Field(min_length=1)
    expected_commit: str = Field(min_length=40, max_length=64)
    expected_tag: str = Field(min_length=1)

    @model_validator(mode="after")
    def reject_rehearsal_artifacts(self) -> "ProductionTargetContract":
        reject_rehearsal_artifact_reuse(self.model_dump(mode="json"))
        if self.expected_commit != B1_FOUNDATION_CHECKPOINT_COMMIT:
            raise CoreError("B2_WRONG_IMPLEMENTATION_COMMIT")
        if self.expected_tag != B1_FOUNDATION_CHECKPOINT_TAG:
            raise CoreError("B2_WRONG_IMPLEMENTATION_TAG")
        return self


class SignedMigrationIntent(B2Model):
    schema_version: Literal[B2_INTENT_SCHEMA_VERSION] = B2_INTENT_SCHEMA_VERSION
    intent_id: str = Field(min_length=1)
    target_environment: str = Field(min_length=1)
    target_reference: str = Field(min_length=1)
    source_checkpoint: str = Field(min_length=40, max_length=64)
    source_tag: str = Field(min_length=1)
    target_schema_migration_version: str = Field(min_length=1)
    authority_trust_reference: str = Field(min_length=1)
    requested_operation: Literal["PRODUCTION_GENESIS"]
    expected_preconditions: list[str] = Field(min_length=1)
    expected_genesis_behavior: Literal["DURABLE_ONCE_THEN_CONTINUATION_ONLY"]
    valid_from: datetime
    expires_at: datetime
    owner_approval_reference: str = Field(min_length=1)
    signature_metadata: dict[str, Any]

    @model_validator(mode="after")
    def validate_intent(self) -> "SignedMigrationIntent":
        reject_rehearsal_artifact_reuse(self.model_dump(mode="json"))
        if self.source_checkpoint != B1_FOUNDATION_CHECKPOINT_COMMIT:
            raise CoreError("B2_WRONG_IMPLEMENTATION_COMMIT")
        if self.source_tag != B1_FOUNDATION_CHECKPOINT_TAG:
            raise CoreError("B2_WRONG_IMPLEMENTATION_TAG")
        if self.expires_at <= self.valid_from:
            raise CoreError("B2_INTENT_EXPIRY_INVALID")
        if not self.signature_metadata.get("signature_ref") or self.signature_metadata.get("raw_private_key"):
            raise CoreError("B2_INTENT_SIGNATURE_METADATA_INVALID")
        return self

    def canonical_payload(self) -> dict[str, Any]:
        payload = self.model_dump(mode="json")
        payload.pop("signature_metadata", None)
        return payload

    @property
    def canonical_payload_hash(self) -> str:
        return sha256_hex(self.canonical_payload())


class OwnerApproval(B2Model):
    approval_id: str = Field(min_length=1)
    approval_state: Literal["OWNER_APPROVED"]
    activation_candidate_hash: str = Field(min_length=64, max_length=64)
    target_reference: str = Field(min_length=1)
    migration_intent_hash: str = Field(min_length=64, max_length=64)
    authority_trust_reference: str = Field(min_length=1)
    source_checkpoint: str = Field(min_length=40, max_length=64)
    source_tag: str = Field(min_length=1)
    approved_at: datetime
    approval_reference: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_approval(self) -> "OwnerApproval":
        reject_rehearsal_artifact_reuse(self.model_dump(mode="json"))
        if self.source_checkpoint != B1_FOUNDATION_CHECKPOINT_COMMIT:
            raise CoreError("B2_WRONG_IMPLEMENTATION_COMMIT")
        if self.source_tag != B1_FOUNDATION_CHECKPOINT_TAG:
            raise CoreError("B2_WRONG_IMPLEMENTATION_TAG")
        return self


class TargetReadOnlyObservation(B2Model):
    target_reference: str
    reachable: bool
    postgres_version_major: int | None = None
    schema_state: Literal["EMPTY_PRE_GENESIS", "GENESIS_PRESENT", "UNKNOWN"]
    migration_version: str | None = None
    durable_genesis_present: bool
    authority_trust_reference: str | None = None
    backup_recovery_available: bool
    audit_sink_available: bool
    activation_lock_available: bool
    read_only: Literal[True] = True
    observed_at: datetime


class ActivationDryRunResult(B2Model):
    schema_version: Literal[B2_PLAN_SCHEMA_VERSION] = B2_PLAN_SCHEMA_VERSION
    status: Literal["DRY_RUN_READY"]
    source_checkpoint: str
    source_tag: str
    activation_candidate_hash: str
    target_reference: str
    current_target_state: dict[str, Any]
    required_target_state: dict[str, Any]
    migration_intent_hash: str
    owner_approval_required: Literal[True] = True
    authority_mode: Literal["PRODUCTION_AUTHORITY_REQUIRED"]
    trust_refs: dict[str, str]
    ordered_activation_steps: list[str]
    preconditions: list[str]
    postconditions: list[str]
    rollback_recovery_semantics: Literal["AFTER_DURABLE_GENESIS_RECOVERY_OR_CONTINUATION_ONLY"]
    irreversible_boundary: Literal["DURABLE_PRODUCTION_GENESIS_COMMIT"]
    evidence_refs: list[str]
    planned_mutations: Literal[0] = 0
    dry_run_read_only: Literal[True] = True
    plan_hash: str


def reject_rehearsal_artifact_reuse(payload: Any) -> None:
    text = repr(payload)
    if any(marker in text for marker in REHEARSAL_FORBIDDEN_MARKERS):
        raise CoreError("B2_REHEARSAL_ARTIFACT_FORBIDDEN")


def validate_state_transition(current: B2ActivationState, next_state: B2ActivationState) -> None:
    if next_state not in ALLOWED_STATE_TRANSITIONS[current]:
        raise CoreError("B2_STATE_TRANSITION_INVALID")


def activation_candidate_hash(*, target: ProductionTargetContract, intent: SignedMigrationIntent) -> str:
    return sha256_hex({
        "schema_version": "qingyu-b2-activation-candidate-v1",
        "foundation_checkpoint_commit": B1_FOUNDATION_CHECKPOINT_COMMIT,
        "foundation_checkpoint_tag": B1_FOUNDATION_CHECKPOINT_TAG,
        "foundation_candidate_manifest_sha256": B1_FOUNDATION_CANDIDATE_MANIFEST_SHA256,
        "target": target.model_dump(mode="json"),
        "intent_hash": intent.canonical_payload_hash,
    })


def validate_signed_migration_intent(intent: SignedMigrationIntent, *, now: datetime | None = None) -> None:
    now = now or datetime.now(timezone.utc)
    if now < intent.valid_from or now >= intent.expires_at:
        raise CoreError("B2_INTENT_NOT_VALID_NOW")


def validate_owner_approval(*, approval: OwnerApproval | None, target: ProductionTargetContract, intent: SignedMigrationIntent) -> None:
    if approval is None:
        raise CoreError("B2_OWNER_APPROVAL_REQUIRED")
    expected_candidate = activation_candidate_hash(target=target, intent=intent)
    if approval.activation_candidate_hash != expected_candidate:
        raise CoreError("B2_OWNER_APPROVAL_SCOPE_MISMATCH")
    if approval.target_reference != target.target_reference:
        raise CoreError("B2_OWNER_APPROVAL_SCOPE_MISMATCH")
    if approval.migration_intent_hash != intent.canonical_payload_hash:
        raise CoreError("B2_OWNER_APPROVAL_SCOPE_MISMATCH")
    if approval.authority_trust_reference != intent.authority_trust_reference:
        raise CoreError("B2_OWNER_APPROVAL_SCOPE_MISMATCH")


def validate_target_observation(target: ProductionTargetContract, observation: TargetReadOnlyObservation) -> None:
    reject_rehearsal_artifact_reuse(observation.model_dump(mode="json"))
    if observation.target_reference != target.target_reference:
        raise CoreError("B2_TARGET_MISMATCH")
    if not observation.reachable:
        raise CoreError("B2_TARGET_UNREACHABLE")
    if observation.postgres_version_major != target.postgres_version_major:
        raise CoreError("B2_TARGET_POSTGRES_VERSION_MISMATCH")
    if observation.durable_genesis_present:
        raise CoreError("B2_DURABLE_GENESIS_ALREADY_PRESENT")
    if observation.schema_state != target.expected_pre_activation_state:
        raise CoreError("B2_TARGET_STATE_NOT_PRE_GENESIS")
    if observation.migration_version != target.migration_version:
        raise CoreError("B2_TARGET_MIGRATION_VERSION_MISMATCH")
    if observation.authority_trust_reference != target.signer_trust_reference:
        raise CoreError("B2_TRUST_REFERENCE_MISMATCH")
    if not observation.backup_recovery_available:
        raise CoreError("B2_RECOVERY_PREREQUISITE_MISSING")
    if not observation.audit_sink_available:
        raise CoreError("B2_AUDIT_SINK_MISSING")
    if not observation.activation_lock_available:
        raise CoreError("B2_ACTIVATION_LOCK_MISSING")


@dataclass
class ActivationAttemptGuard:
    active_attempt_id: str | None = None

    def acquire(self, attempt_id: str) -> None:
        if self.active_attempt_id is not None and self.active_attempt_id != attempt_id:
            raise CoreError("B2_ACTIVATION_ATTEMPT_CONFLICT")
        self.active_attempt_id = attempt_id


def production_authority_decision() -> dict[str, Any]:
    return {
        "decision": PRODUCTION_AUTHORITY_DECISION,
        "rehearsal_authority_reusable": False,
        "activation_blocker": "BLOCKED_BY_PRODUCTION_AUTHORITY_GAP",
        "minimum_gap": [
            "production authority coordinator acceptance",
            "production DB CAS/locking/stored procedures acceptance",
            "authenticated production service API acceptance",
            "Core durable INTENT/reconciliation for production GENESIS",
            "owner lifecycle and recovery ceremonies",
        ],
    }


def build_activation_dry_run(
    *,
    target: ProductionTargetContract,
    observation: TargetReadOnlyObservation,
    intent: SignedMigrationIntent,
    approval: OwnerApproval | None,
    evidence_refs: list[str],
    now: datetime | None = None,
) -> ActivationDryRunResult:
    validate_signed_migration_intent(intent, now=now)
    validate_target_observation(target, observation)
    validate_owner_approval(approval=approval, target=target, intent=intent)
    decision = production_authority_decision()
    if decision["decision"] != "EXISTS_AND_REUSABLE":
        raise CoreError("B2_PRODUCTION_AUTHORITY_BLOCKED")
    # This branch is intentionally unreachable in Batch01 until production
    # authority is accepted. It documents deterministic plan construction only.
    return _build_activation_plan(target=target, observation=observation, intent=intent,
                                  approval=approval, evidence_refs=evidence_refs)


def build_activation_plan_without_execution(
    *,
    target: ProductionTargetContract,
    observation: TargetReadOnlyObservation,
    intent: SignedMigrationIntent,
    approval: OwnerApproval,
    evidence_refs: list[str],
) -> ActivationDryRunResult:
    """Build a deterministic review artifact after individual gates are checked.

    This helper still performs no production mutation and does not override the
    production-authority blocker. It is used to freeze the planned sequence for
    independent review while final execution remains blocked.
    """
    validate_target_observation(target, observation)
    validate_owner_approval(approval=approval, target=target, intent=intent)
    return _build_activation_plan(target=target, observation=observation, intent=intent,
                                  approval=approval, evidence_refs=evidence_refs)


def _build_activation_plan(
    *,
    target: ProductionTargetContract,
    observation: TargetReadOnlyObservation,
    intent: SignedMigrationIntent,
    approval: OwnerApproval,
    evidence_refs: list[str],
) -> ActivationDryRunResult:
    candidate_hash = activation_candidate_hash(target=target, intent=intent)
    base = {
        "schema_version": B2_PLAN_SCHEMA_VERSION,
        "status": "DRY_RUN_READY",
        "source_checkpoint": B1_FOUNDATION_CHECKPOINT_COMMIT,
        "source_tag": B1_FOUNDATION_CHECKPOINT_TAG,
        "activation_candidate_hash": candidate_hash,
        "target_reference": target.target_reference,
        "current_target_state": observation.model_dump(mode="json"),
        "required_target_state": {
            "schema_state": target.expected_pre_activation_state,
            "durable_genesis_present": False,
            "migration_version": target.migration_version,
        },
        "migration_intent_hash": intent.canonical_payload_hash,
        "owner_approval_required": True,
        "authority_mode": "PRODUCTION_AUTHORITY_REQUIRED",
        "trust_refs": {
            "authority_trust_reference": intent.authority_trust_reference,
            "signer_trust_reference": target.signer_trust_reference,
            "owner_approval_reference": approval.approval_reference,
        },
        "ordered_activation_steps": [
            "verify reviewed commit and tag",
            "verify signed migration intent",
            "verify owner approval",
            "verify target pre-GENESIS state",
            "acquire activation lock",
            "execute production GENESIS only after explicit owner execution authorization",
            "verify durable GENESIS result",
            "run production acceptance checks",
        ],
        "preconditions": production_genesis_preconditions(),
        "postconditions": production_acceptance_checks(),
        "rollback_recovery_semantics": "AFTER_DURABLE_GENESIS_RECOVERY_OR_CONTINUATION_ONLY",
        "irreversible_boundary": "DURABLE_PRODUCTION_GENESIS_COMMIT",
        "evidence_refs": evidence_refs,
        "planned_mutations": 0,
        "dry_run_read_only": True,
    }
    base["plan_hash"] = sha256_hex(base)
    return ActivationDryRunResult(**base)


def production_genesis_preconditions() -> list[str]:
    return [
        "target identity matches expected target",
        "database is expected pre-GENESIS state",
        "no previous durable GENESIS",
        "schema/migration compatible",
        "authority/trust material validated",
        "Signed Migration Intent valid",
        "owner approval valid",
        "implementation commit/tag match",
        "no unexpected dirty deployment artifact",
        "recovery/backup prerequisites available",
        "activation lock acquired",
        "audit sink available",
        "clock/expiry checks valid",
    ]


def production_acceptance_checks() -> list[str]:
    return [
        "durable identity verify",
        "continuity verify",
        "generation verify",
        "state_version verify",
        "audit verify",
        "authorization verify",
        "restart verify",
        "Core Read Model verify",
        "minimal backup/recovery acceptance",
        "no second identity",
        "no rehearsal identity bleed",
    ]

