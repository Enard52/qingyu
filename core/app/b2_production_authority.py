from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Callable
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.exc import IntegrityError

from .b2_activation_readiness import (
    B1_FOUNDATION_CHECKPOINT_COMMIT,
    B1_FOUNDATION_CHECKPOINT_TAG,
    OwnerApproval,
    ProductionTargetContract,
    SignedMigrationIntent,
    TargetReadOnlyObservation,
    activation_candidate_hash,
    build_activation_plan_without_execution,
    reject_rehearsal_artifact_reuse,
    validate_owner_approval,
    validate_signed_migration_intent,
    validate_target_observation,
)
from .canonical import sha256_hex
from .errors import CoreError

SYNTHETIC_PRODUCTION_TEST = "SYNTHETIC_PRODUCTION_TEST"
PRODUCTION_AUTHORITY_SCHEMA_VERSION = "qingyu-b2-production-authority-candidate-v1"
PRODUCTION_AUTHORITY_ENVIRONMENT_CLASS = "synthetic-production-test"
EXPECTED_RESERVATION_CONSTRAINTS = {
    "b2_production_authority_domains_pkey",
    "b2_production_authority_attempts_pkey",
}


class ProductionAuthorityState(StrEnum):
    PRE_GENESIS = "PRE_GENESIS"
    GENESIS_RESERVED = "GENESIS_RESERVED"
    GENESIS_DURABLE = "GENESIS_DURABLE"
    RECOVERY_QUARANTINED = "RECOVERY_QUARANTINED"
    ACTIVE = "ACTIVE"


@dataclass(frozen=True, slots=True)
class ProductionAuthorityGenesisResult:
    attempt_id: str
    state: ProductionAuthorityState
    trust_domain_id: str
    qingyu_identity_id: str
    continuity_id: str
    storage_generation_id: str
    recovery_epoch: int
    governed_state_version: int
    activation_candidate_hash: str
    audit_hash: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "attempt_id": self.attempt_id,
            "state": self.state.value if isinstance(self.state, ProductionAuthorityState) else self.state,
            "trust_domain_id": self.trust_domain_id,
            "qingyu_identity_id": self.qingyu_identity_id,
            "continuity_id": self.continuity_id,
            "storage_generation_id": self.storage_generation_id,
            "recovery_epoch": self.recovery_epoch,
            "governed_state_version": self.governed_state_version,
            "activation_candidate_hash": self.activation_candidate_hash,
            "audit_hash": self.audit_hash,
        }


class ProductionAuthorityStore:
    """Explicit durable production-authority candidate store.

    The store is intended for isolated synthetic production-like tests in B2
    readiness. It uses versioned JSON/relational fields and never serializes a
    Python object graph. It is not a real deployed production authority instance.
    """

    def __init__(self, sqlalchemy_url: str):
        self.sqlalchemy_url = sqlalchemy_url
        self.engine = create_engine(sqlalchemy_url, pool_pre_ping=True)
        self.ensure_schema()

    def ensure_schema(self) -> None:
        with self.engine.begin() as connection:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS b2_production_authority_domains (
                    environment_identity TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    authority_version INTEGER NOT NULL,
                    environment_class TEXT NOT NULL,
                    state TEXT NOT NULL,
                    target_reference TEXT NOT NULL,
                    trust_reference TEXT NOT NULL,
                    source_checkpoint TEXT NOT NULL,
                    source_tag TEXT NOT NULL,
                    activation_candidate_hash TEXT,
                    intent_hash TEXT,
                    owner_approval_hash TEXT,
                    attempt_id TEXT,
                    trust_domain_id TEXT,
                    qingyu_identity_id TEXT,
                    continuity_id TEXT,
                    storage_generation_id TEXT,
                    recovery_epoch INTEGER NOT NULL DEFAULT 0,
                    governed_state_version INTEGER NOT NULL DEFAULT 0,
                    last_checkpoint_hash TEXT,
                    last_recovery_anchor_hash TEXT,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS b2_production_authority_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    environment_identity TEXT NOT NULL REFERENCES b2_production_authority_domains(environment_identity),
                    activation_candidate_hash TEXT NOT NULL,
                    intent_hash TEXT NOT NULL,
                    owner_approval_hash TEXT NOT NULL,
                    target_reference TEXT NOT NULL,
                    trust_reference TEXT NOT NULL,
                    status TEXT NOT NULL,
                    request_binding_hash TEXT NOT NULL,
                    result_payload TEXT,
                    result_hash TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS b2_production_authority_audit (
                    audit_id BIGSERIAL PRIMARY KEY,
                    environment_identity TEXT NOT NULL,
                    attempt_id TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    state_before TEXT,
                    state_after TEXT NOT NULL,
                    intent_hash TEXT NOT NULL,
                    owner_approval_hash TEXT NOT NULL,
                    activation_candidate_hash TEXT NOT NULL,
                    target_reference TEXT NOT NULL,
                    trust_reference TEXT NOT NULL,
                    payload_hash TEXT NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))

    def counts_and_hash(self) -> dict[str, Any]:
        with self.engine.begin() as connection:
            domains = [dict(row) for row in connection.execute(text("SELECT * FROM b2_production_authority_domains ORDER BY environment_identity")).mappings()]
            attempts = [dict(row) for row in connection.execute(text("SELECT * FROM b2_production_authority_attempts ORDER BY attempt_id")).mappings()]
            audit = [dict(row) for row in connection.execute(text("SELECT environment_identity, attempt_id, event_type, state_before, state_after, intent_hash, owner_approval_hash, activation_candidate_hash, target_reference, trust_reference, payload_hash FROM b2_production_authority_audit ORDER BY audit_id")).mappings()]
        payload = {"domains": domains, "attempts": attempts, "audit": audit}
        return {
            "domain_count": len(domains),
            "attempt_count": len(attempts),
            "audit_count": len(audit),
            "canonical_hash": sha256_hex(payload),
        }


class ProductionAuthorityCandidate:
    def __init__(self, store: ProductionAuthorityStore, *, reservation_race_hook: Callable[[], None] | None = None):
        self.store = store
        self._reservation_race_hook = reservation_race_hook

    @property
    def schema_version(self) -> str:
        return PRODUCTION_AUTHORITY_SCHEMA_VERSION

    def _owner_approval_hash(self, approval: OwnerApproval) -> str:
        return sha256_hex(approval.model_dump(mode="json"))

    def _request_binding_hash(
        self,
        *,
        target: ProductionTargetContract,
        observation: TargetReadOnlyObservation,
        intent: SignedMigrationIntent,
        approval: OwnerApproval,
        attempt_id: str,
    ) -> str:
        return sha256_hex({
            "attempt_id": attempt_id,
            "target": target.model_dump(mode="json"),
            "observation": observation.model_dump(mode="json"),
            "intent_hash": intent.canonical_payload_hash,
            "approval_hash": self._owner_approval_hash(approval),
            "activation_candidate_hash": activation_candidate_hash(target=target, intent=intent),
        })

    def _validate_all(
        self,
        *,
        target: ProductionTargetContract,
        observation: TargetReadOnlyObservation,
        intent: SignedMigrationIntent,
        approval: OwnerApproval | None,
        attempt_id: str,
        now: datetime | None = None,
    ) -> OwnerApproval:
        if target.environment_identity != SYNTHETIC_PRODUCTION_TEST:
            raise CoreError("B2_SYNTHETIC_PRODUCTION_MARKER_REQUIRED")
        if target.environment_class != "production":
            raise CoreError("B2_PRODUCTION_TARGET_CONTRACT_REQUIRED")
        reject_rehearsal_artifact_reuse({
            "target": target.model_dump(mode="json"),
            "observation": observation.model_dump(mode="json"),
            "intent": intent.model_dump(mode="json"),
            "approval": approval.model_dump(mode="json") if approval else None,
        })
        validate_signed_migration_intent(intent, now=now)
        validate_target_observation(target, observation)
        validate_owner_approval(approval=approval, target=target, intent=intent)
        assert approval is not None
        if not attempt_id or len(attempt_id) > 128:
            raise CoreError("B2_ACTIVATION_ATTEMPT_INVALID")
        if intent.authority_trust_reference != target.signer_trust_reference:
            raise CoreError("B2_TRUST_REFERENCE_MISMATCH")
        return approval

    def reserve_genesis(
        self,
        *,
        target: ProductionTargetContract,
        observation: TargetReadOnlyObservation,
        intent: SignedMigrationIntent,
        approval: OwnerApproval | None,
        attempt_id: str,
        now: datetime | None = None,
        simulate_failure_before_commit: bool = False,
    ) -> dict[str, Any]:
        approval = self._validate_all(target=target, observation=observation, intent=intent,
                                      approval=approval, attempt_id=attempt_id, now=now)
        if simulate_failure_before_commit:
            raise CoreError("B2_SIMULATED_FAILURE_BEFORE_COMMIT")
        candidate_hash = activation_candidate_hash(target=target, intent=intent)
        owner_hash = self._owner_approval_hash(approval)
        binding_hash = self._request_binding_hash(target=target, observation=observation, intent=intent,
                                                  approval=approval, attempt_id=attempt_id)
        try:
            with self.store.engine.begin() as connection:
                return self._reserve_genesis_transaction(
                    connection=connection,
                    target=target,
                    intent=intent,
                    attempt_id=attempt_id,
                    candidate_hash=candidate_hash,
                    owner_hash=owner_hash,
                    binding_hash=binding_hash,
                )
        except IntegrityError as exc:
            if not self._is_expected_reservation_integrity_error(exc):
                raise
            return self._resolve_reservation_conflict(
                target=target,
                attempt_id=attempt_id,
                candidate_hash=candidate_hash,
                binding_hash=binding_hash,
                original_error=exc,
            )

    def _reserve_genesis_transaction(
        self,
        *,
        connection: Any,
        target: ProductionTargetContract,
        intent: SignedMigrationIntent,
        attempt_id: str,
        candidate_hash: str,
        owner_hash: str,
        binding_hash: str,
    ) -> dict[str, Any]:
        domain = connection.execute(text("""
            SELECT * FROM b2_production_authority_domains
            WHERE environment_identity = :environment_identity
            FOR UPDATE
        """), {"environment_identity": target.environment_identity}).mappings().first()
        if domain is not None:
            if domain["activation_candidate_hash"] == candidate_hash and domain["attempt_id"] == attempt_id:
                attempt = connection.execute(text("SELECT * FROM b2_production_authority_attempts WHERE attempt_id = :attempt_id FOR UPDATE"), {"attempt_id": attempt_id}).mappings().first()
                if attempt is None or attempt["request_binding_hash"] != binding_hash:
                    raise CoreError("B2_ACTIVATION_ATTEMPT_CONFLICT")
                return dict(attempt)
            raise CoreError("B2_ACTIVATION_ATTEMPT_CONFLICT")
        if self._reservation_race_hook is not None:
            self._reservation_race_hook()
        connection.execute(text("""
            INSERT INTO b2_production_authority_domains (
                environment_identity, schema_version, authority_version, environment_class, state,
                target_reference, trust_reference, source_checkpoint, source_tag,
                activation_candidate_hash, intent_hash, owner_approval_hash, attempt_id
            ) VALUES (
                :environment_identity, :schema_version, 1, :environment_class, :state,
                :target_reference, :trust_reference, :source_checkpoint, :source_tag,
                :activation_candidate_hash, :intent_hash, :owner_approval_hash, :attempt_id
            )
        """), {
            "environment_identity": target.environment_identity,
            "schema_version": PRODUCTION_AUTHORITY_SCHEMA_VERSION,
            "environment_class": PRODUCTION_AUTHORITY_ENVIRONMENT_CLASS,
            "state": ProductionAuthorityState.GENESIS_RESERVED.value,
            "target_reference": target.target_reference,
            "trust_reference": target.signer_trust_reference,
            "source_checkpoint": B1_FOUNDATION_CHECKPOINT_COMMIT,
            "source_tag": B1_FOUNDATION_CHECKPOINT_TAG,
            "activation_candidate_hash": candidate_hash,
            "intent_hash": intent.canonical_payload_hash,
            "owner_approval_hash": owner_hash,
            "attempt_id": attempt_id,
        })
        connection.execute(text("""
            INSERT INTO b2_production_authority_attempts (
                attempt_id, environment_identity, activation_candidate_hash, intent_hash,
                owner_approval_hash, target_reference, trust_reference, status, request_binding_hash
            ) VALUES (
                :attempt_id, :environment_identity, :activation_candidate_hash, :intent_hash,
                :owner_approval_hash, :target_reference, :trust_reference, :status, :request_binding_hash
            )
        """), {
            "attempt_id": attempt_id,
            "environment_identity": target.environment_identity,
            "activation_candidate_hash": candidate_hash,
            "intent_hash": intent.canonical_payload_hash,
            "owner_approval_hash": owner_hash,
            "target_reference": target.target_reference,
            "trust_reference": target.signer_trust_reference,
            "status": ProductionAuthorityState.GENESIS_RESERVED.value,
            "request_binding_hash": binding_hash,
        })
        payload_hash = sha256_hex({"attempt_id": attempt_id, "binding_hash": binding_hash})
        connection.execute(text("""
            INSERT INTO b2_production_authority_audit (
                environment_identity, attempt_id, event_type, state_before, state_after,
                intent_hash, owner_approval_hash, activation_candidate_hash,
                target_reference, trust_reference, payload_hash
            ) VALUES (
                :environment_identity, :attempt_id, 'GENESIS_RESERVED', 'PRE_GENESIS', 'GENESIS_RESERVED',
                :intent_hash, :owner_approval_hash, :activation_candidate_hash,
                :target_reference, :trust_reference, :payload_hash
            )
        """), {
            "environment_identity": target.environment_identity,
            "attempt_id": attempt_id,
            "intent_hash": intent.canonical_payload_hash,
            "owner_approval_hash": owner_hash,
            "activation_candidate_hash": candidate_hash,
            "target_reference": target.target_reference,
            "trust_reference": target.signer_trust_reference,
            "payload_hash": payload_hash,
        })
        attempt = connection.execute(text("SELECT * FROM b2_production_authority_attempts WHERE attempt_id = :attempt_id"), {"attempt_id": attempt_id}).mappings().first()
        assert attempt is not None
        return dict(attempt)

    def _is_expected_reservation_integrity_error(self, exc: IntegrityError) -> bool:
        orig = getattr(exc, "orig", None)
        sqlstate = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
        diag = getattr(orig, "diag", None)
        constraint = getattr(diag, "constraint_name", None)
        return sqlstate == "23505" and constraint in EXPECTED_RESERVATION_CONSTRAINTS

    def _resolve_reservation_conflict(
        self,
        *,
        target: ProductionTargetContract,
        attempt_id: str,
        candidate_hash: str,
        binding_hash: str,
        original_error: IntegrityError,
    ) -> dict[str, Any]:
        with self.store.engine.begin() as connection:
            domain = connection.execute(text("""
                SELECT * FROM b2_production_authority_domains
                WHERE environment_identity = :environment_identity
                FOR UPDATE
            """), {"environment_identity": target.environment_identity}).mappings().first()
            if domain is None:
                raise original_error
            if domain["activation_candidate_hash"] != candidate_hash or domain["attempt_id"] != attempt_id:
                raise CoreError("B2_ACTIVATION_ATTEMPT_CONFLICT") from None
            attempt = connection.execute(text("SELECT * FROM b2_production_authority_attempts WHERE attempt_id = :attempt_id FOR UPDATE"), {"attempt_id": attempt_id}).mappings().first()
            if attempt is None or attempt["request_binding_hash"] != binding_hash:
                raise CoreError("B2_ACTIVATION_ATTEMPT_CONFLICT") from None
            return dict(attempt)

    def commit_genesis(
        self,
        *,
        target: ProductionTargetContract,
        observation: TargetReadOnlyObservation,
        intent: SignedMigrationIntent,
        approval: OwnerApproval | None,
        attempt_id: str,
        now: datetime | None = None,
        simulate_failure_after_commit: bool = False,
    ) -> ProductionAuthorityGenesisResult:
        approval = self._validate_all(target=target, observation=observation, intent=intent,
                                      approval=approval, attempt_id=attempt_id, now=now)
        candidate_hash = activation_candidate_hash(target=target, intent=intent)
        owner_hash = self._owner_approval_hash(approval)
        binding_hash = self._request_binding_hash(target=target, observation=observation, intent=intent,
                                                  approval=approval, attempt_id=attempt_id)
        with self.store.engine.begin() as connection:
            domain = connection.execute(text("""
                SELECT * FROM b2_production_authority_domains
                WHERE environment_identity = :environment_identity
                FOR UPDATE
            """), {"environment_identity": target.environment_identity}).mappings().first()
            if domain is None:
                # Explicit transaction boundary: reservation is created inside
                # this durable command only after all validation completed.
                self.reserve_genesis(target=target, observation=observation, intent=intent,
                                     approval=approval, attempt_id=attempt_id, now=now)
                domain = connection.execute(text("""
                    SELECT * FROM b2_production_authority_domains
                    WHERE environment_identity = :environment_identity
                    FOR UPDATE
                """), {"environment_identity": target.environment_identity}).mappings().first()
            assert domain is not None
            if domain["attempt_id"] != attempt_id or domain["activation_candidate_hash"] != candidate_hash:
                raise CoreError("B2_ACTIVATION_ATTEMPT_CONFLICT")
            attempt = connection.execute(text("SELECT * FROM b2_production_authority_attempts WHERE attempt_id = :attempt_id FOR UPDATE"), {"attempt_id": attempt_id}).mappings().first()
            if attempt is None or attempt["request_binding_hash"] != binding_hash:
                raise CoreError("B2_ACTIVATION_ATTEMPT_CONFLICT")
            if attempt["status"] == ProductionAuthorityState.GENESIS_DURABLE.value:
                result_payload = json_loads(attempt["result_payload"])
                return ProductionAuthorityGenesisResult(**result_payload)
            if attempt["status"] != ProductionAuthorityState.GENESIS_RESERVED.value:
                raise CoreError("B2_AUTHORITY_STATE_INVALID")
            result = ProductionAuthorityGenesisResult(
                attempt_id=attempt_id,
                state=ProductionAuthorityState.GENESIS_DURABLE,
                trust_domain_id=str(uuid.uuid5(uuid.NAMESPACE_URL, candidate_hash + ":trust-domain")),
                qingyu_identity_id=str(uuid.uuid5(uuid.NAMESPACE_URL, candidate_hash + ":identity")),
                continuity_id=str(uuid.uuid5(uuid.NAMESPACE_URL, candidate_hash + ":continuity")),
                storage_generation_id=str(uuid.uuid5(uuid.NAMESPACE_URL, candidate_hash + ":storage")),
                recovery_epoch=0,
                governed_state_version=1,
                activation_candidate_hash=candidate_hash,
                audit_hash=sha256_hex({"attempt_id": attempt_id, "candidate_hash": candidate_hash, "event": "GENESIS_DURABLE"}),
            )
            result_payload = json_dumps(result.as_dict())
            result_hash = sha256_hex(result.as_dict())
            checkpoint_hash = sha256_hex({"state": result.as_dict(), "schema_version": PRODUCTION_AUTHORITY_SCHEMA_VERSION})
            connection.execute(text("""
                UPDATE b2_production_authority_domains SET
                    authority_version = authority_version + 1,
                    state = :state,
                    trust_domain_id = :trust_domain_id,
                    qingyu_identity_id = :qingyu_identity_id,
                    continuity_id = :continuity_id,
                    storage_generation_id = :storage_generation_id,
                    recovery_epoch = :recovery_epoch,
                    governed_state_version = :governed_state_version,
                    last_checkpoint_hash = :last_checkpoint_hash,
                    updated_at = now()
                WHERE environment_identity = :environment_identity
            """), {
                "state": ProductionAuthorityState.GENESIS_DURABLE.value,
                "trust_domain_id": result.trust_domain_id,
                "qingyu_identity_id": result.qingyu_identity_id,
                "continuity_id": result.continuity_id,
                "storage_generation_id": result.storage_generation_id,
                "recovery_epoch": result.recovery_epoch,
                "governed_state_version": result.governed_state_version,
                "last_checkpoint_hash": checkpoint_hash,
                "environment_identity": target.environment_identity,
            })
            connection.execute(text("""
                UPDATE b2_production_authority_attempts SET
                    status = :status,
                    result_payload = :result_payload,
                    result_hash = :result_hash,
                    updated_at = now()
                WHERE attempt_id = :attempt_id
            """), {
                "status": ProductionAuthorityState.GENESIS_DURABLE.value,
                "result_payload": result_payload,
                "result_hash": result_hash,
                "attempt_id": attempt_id,
            })
            connection.execute(text("""
                INSERT INTO b2_production_authority_audit (
                    environment_identity, attempt_id, event_type, state_before, state_after,
                    intent_hash, owner_approval_hash, activation_candidate_hash,
                    target_reference, trust_reference, payload_hash
                ) VALUES (
                    :environment_identity, :attempt_id, 'GENESIS_DURABLE', 'GENESIS_RESERVED', 'GENESIS_DURABLE',
                    :intent_hash, :owner_approval_hash, :activation_candidate_hash,
                    :target_reference, :trust_reference, :payload_hash
                )
            """), {
                "environment_identity": target.environment_identity,
                "attempt_id": attempt_id,
                "intent_hash": intent.canonical_payload_hash,
                "owner_approval_hash": owner_hash,
                "activation_candidate_hash": candidate_hash,
                "target_reference": target.target_reference,
                "trust_reference": target.signer_trust_reference,
                "payload_hash": result_hash,
            })
        if simulate_failure_after_commit:
            raise CoreError("B2_SIMULATED_RESPONSE_LOSS_AFTER_DURABLE_COMMIT")
        return result

    def export_state(self, environment_identity: str) -> dict[str, Any] | None:
        with self.store.engine.begin() as connection:
            row = connection.execute(text("""
                SELECT * FROM b2_production_authority_domains
                WHERE environment_identity = :environment_identity
            """), {"environment_identity": environment_identity}).mappings().first()
        return dict(row) if row is not None else None

    def build_read_only_plan(
        self,
        *,
        target: ProductionTargetContract,
        observation: TargetReadOnlyObservation,
        intent: SignedMigrationIntent,
        approval: OwnerApproval,
        evidence_refs: list[str],
    ):
        return build_activation_plan_without_execution(target=target, observation=observation,
                                                       intent=intent, approval=approval,
                                                       evidence_refs=evidence_refs)


def json_dumps(value: dict[str, Any]) -> str:
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def json_loads(value: str | None) -> dict[str, Any]:
    import json
    if value is None:
        raise CoreError("B2_AUTHORITY_RESULT_MISSING")
    return json.loads(value)

