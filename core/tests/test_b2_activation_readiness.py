from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.b2_activation_readiness import (
    B1_FOUNDATION_CHECKPOINT_COMMIT,
    B1_FOUNDATION_CHECKPOINT_TAG,
    B2ActivationState,
    ActivationAttemptGuard,
    OwnerApproval,
    ProductionTargetContract,
    SignedMigrationIntent,
    TargetReadOnlyObservation,
    activation_candidate_hash,
    build_activation_dry_run,
    build_activation_plan_without_execution,
    production_acceptance_checks,
    production_authority_decision,
    reject_rehearsal_artifact_reuse,
    validate_owner_approval,
    validate_signed_migration_intent,
    validate_state_transition,
    validate_target_observation,
)
from app.errors import CoreError
from app.b2_signer_trust import (
    AuthorityEnvironmentMode,
    EncryptedFileBackedEd25519SignerProvider,
    InMemoryEd25519SignerProvider,
    PRODUCTION_PERMISSION_POLICY,
    PRODUCTION_STORAGE_POLICY,
    PRODUCTION_WSL_ROOTFS_STORAGE_POLICY,
    ProductionSignerAdmissionRecord,
    ProductionSignerAdmissionStatus,
    ProductionSignerAdmissionStore,
    ProductionSignerStorageAttestation,
    ProductionSignerStorageAttestationStore,
    ProductionSignerStorageClass,
    ProductionSignerStorageInspectionResult,
    ProductionSignerStorageInspector,
    SignerProviderClassification,
    TrustRecord,
    TrustStore,
    sign_smi_payload,
)
from app.foundation_rehearsal import REHEARSAL_ENVIRONMENT, assert_rehearsal_genesis_request
from app.schemas import GenesisRequest
import uuid

NOW = datetime.now(timezone.utc)
_TEST_TRUST_CACHE = {}


def signed_test_trust(
    *,
    trust_reference: str = "production-root-trust-ref-001",
    environment: str = "qingyu-production-primary",
    target_reference: str = "prod-target-ref-001",
    classification: SignerProviderClassification = SignerProviderClassification.TEST_ONLY,
):
    cache_key = (trust_reference, environment, target_reference, classification.value)
    if cache_key not in _TEST_TRUST_CACHE:
        provider = InMemoryEd25519SignerProvider(
            provider_reference=f"test-provider:{trust_reference}",
            private_key=Ed25519PrivateKey.generate(),
            classification=classification,
        )
        record = TrustRecord.from_provider(
            trust_reference=trust_reference,
            provider=provider,
            environment=environment,
            target_reference=target_reference,
            generation=1,
            created_at=NOW,
        )
        _TEST_TRUST_CACHE[cache_key] = (provider, record)
    provider, record = _TEST_TRUST_CACHE[cache_key]
    return TrustStore({trust_reference: record}), provider, record


def _sign_intent_data(data: dict, provider: InMemoryEd25519SignerProvider) -> dict:
    placeholder = dict(data)
    placeholder["signature_metadata"] = {"signature_ref": "test-signature-reference", "signature": "0" * 128}
    payload = SignedMigrationIntent(**placeholder).canonical_payload()
    signed = dict(data)
    signed["signature_metadata"] = {
        **signed.get("signature_metadata", {}),
        "signature_ref": signed.get("signature_metadata", {}).get("signature_ref", "test-signature-reference"),
        "signature": sign_smi_payload(provider, payload),
    }
    return signed



def real_file_backed_signer_fixture(tmp_path):
    key_path = "//wsl.localhost/qingyu-prod-local-01/etc/qingyu/secrets/production-signer/qingyu-prod-signer-01.pem"
    passphrase_path = "//wsl.localhost/qingyu-prod-local-01/etc/qingyu/secrets/production-signer/qingyu-prod-signer-01.passphrase"
    provider = EncryptedFileBackedEd25519SignerProvider(
        provider_reference="qingyu-prod-signer-01",
        encrypted_private_key_path=key_path,
        passphrase_provider=lambda: Path(passphrase_path).read_bytes().strip(),
        classification=SignerProviderClassification.PRODUCTION_ELIGIBLE,
    )
    record = TrustRecord.from_provider(
        trust_reference="production-root-trust-ref-001",
        provider=provider,
        environment="qingyu-production-primary",
        target_reference="prod-target-ref-001",
        generation=1,
        created_at=NOW,
    )
    admission = ProductionSignerAdmissionRecord(
        admission_reference="ephemeral-real-production-admission-fixture",
        provider_reference=record.provider_reference,
        provider_backend_type=record.provider_backend_type,
        algorithm=record.algorithm,
        key_id=record.key_id,
        public_key_fingerprint=record.public_key_fingerprint,
        environment=record.environment,
        target_reference=record.target_reference,
        storage_policy=PRODUCTION_WSL_ROOTFS_STORAGE_POLICY,
        storage_class=ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value,
        permission_policy=PRODUCTION_PERMISSION_POLICY,
        custody_policy_version="ephemeral-test-custody-policy-v1",
        provisioning_reference="ephemeral-test-fixture-not-real-admission-record",
        provisioning_generation=1,
        status=ProductionSignerAdmissionStatus.ACTIVE,
        created_at=NOW,
    )
    return TrustStore({record.trust_reference: record}), provider, record, ProductionSignerAdmissionStore({admission.admission_reference: admission})


def real_signed_intent(provider, record):
    data = {
        "intent_id": "real-path-threading-intent",
        "target_environment": "qingyu-production-primary",
        "target_reference": "prod-target-ref-001",
        "source_checkpoint": B1_FOUNDATION_CHECKPOINT_COMMIT,
        "source_tag": B1_FOUNDATION_CHECKPOINT_TAG,
        "target_schema_migration_version": "r1-control-plane-initial-v1",
        "authority_trust_reference": record.trust_reference,
        "requested_operation": "PRODUCTION_GENESIS",
        "expected_preconditions": ["no previous durable GENESIS", "owner approval valid"],
        "expected_genesis_behavior": "DURABLE_ONCE_THEN_CONTINUATION_ONLY",
        "valid_from": NOW - timedelta(minutes=5),
        "expires_at": NOW + timedelta(hours=1),
        "owner_approval_reference": "owner-approval-ref-required",
        "signer_key_id": record.key_id,
        "signature_metadata": {"signature_ref": "real-path-test-signature", "signature": "0" * 128},
    }
    placeholder = SignedMigrationIntent(**data)
    data["signature_metadata"] = {"signature_ref": "real-path-test-signature", "signature": sign_smi_payload(provider, placeholder.canonical_payload())}
    return SignedMigrationIntent(**data)


def target(**updates):
    data = {
        "target_reference": "prod-target-ref-001",
        "environment_identity": "qingyu-production-primary",
        "environment_class": "production",
        "host_reference": "prod-db-host-fingerprint-001",
        "database_reference": "prod-db-reference-001",
        "postgres_version_major": 16,
        "schema_owner_reference": "control-plane-owner-ref",
        "expected_pre_activation_state": "EMPTY_PRE_GENESIS",
        "migration_version": "r1-control-plane-initial-v1",
        "allowed_network_boundary": "owner-approved-production-network-ref",
        "backup_recovery_reference": "owner-approved-backup-ref",
        "signer_trust_reference": "production-root-trust-ref-001",
        "authority_reference": "production-authority-ref-001",
        "audit_destination_reference": "production-audit-sink-ref-001",
        "activation_lock_reference": "production-activation-lock-ref-001",
        "expected_commit": B1_FOUNDATION_CHECKPOINT_COMMIT,
        "expected_tag": B1_FOUNDATION_CHECKPOINT_TAG,
    }
    data.update(updates)
    return ProductionTargetContract(**data)


def intent(**updates):
    data = {
        "intent_id": "intent-001",
        "target_environment": "qingyu-production-primary",
        "target_reference": "prod-target-ref-001",
        "source_checkpoint": B1_FOUNDATION_CHECKPOINT_COMMIT,
        "source_tag": B1_FOUNDATION_CHECKPOINT_TAG,
        "target_schema_migration_version": "r1-control-plane-initial-v1",
        "authority_trust_reference": "production-root-trust-ref-001",
        "requested_operation": "PRODUCTION_GENESIS",
        "expected_preconditions": ["no previous durable GENESIS", "owner approval valid"],
        "expected_genesis_behavior": "DURABLE_ONCE_THEN_CONTINUATION_ONLY",
        "valid_from": NOW - timedelta(minutes=5),
        "expires_at": NOW + timedelta(hours=1),
        "owner_approval_reference": "owner-approval-ref-required",
        "signature_metadata": {"signature_ref": "owner-signature-reference"},
    }
    data.update(updates)
    signer_key_id_overridden = "signer_key_id" in updates
    store, provider, record = signed_test_trust(
        trust_reference=data["authority_trust_reference"],
        environment=data["target_environment"],
        target_reference=data["target_reference"],
    )
    data["signer_key_id"] = data.get("signer_key_id", record.key_id)
    if "signature_metadata" not in updates or "signature" not in data["signature_metadata"]:
        signing_data = dict(data)
        if signer_key_id_overridden:
            signing_data["signer_key_id"] = record.key_id
        data = _sign_intent_data(signing_data, provider) | {"signer_key_id": data["signer_key_id"]}
    return SignedMigrationIntent(**data)


def observation(**updates):
    data = {
        "target_reference": "prod-target-ref-001",
        "reachable": True,
        "postgres_version_major": 16,
        "schema_state": "EMPTY_PRE_GENESIS",
        "migration_version": "r1-control-plane-initial-v1",
        "durable_genesis_present": False,
        "authority_trust_reference": "production-root-trust-ref-001",
        "backup_recovery_available": True,
        "audit_sink_available": True,
        "activation_lock_available": True,
        "observed_at": NOW,
    }
    data.update(updates)
    return TargetReadOnlyObservation(**data)


def approval(t=None, i=None, **updates):
    t = t or target()
    i = i or intent()
    data = {
        "approval_id": "approval-001",
        "approval_state": "OWNER_APPROVED",
        "activation_candidate_hash": activation_candidate_hash(target=t, intent=i),
        "target_reference": t.target_reference,
        "migration_intent_hash": i.canonical_payload_hash,
        "authority_trust_reference": i.authority_trust_reference,
        "source_checkpoint": B1_FOUNDATION_CHECKPOINT_COMMIT,
        "source_tag": B1_FOUNDATION_CHECKPOINT_TAG,
        "approved_at": NOW,
        "approval_reference": "owner-explicit-approval-reference",
    }
    data.update(updates)
    return OwnerApproval(**data)


def test_state_machine_requires_review_and_owner_before_execution():
    validate_state_transition(B2ActivationState.B1_CLOSED, B2ActivationState.B2_PREPARATION)
    validate_state_transition(B2ActivationState.PRE_ACTIVATION_READY, B2ActivationState.INDEPENDENT_REVIEW_PASS)
    validate_state_transition(B2ActivationState.INDEPENDENT_REVIEW_PASS, B2ActivationState.OWNER_APPROVED)
    with pytest.raises(CoreError, match="B2_STATE_TRANSITION_INVALID"):
        validate_state_transition(B2ActivationState.B1_CLOSED, B2ActivationState.ACTIVATION_EXECUTING)


def test_target_contract_and_commit_tag_binding():
    t = target()
    assert t.expected_commit == B1_FOUNDATION_CHECKPOINT_COMMIT
    with pytest.raises(CoreError, match="B2_WRONG_IMPLEMENTATION_COMMIT"):
        target(expected_commit="0" * 40)
    with pytest.raises(CoreError, match="B2_WRONG_IMPLEMENTATION_TAG"):
        target(expected_tag="wrong-tag")


def test_signed_migration_intent_hash_and_negative_cases():
    i = intent()
    assert len(i.canonical_payload_hash) == 64
    validate_signed_migration_intent(i, now=NOW, trust_store=signed_test_trust()[0])
    changed = intent(intent_id="intent-002")
    assert changed.canonical_payload_hash != i.canonical_payload_hash
    with pytest.raises(CoreError, match="B2_INTENT_NOT_VALID_NOW"):
        validate_signed_migration_intent(intent(valid_from=NOW - timedelta(hours=2), expires_at=NOW - timedelta(hours=1)), now=NOW, trust_store=signed_test_trust()[0])
    with pytest.raises(CoreError, match="B2_WRONG_IMPLEMENTATION_TAG"):
        intent(source_tag="wrong-tag")
    with pytest.raises(CoreError, match="B2_REHEARSAL_ARTIFACT_FORBIDDEN"):
        intent(authority_trust_reference="PostgresAuthorityStateStore")
    with pytest.raises(CoreError, match="SMI_SIGNATURE_INVALID"):
        bad = intent(signature_metadata={"signature_ref": "bad", "signature": "1" * 128})
        validate_signed_migration_intent(bad, now=NOW, trust_store=signed_test_trust()[0])
    with pytest.raises(CoreError, match="SMI_SIGNER_KEY_ID_MISMATCH"):
        validate_signed_migration_intent(intent(signer_key_id="0" * 64), now=NOW, trust_store=signed_test_trust()[0])
    with pytest.raises(CoreError, match="SMI_SIGNER_TRUST_NOT_FOUND"):
        validate_signed_migration_intent(i, now=NOW, trust_store=TrustStore())
    for forbidden in ["raw_private_key", "private_key", "private_key_bytes", "seed", "secret_key", "secret_scalar", "passphrase", "unknown"]:
        with pytest.raises(Exception):
            intent(signature_metadata={"signature_ref": "x", "signature": "0" * 128, forbidden: "secret"})


def test_owner_approval_is_independent_gate_and_scope_bound():
    t, i = target(), intent()
    with pytest.raises(CoreError, match="B2_OWNER_APPROVAL_REQUIRED"):
        validate_owner_approval(approval=None, target=t, intent=i)
    validate_owner_approval(approval=approval(t, i), target=t, intent=i)
    wrong = approval(t, i, target_reference="other-target")
    with pytest.raises(CoreError, match="B2_OWNER_APPROVAL_SCOPE_MISMATCH"):
        validate_owner_approval(approval=wrong, target=t, intent=i)


def test_target_preflight_rejects_wrong_target_trust_and_existing_genesis():
    t = target()
    validate_target_observation(t, observation())
    with pytest.raises(CoreError, match="B2_TARGET_MISMATCH"):
        validate_target_observation(t, observation(target_reference="other"))
    with pytest.raises(CoreError, match="B2_TRUST_REFERENCE_MISMATCH"):
        validate_target_observation(t, observation(authority_trust_reference="wrong-trust"))
    with pytest.raises(CoreError, match="B2_DURABLE_GENESIS_ALREADY_PRESENT"):
        validate_target_observation(t, observation(schema_state="GENESIS_PRESENT", durable_genesis_present=True))


def test_rehearsal_artifact_reuse_rejected_and_rehearsal_production_marker_guard_remains():
    with pytest.raises(CoreError, match="B2_REHEARSAL_ARTIFACT_FORBIDDEN"):
        reject_rehearsal_artifact_reuse({"authority": "foundation_rehearsal_authority_state"})
    req = GenesisRequest(
        trust_domain_id=uuid.uuid4(),
        qingyu_identity_id=uuid.uuid4(),
        continuity_id=uuid.uuid4(),
        continuity_alias="qingyu-production",
        genesis_request_id="prod-genesis",
        genesis_nonce="n" * 16,
        initial_owner_fingerprint="f" * 16,
        actor_principal_id="owner",
        governance_provenance={"environment": REHEARSAL_ENVIRONMENT, "production_activated": True, "requires_b2_activation": False},
    )
    with pytest.raises(CoreError, match="FOUNDATION_REHEARSAL_MUST_NOT_ACTIVATE_PRODUCTION"):
        assert_rehearsal_genesis_request(req)


def test_activation_dry_run_is_blocked_by_missing_production_authority():
    t, i, o = target(), intent(), observation()
    a = approval(t, i)
    assert production_authority_decision()["decision"] == "MISSING_AND_BLOCKS_ACTIVATION"
    with pytest.raises(CoreError, match="B2_PRODUCTION_AUTHORITY_BLOCKED"):
        build_activation_dry_run(target=t, observation=o, intent=i, approval=a, evidence_refs=["b1-checkpoint"], now=NOW, trust_store=signed_test_trust()[0])


def test_plan_builder_is_deterministic_and_read_only_for_review_artifact():
    t, i, o = target(), intent(), observation()
    a = approval(t, i)
    trust_store = signed_test_trust()[0]
    first = build_activation_plan_without_execution(target=t, observation=o, intent=i, approval=a, evidence_refs=["b1-checkpoint"], trust_store=trust_store, now=NOW)
    second = build_activation_plan_without_execution(target=t, observation=o, intent=i, approval=a, evidence_refs=["b1-checkpoint"], trust_store=trust_store, now=NOW)
    assert first.plan_hash == second.plan_hash
    assert first.planned_mutations == 0
    assert first.dry_run_read_only is True
    assert first.rollback_recovery_semantics == "AFTER_DURABLE_GENESIS_RECOVERY_OR_CONTINUATION_ONLY"
    bad = intent(intent_id="plan-bad-signature", signature_metadata={"signature_ref": "bad", "signature": "1" * 128})
    bad_approval = approval(t, bad)
    with pytest.raises(CoreError, match="SMI_SIGNATURE_INVALID"):
        build_activation_plan_without_execution(target=t, observation=o, intent=bad, approval=bad_approval, evidence_refs=["b1-checkpoint"], trust_store=trust_store, now=NOW)



def test_real_production_activation_path_uses_owned_storage_composition(tmp_path):
    trust_store, provider, record, admission_store = real_file_backed_signer_fixture(tmp_path)
    i = real_signed_intent(provider, record)
    t = target()
    o = observation()
    a = approval(t, i)
    validate_signed_migration_intent(
        i,
        now=NOW,
        trust_store=trust_store,
        target=t,
        environment_mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
        admission_store=admission_store,
        signer_provider=provider,
    )
    plan = build_activation_plan_without_execution(
        target=t,
        observation=o,
        intent=i,
        approval=a,
        evidence_refs=["owned-storage-composition-test"],
        trust_store=trust_store,
        environment_mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
        admission_store=admission_store,
        signer_provider=provider,
        now=NOW,
    )
    assert plan.planned_mutations == 0


def test_activation_request_cannot_supply_storage_trust_capability(tmp_path):
    trust_store, provider, record, admission_store = real_file_backed_signer_fixture(tmp_path)
    i = real_signed_intent(provider, record)
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        validate_signed_migration_intent(
            i,
            now=NOW,
            trust_store=trust_store,
            target=target(),
            environment_mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
            admission_store=admission_store,
            signer_provider=provider,
            storage_inspector=object(),
        )
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        build_activation_plan_without_execution(
            target=target(),
            observation=observation(),
            intent=i,
            approval=approval(target(), i),
            evidence_refs=["caller-storage-trust-rejected"],
            trust_store=trust_store,
            environment_mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
            admission_store=admission_store,
            signer_provider=provider,
            storage_attestation_store=object(),
            now=NOW,
        )


def test_activation_attempt_guard_allows_same_attempt_and_rejects_concurrent_attempt():
    guard = ActivationAttemptGuard()
    guard.acquire("attempt-1")
    guard.acquire("attempt-1")
    with pytest.raises(CoreError, match="B2_ACTIVATION_ATTEMPT_CONFLICT"):
        guard.acquire("attempt-2")


def test_post_genesis_acceptance_plan_contains_required_checks():
    checks = production_acceptance_checks()
    for required in ["durable identity verify", "Core Read Model verify", "no second identity", "no rehearsal identity bleed"]:
        assert required in checks
