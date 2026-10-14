from __future__ import annotations

from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.b2_activation_readiness import (
    B1_FOUNDATION_CHECKPOINT_COMMIT,
    B1_FOUNDATION_CHECKPOINT_TAG,
    OwnerApproval,
    ProductionTargetContract,
    SignedMigrationIntent,
    TargetReadOnlyObservation,
    activation_candidate_hash,
)
from app.b2_production_authority import (
    REAL_PRODUCTION,
    SYNTHETIC_PRODUCTION_TEST,
    PRODUCTION_AUTHORITY_SCHEMA_VERSION,
    ProductionAuthorityCandidate,
    ProductionAuthorityState,
    ProductionAuthorityStore,
)
from app.errors import CoreError
from app.b2_signer_trust import (
    AuthorityEnvironmentMode,
    InMemoryEd25519SignerProvider,
    SignerProviderClassification,
    TrustRecord,
    TrustStore,
    sign_smi_payload,
)
from tests.test_foundation_closure_rehearsal import FoundationPostgresEnvironment

NOW = datetime(2026, 9, 18, 12, 0, tzinfo=timezone.utc)

_SYNTHETIC_TRUST_CACHE = {}


def synthetic_trust(
    *,
    trust_reference="synthetic-production-trust-ref",
    environment=SYNTHETIC_PRODUCTION_TEST,
    target_reference="synthetic-prod-target-ref-001",
    classification=SignerProviderClassification.SYNTHETIC_PRODUCTION_TEST_ONLY,
):
    cache_key = (trust_reference, environment, target_reference, classification.value)
    if cache_key not in _SYNTHETIC_TRUST_CACHE:
        provider = InMemoryEd25519SignerProvider(
            provider_reference=f"synthetic-provider:{trust_reference}",
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
        _SYNTHETIC_TRUST_CACHE[cache_key] = (provider, record)
    provider, record = _SYNTHETIC_TRUST_CACHE[cache_key]
    return TrustStore({trust_reference: record}), provider, record


def synthetic_trust_store(**kwargs):
    return synthetic_trust(**kwargs)[0]


def fresh_synthetic_trust(*, trust_reference="synthetic-production-trust-ref", environment=SYNTHETIC_PRODUCTION_TEST, target_reference="synthetic-prod-target-ref-001"):
    provider = InMemoryEd25519SignerProvider(
        provider_reference=f"synthetic-provider:{trust_reference}",
        private_key=Ed25519PrivateKey.generate(),
        classification=SignerProviderClassification.SYNTHETIC_PRODUCTION_TEST_ONLY,
    )
    record = TrustRecord.from_provider(
        trust_reference=trust_reference,
        provider=provider,
        environment=environment,
        target_reference=target_reference,
        generation=1,
        created_at=NOW,
    )
    return TrustStore({trust_reference: record}), provider, record


def _sign_intent_data(data: dict, provider: InMemoryEd25519SignerProvider) -> dict:
    placeholder = dict(data)
    placeholder["signature_metadata"] = {"signature_ref": "synthetic-test-signature", "signature": "0" * 128}
    payload = SignedMigrationIntent(**placeholder).canonical_payload()
    signed = dict(data)
    signed["signature_metadata"] = {
        **signed.get("signature_metadata", {}),
        "signature_ref": signed.get("signature_metadata", {}).get("signature_ref", "synthetic-test-signature"),
        "signature": sign_smi_payload(provider, payload),
    }
    return signed


def make_target(**updates):
    data = {
        "target_reference": "synthetic-prod-target-ref-001",
        "environment_identity": SYNTHETIC_PRODUCTION_TEST,
        "environment_class": "production",
        "host_reference": "synthetic-host-ref",
        "database_reference": "synthetic-authority-db",
        "postgres_version_major": 16,
        "schema_owner_reference": "synthetic-owner-ref",
        "expected_pre_activation_state": "EMPTY_PRE_GENESIS",
        "migration_version": "synthetic-migration-v1",
        "allowed_network_boundary": "loopback-test-boundary",
        "backup_recovery_reference": "synthetic-backup-ref",
        "signer_trust_reference": "synthetic-production-trust-ref",
        "authority_reference": "synthetic-authority-ref",
        "audit_destination_reference": "synthetic-audit-ref",
        "activation_lock_reference": "synthetic-lock-ref",
        "expected_commit": B1_FOUNDATION_CHECKPOINT_COMMIT,
        "expected_tag": B1_FOUNDATION_CHECKPOINT_TAG,
    }
    data.update(updates)
    return ProductionTargetContract(**data)


def make_intent(**updates):
    data = {
        "intent_id": "synthetic-intent-001",
        "target_environment": SYNTHETIC_PRODUCTION_TEST,
        "target_reference": "synthetic-prod-target-ref-001",
        "source_checkpoint": B1_FOUNDATION_CHECKPOINT_COMMIT,
        "source_tag": B1_FOUNDATION_CHECKPOINT_TAG,
        "target_schema_migration_version": "synthetic-migration-v1",
        "authority_trust_reference": "synthetic-production-trust-ref",
        "requested_operation": "PRODUCTION_GENESIS",
        "expected_preconditions": ["no previous durable GENESIS", "owner approval valid"],
        "expected_genesis_behavior": "DURABLE_ONCE_THEN_CONTINUATION_ONLY",
        "valid_from": NOW - timedelta(minutes=5),
        "expires_at": NOW + timedelta(hours=1),
        "owner_approval_reference": "synthetic-owner-approval-required",
        "signature_metadata": {"signature_ref": "synthetic-test-signature"},
    }
    data.update(updates)
    signer_key_id_overridden = "signer_key_id" in updates
    _, provider, record = synthetic_trust(
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


def make_observation(**updates):
    data = {
        "target_reference": "synthetic-prod-target-ref-001",
        "reachable": True,
        "postgres_version_major": 16,
        "schema_state": "EMPTY_PRE_GENESIS",
        "migration_version": "synthetic-migration-v1",
        "durable_genesis_present": False,
        "authority_trust_reference": "synthetic-production-trust-ref",
        "backup_recovery_available": True,
        "audit_sink_available": True,
        "activation_lock_available": True,
        "observed_at": NOW,
    }
    data.update(updates)
    return TargetReadOnlyObservation(**data)


def make_approval(target=None, intent=None, **updates):
    target = target or make_target()
    intent = intent or make_intent()
    data = {
        "approval_id": "synthetic-approval-001",
        "approval_state": "OWNER_APPROVED",
        "activation_candidate_hash": activation_candidate_hash(target=target, intent=intent),
        "target_reference": target.target_reference,
        "migration_intent_hash": intent.canonical_payload_hash,
        "authority_trust_reference": intent.authority_trust_reference,
        "source_checkpoint": B1_FOUNDATION_CHECKPOINT_COMMIT,
        "source_tag": B1_FOUNDATION_CHECKPOINT_TAG,
        "approved_at": NOW,
        "approval_reference": "synthetic-explicit-owner-approval",
    }
    data.update(updates)
    return OwnerApproval(**data)


@pytest.fixture
def authority(tmp_path):
    env = FoundationPostgresEnvironment(tmp_path).create()
    try:
        env.create_database("b2_authority")
        store = ProductionAuthorityStore(env.url("b2_authority"))
        yield ProductionAuthorityCandidate(store, trust_store=synthetic_trust_store())
    finally:
        env.destroy()


def test_schema_version_and_no_pickle_persistence(authority):
    assert authority.schema_version == PRODUCTION_AUTHORITY_SCHEMA_VERSION
    before = authority.store.counts_and_hash()
    assert before["domain_count"] == 0
    assert "pickle" not in PRODUCTION_AUTHORITY_SCHEMA_VERSION.lower()


def test_validate_before_mutation_no_side_effect_for_invalid_inputs(authority):
    before = authority.store.counts_and_hash()
    with pytest.raises(CoreError, match="B2_OWNER_APPROVAL_REQUIRED"):
        authority.reserve_genesis(target=make_target(), observation=make_observation(), intent=make_intent(), approval=None, attempt_id="attempt-invalid", now=NOW)
    after = authority.store.counts_and_hash()
    assert after == before


def test_reservation_restart_reconstruction_and_same_retry(authority, tmp_path):
    target, intent, obs = make_target(), make_intent(), make_observation()
    approval = make_approval(target, intent)
    first = authority.reserve_genesis(target=target, observation=obs, intent=intent, approval=approval, attempt_id="attempt-1", now=NOW)
    restarted = ProductionAuthorityCandidate(ProductionAuthorityStore(authority.store.sqlalchemy_url), trust_store=synthetic_trust_store())
    second = restarted.reserve_genesis(target=target, observation=obs, intent=intent, approval=approval, attempt_id="attempt-1", now=NOW)
    assert second["request_binding_hash"] == first["request_binding_hash"]
    assert restarted.export_state(SYNTHETIC_PRODUCTION_TEST)["state"] == ProductionAuthorityState.GENESIS_RESERVED.value


def test_durable_genesis_restart_response_loss_and_no_regenesis(authority):
    target, intent, obs = make_target(), make_intent(), make_observation()
    approval = make_approval(target, intent)
    with pytest.raises(CoreError, match="B2_SIMULATED_RESPONSE_LOSS_AFTER_DURABLE_COMMIT"):
        authority.commit_genesis(target=target, observation=obs, intent=intent, approval=approval, attempt_id="attempt-2", now=NOW, simulate_failure_after_commit=True)
    restarted = ProductionAuthorityCandidate(ProductionAuthorityStore(authority.store.sqlalchemy_url), trust_store=synthetic_trust_store())
    replay = restarted.commit_genesis(target=target, observation=obs, intent=intent, approval=approval, attempt_id="attempt-2", now=NOW)
    again = restarted.commit_genesis(target=target, observation=obs, intent=intent, approval=approval, attempt_id="attempt-2", now=NOW)
    assert again.as_dict() == replay.as_dict()
    changed_intent = make_intent(intent_id="changed-intent")
    changed_approval = make_approval(target, changed_intent)
    with pytest.raises(CoreError, match="B2_ACTIVATION_ATTEMPT_CONFLICT"):
        restarted.commit_genesis(target=target, observation=obs, intent=changed_intent, approval=changed_approval, attempt_id="attempt-3", now=NOW)


def test_crash_before_reservation_commit_has_no_durable_state(authority):
    with pytest.raises(CoreError, match="B2_SIMULATED_FAILURE_BEFORE_COMMIT"):
        authority.reserve_genesis(target=make_target(), observation=make_observation(), intent=make_intent(), approval=make_approval(), attempt_id="attempt-crash-before", now=NOW, simulate_failure_before_commit=True)
    assert authority.store.counts_and_hash()["domain_count"] == 0


def test_concurrent_attempt_durable_guard(authority):
    target, intent, obs = make_target(), make_intent(), make_observation()
    approval = make_approval(target, intent)
    def run(attempt_id):
        try:
            return authority.reserve_genesis(target=target, observation=obs, intent=intent, approval=approval, attempt_id=attempt_id, now=NOW)["attempt_id"]
        except CoreError as exc:
            return str(exc)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(run, ["winner", "loser"]))
    assert "winner" in results or "loser" in results
    assert any("B2_ACTIVATION_ATTEMPT_CONFLICT" in item for item in results)
    assert authority.store.counts_and_hash()["domain_count"] == 1


def test_intent_approval_and_trust_binding_rejections(authority):
    target, intent, obs = make_target(), make_intent(), make_observation()
    approval = make_approval(target, intent)
    authority.reserve_genesis(target=target, observation=obs, intent=intent, approval=approval, attempt_id="binding", now=NOW)
    with pytest.raises(CoreError, match="B2_INTENT_NOT_VALID_NOW"):
        expired = make_intent(intent_id="expired", valid_from=NOW - timedelta(hours=2), expires_at=NOW - timedelta(hours=1))
        authority.reserve_genesis(target=target, observation=obs, intent=expired, approval=make_approval(target, expired), attempt_id="expired", now=NOW)
    with pytest.raises(CoreError, match="B2_TRUST_REFERENCE_MISMATCH|B2_OWNER_APPROVAL_SCOPE_MISMATCH"):
        wrong_obs = make_observation(authority_trust_reference="wrong-trust")
        authority.reserve_genesis(target=target, observation=wrong_obs, intent=intent, approval=approval, attempt_id="wrong-trust", now=NOW)
    with pytest.raises(CoreError, match="B2_OWNER_APPROVAL_SCOPE_MISMATCH"):
        wrong_approval = make_approval(target, intent, activation_candidate_hash="0" * 64)
        authority.reserve_genesis(target=target, observation=obs, intent=intent, approval=wrong_approval, attempt_id="wrong-approval", now=NOW)


def test_signature_and_trust_failures_are_pre_mutation(authority):
    before = authority.store.counts_and_hash()
    target, obs = make_target(), make_observation()
    cases = [
        make_intent(intent_id="bad-signature", signature_metadata={"signature_ref": "bad", "signature": "1" * 128}),
        make_intent(intent_id="wrong-key", signer_key_id="0" * 64),
        make_intent(intent_id="unknown-trust", authority_trust_reference="unknown-trust-ref"),
        make_intent(intent_id="wrong-env").model_copy(update={"target_environment": "wrong-env"}),
        make_intent(intent_id="wrong-target").model_copy(update={"target_reference": "wrong-target"}),
    ]
    expected = [
        "SMI_SIGNATURE_INVALID",
        "SMI_SIGNER_KEY_ID_MISMATCH",
        "SMI_SIGNER_TRUST_NOT_FOUND",
        "SMI_ENVIRONMENT_MISMATCH",
        "SMI_TARGET_MISMATCH",
    ]
    for bad_intent, pattern in zip(cases, expected):
        with pytest.raises(CoreError, match=pattern):
            authority.reserve_genesis(
                target=target,
                observation=obs,
                intent=bad_intent,
                approval=make_approval(target, bad_intent),
                attempt_id=f"negative-{bad_intent.intent_id}",
                now=NOW,
            )
    assert authority.store.counts_and_hash() == before


def test_real_production_mode_rejects_synthetic_trust_classification(tmp_path):
    env = FoundationPostgresEnvironment(tmp_path).create()
    try:
        env.create_database("b2_real_mode")
        store = ProductionAuthorityStore(env.url("b2_real_mode"))
        target = make_target(environment_identity="qingyu-real-prod-primary")
        obs = make_observation()
        intent = make_intent(target_environment="qingyu-real-prod-primary")
        candidate = ProductionAuthorityCandidate(
            store,
            trust_store=synthetic_trust_store(environment="qingyu-real-prod-primary"),
            environment_mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
        )
        with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_NOT_FOUND"):
            candidate.reserve_genesis(
                target=target,
                observation=obs,
                intent=intent,
                approval=make_approval(target, intent),
                attempt_id="real-mode-synthetic-key",
                now=NOW,
            )
        assert store.counts_and_hash()["domain_count"] == 0
    finally:
        env.destroy()


def test_rehearsal_artifact_and_marker_rejected(authority):
    with pytest.raises(CoreError, match="B2_REHEARSAL_ARTIFACT_FORBIDDEN"):
        bad_target = make_target(authority_reference="PostgresAuthorityStateStore")
        authority.reserve_genesis(target=bad_target, observation=make_observation(), intent=make_intent(), approval=make_approval(), attempt_id="bad-rehearsal", now=NOW)
    with pytest.raises(CoreError, match="B2_SYNTHETIC_PRODUCTION_MARKER_REQUIRED"):
        bad_marker = make_target(environment_identity="REAL_PRODUCTION_FORBIDDEN")
        bad_intent = make_intent(target_environment="REAL_PRODUCTION_FORBIDDEN")
        authority.reserve_genesis(target=bad_marker, observation=make_observation(), intent=bad_intent, approval=make_approval(bad_marker, bad_intent), attempt_id="bad-marker", now=NOW)


def test_recovery_state_fields_persist_after_durable_genesis(authority):
    target, intent, obs = make_target(), make_intent(), make_observation()
    approval = make_approval(target, intent)
    result = authority.commit_genesis(target=target, observation=obs, intent=intent, approval=approval, attempt_id="recovery-fields", now=NOW)
    state = ProductionAuthorityCandidate(ProductionAuthorityStore(authority.store.sqlalchemy_url), trust_store=synthetic_trust_store()).export_state(SYNTHETIC_PRODUCTION_TEST)
    assert state["recovery_epoch"] == result.recovery_epoch
    assert state["governed_state_version"] == result.governed_state_version
    assert state["last_checkpoint_hash"]
    assert state["trust_reference"] == target.signer_trust_reference
    _, _, record = synthetic_trust()
    assert state["trust_algorithm"] == "Ed25519"
    assert state["trust_key_id"] == record.key_id
    assert state["trust_public_key_fingerprint"] == record.public_key_fingerprint
    assert state["trust_schema_version"] == record.schema_version
    assert state["trust_environment"] == SYNTHETIC_PRODUCTION_TEST
    assert state["trust_target_reference"] == target.target_reference
    with authority.store.engine.begin() as connection:
        audit = connection.execute(text("SELECT * FROM b2_production_authority_audit ORDER BY audit_id")).mappings().all()
    assert audit
    assert all(row["trust_key_id"] == record.key_id for row in audit)
    assert all(row["trust_public_key_fingerprint"] == record.public_key_fingerprint for row in audit)
    assert all(row["trust_schema_version"] == record.schema_version for row in audit)
    assert all(row["trust_environment"] == SYNTHETIC_PRODUCTION_TEST for row in audit)
    assert all(row["trust_target_reference"] == target.target_reference for row in audit)


def test_restart_rejects_same_trust_reference_with_different_key(authority):
    target, intent, obs = make_target(), make_intent(), make_observation()
    approval = make_approval(target, intent)
    first = authority.reserve_genesis(target=target, observation=obs, intent=intent, approval=approval, attempt_id="drift", now=NOW)
    drift_store, drift_provider, drift_record = fresh_synthetic_trust()
    drift_data = intent.model_dump(mode="python")
    drift_data["signer_key_id"] = drift_record.key_id
    drift_data["intent_id"] = "intent-drift"
    drift_data["signature_metadata"] = {"signature_ref": "drift"}
    drift_intent = SignedMigrationIntent(**_sign_intent_data(drift_data, drift_provider))
    drift_approval = make_approval(target, drift_intent)
    restarted = ProductionAuthorityCandidate(ProductionAuthorityStore(authority.store.sqlalchemy_url), trust_store=drift_store)
    with pytest.raises(CoreError, match="B2_PERSISTED_TRUST_BINDING_MISMATCH"):
        restarted.reserve_genesis(target=target, observation=obs, intent=drift_intent, approval=drift_approval, attempt_id="drift", now=NOW)


def test_dry_run_plan_deterministic_read_only_and_changes_on_trust_change(authority):
    target, intent, obs = make_target(), make_intent(), make_observation()
    approval = make_approval(target, intent)
    first = authority.build_read_only_plan(target=target, observation=obs, intent=intent, approval=approval, evidence_refs=["synthetic"], now=NOW)
    second = authority.build_read_only_plan(target=target, observation=obs, intent=intent, approval=approval, evidence_refs=["synthetic"], now=NOW)
    assert first.plan_hash == second.plan_hash
    assert first.planned_mutations == 0
    changed_target = make_target(signer_trust_reference="synthetic-production-trust-ref-2")
    changed_intent = make_intent(authority_trust_reference="synthetic-production-trust-ref-2")
    changed_approval = make_approval(changed_target, changed_intent)
    changed_authority = ProductionAuthorityCandidate(authority.store, trust_store=synthetic_trust_store(trust_reference="synthetic-production-trust-ref-2"))
    changed = changed_authority.build_read_only_plan(target=changed_target, observation=make_observation(authority_trust_reference="synthetic-production-trust-ref-2"), intent=changed_intent, approval=changed_approval, evidence_refs=["synthetic"], now=NOW)
    assert changed.plan_hash != first.plan_hash



def _clear_authority_store(authority):
    with authority.store.engine.begin() as connection:
        connection.execute(text("DELETE FROM b2_production_authority_audit"))
        connection.execute(text("DELETE FROM b2_production_authority_attempts"))
        connection.execute(text("DELETE FROM b2_production_authority_domains"))


def _barrier_race(authority, attempt_ids):
    target, intent, obs = make_target(), make_intent(), make_observation()
    approval = make_approval(target, intent)
    barrier = Barrier(len(attempt_ids))
    def run(attempt_id):
        candidate = ProductionAuthorityCandidate(authority.store, reservation_race_hook=lambda: barrier.wait(timeout=10), trust_store=synthetic_trust_store())
        try:
            row = candidate.reserve_genesis(target=target, observation=obs, intent=intent,
                                            approval=approval, attempt_id=attempt_id, now=NOW)
            return {"kind": "ok", "attempt_id": row["attempt_id"]}
        except CoreError as exc:
            return {"kind": "core_error", "error": str(exc)}
        except Exception as exc:  # The regression asserts this branch is never a raw DB exception.
            return {"kind": "unexpected", "type": type(exc).__name__, "error": str(exc)}
    with ThreadPoolExecutor(max_workers=len(attempt_ids)) as pool:
        return list(pool.map(run, attempt_ids))


def test_barrier_same_attempt_concurrency_replays_without_raw_integrity_error(authority):
    results = _barrier_race(authority, ["same-attempt", "same-attempt"])
    assert results == [
        {"kind": "ok", "attempt_id": "same-attempt"},
        {"kind": "ok", "attempt_id": "same-attempt"},
    ] or results == [
        {"kind": "ok", "attempt_id": "same-attempt"},
        {"kind": "ok", "attempt_id": "same-attempt"},
    ]
    counts = authority.store.counts_and_hash()
    assert counts["domain_count"] == 1
    assert counts["attempt_count"] == 1
    assert counts["audit_count"] == 1


def test_barrier_competing_attempt_concurrency_normalizes_unique_violation(authority):
    results = _barrier_race(authority, ["winner-a", "winner-b"])
    assert sum(1 for item in results if item["kind"] == "ok") == 1
    assert sum(1 for item in results if item.get("error") == "B2_ACTIVATION_ATTEMPT_CONFLICT") == 1
    assert all(item["kind"] != "unexpected" for item in results)
    counts = authority.store.counts_and_hash()
    assert counts["domain_count"] == 1
    assert counts["attempt_count"] == 1
    assert counts["audit_count"] == 1
    restarted = ProductionAuthorityCandidate(ProductionAuthorityStore(authority.store.sqlalchemy_url), trust_store=synthetic_trust_store())
    state = restarted.export_state(SYNTHETIC_PRODUCTION_TEST)
    assert state["attempt_id"] in {"winner-a", "winner-b"}
    target, intent, obs = make_target(), make_intent(), make_observation()
    approval = make_approval(target, intent)
    replay = restarted.reserve_genesis(target=target, observation=obs, intent=intent,
                                       approval=approval, attempt_id=state["attempt_id"], now=NOW)
    assert replay["attempt_id"] == state["attempt_id"]
    loser = ({"winner-a", "winner-b"} - {state["attempt_id"]}).pop()
    with pytest.raises(CoreError, match="B2_ACTIVATION_ATTEMPT_CONFLICT"):
        restarted.reserve_genesis(target=target, observation=obs, intent=intent,
                                  approval=approval, attempt_id=loser, now=NOW)


def test_repeated_competing_attempt_trials_never_expose_raw_integrity_error(authority):
    trial_count = 50
    summary = {"winner_count": 0, "conflict_count": 0, "unexpected_exception_count": 0}
    for index in range(trial_count):
        _clear_authority_store(authority)
        results = _barrier_race(authority, [f"trial-{index}-a", f"trial-{index}-b"])
        summary["winner_count"] += sum(1 for item in results if item["kind"] == "ok")
        summary["conflict_count"] += sum(1 for item in results if item.get("error") == "B2_ACTIVATION_ATTEMPT_CONFLICT")
        summary["unexpected_exception_count"] += sum(1 for item in results if item["kind"] == "unexpected")
        counts = authority.store.counts_and_hash()
        assert counts["domain_count"] == 1
        assert counts["attempt_count"] == 1
        assert counts["audit_count"] == 1
    assert summary == {"winner_count": trial_count, "conflict_count": trial_count, "unexpected_exception_count": 0}


def test_unexpected_integrity_errors_are_not_classified_as_reservation_conflicts(authority):
    class Diag:
        constraint_name = "some_unexpected_constraint"
    class Orig:
        sqlstate = "23505"
        diag = Diag()
    err = IntegrityError("statement", {}, Orig())
    assert authority._is_expected_reservation_integrity_error(err) is False
