"""Current Core service regressions; SQLite and the in-memory authority only."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import delete, event, select

from app.audit import verify_audit_chain
from app.canonical import sha256_hex
from app.errors import CoreError
from app.models import AuditLedger, ControlPlaneState, CoreMetadata, GenesisAttempt, GenesisRecord, MutationReceipt, RestoreRecord
from app.schemas import MutationRequest, RestoreManifest, RestoreRequest


def mutation(genesis_request, lease, mutation_id="state-m1"):
    return MutationRequest(
        continuity_id=genesis_request.continuity_id, continuity_epoch=0,
        lease_id=lease, mutation_id=mutation_id, actor_principal_id="owner-1",
        capability="core_writer", payload={"id": mutation_id},
    )


def restore_request(service, authority, genesis_request, genesis):
    checkpoint = authority.export_checkpoint(genesis_request.continuity_id)
    return RestoreRequest(
        request_id="state-restore-1",
        manifest=RestoreManifest(
            trust_domain_id=genesis_request.trust_domain_id,
            qingyu_identity_id=genesis_request.qingyu_identity_id,
            continuity_id=genesis_request.continuity_id,
            genesis_fingerprint=genesis.fingerprint,
            initial_owner_fingerprint=genesis_request.initial_owner_fingerprint,
            manifest_hash=genesis.manifest_hash,
            audit_high_water=checkpoint["audit_high_water"],
            audit_head_hash=checkpoint["audit_head_hash"],
            control_plane_generation_id=checkpoint["control_plane_generation_id"],
            storage_generation_id=checkpoint["storage_generation_id"],
            witness_set_version=checkpoint["witness_set_version"],
        ),
        current_owner_principal_id=checkpoint["owner_principal_id"],
        current_owner_record_hash=sha256_hex({
            "owner_version": checkpoint["owner_version"],
            "owner_principal_id": checkpoint["owner_principal_id"],
            "owner_key_fingerprint": checkpoint["owner_key_fingerprint"],
        }),
        target_storage_generation_id=uuid.uuid4(),
    )


def assert_quarantined(factory, continuity_id):
    with factory() as session:
        assert session.get(CoreMetadata, 1).status == "RESTORE_QUARANTINED"
        state = session.get(ControlPlaneState, continuity_id)
        assert state.status == "RESTORE_QUARANTINED"
        assert state.lease_id is None


@pytest.mark.parametrize("after_commit", [False, True])
def test_failed_genesis_completion_quarantines_all_local_projections(
    foundation, genesis_request, monkeypatch, after_commit,
):
    service, factory, authority = foundation
    original = authority.complete_genesis

    def fail(**kwargs):
        if after_commit:
            original(**kwargs)
        raise CoreError("GENESIS_OUTCOME_UNKNOWN")

    monkeypatch.setattr(authority, "complete_genesis", fail)
    with pytest.raises(CoreError):
        service.bootstrap_genesis(genesis_request)
    assert_quarantined(factory, genesis_request.continuity_id)
    with pytest.raises(CoreError):
        service.acquire_owner_lease(genesis_request.continuity_id)


def test_genesis_retry_cannot_claim_success_from_quarantined_local_state(
    foundation, genesis_request,
):
    service, factory, _ = foundation
    service.bootstrap_genesis(genesis_request)
    with factory.begin() as session:
        session.get(CoreMetadata, 1).status = "RESTORE_QUARANTINED"
    with pytest.raises(CoreError, match="GENESIS_OUTCOME_UNKNOWN|RESTORE_FENCE_UNPROVEN"):
        service.bootstrap_genesis(genesis_request)


@pytest.mark.parametrize("entry", ["lease", "mutation", "owner_transfer"])
def test_metadata_quarantine_blocks_every_governance_entry(foundation, genesis_request, entry):
    service, factory, authority = foundation
    service.bootstrap_genesis(genesis_request)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    before = authority.export_checkpoint(genesis_request.continuity_id)
    with factory.begin() as session:
        session.get(CoreMetadata, 1).status = "RESTORE_QUARANTINED"
    with pytest.raises(CoreError, match="RESTORE_FENCE_UNPROVEN"):
        if entry == "lease":
            service.acquire_owner_lease(genesis_request.continuity_id)
        elif entry == "mutation":
            service.governed_mutation(mutation(genesis_request, lease))
        else:
            service.transfer_owner(
                continuity_id=genesis_request.continuity_id, current_owner_principal_id="owner-1",
                expected_owner_version=0, target_principal_id="owner-2",
                target_key_fingerprint="owner-fingerprint-2",
            )
    assert authority.export_checkpoint(genesis_request.continuity_id) == before


def test_incomplete_local_genesis_receipt_blocks_lease(foundation, genesis_request):
    service, factory, _ = foundation
    service.bootstrap_genesis(genesis_request)
    with factory.begin() as session:
        session.get(GenesisAttempt, genesis_request.genesis_request_id).state = "CORE_COMMITTED"
    with pytest.raises(CoreError):
        service.acquire_owner_lease(genesis_request.continuity_id)


def test_mutation_rechecks_local_eligibility_after_authority_prepare(
    foundation, genesis_request, monkeypatch,
):
    service, factory, authority = foundation
    service.bootstrap_genesis(genesis_request)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    original = authority.prepare_mutation

    def prepare_then_quarantine(**kwargs):
        permit = original(**kwargs)
        with factory.begin() as session:
            session.get(CoreMetadata, 1).status = "RESTORE_QUARANTINED"
        return permit

    monkeypatch.setattr(authority, "prepare_mutation", prepare_then_quarantine)
    with pytest.raises(CoreError, match="RESTORE_FENCE_UNPROVEN"):
        service.governed_mutation(mutation(genesis_request, lease))
    assert authority.get_domain(genesis_request.continuity_id).state_version == 0
    with factory() as session:
        assert session.get(MutationReceipt, "state-m1") is None


def test_mutation_finalization_rechecks_quarantine(foundation, genesis_request, monkeypatch):
    service, factory, authority = foundation
    service.bootstrap_genesis(genesis_request)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    original = authority.commit_mutation

    def commit_then_quarantine(**kwargs):
        permit = original(**kwargs)
        with factory.begin() as session:
            session.get(CoreMetadata, 1).status = "RESTORE_QUARANTINED"
        return permit

    monkeypatch.setattr(authority, "commit_mutation", commit_then_quarantine)
    with pytest.raises(CoreError, match="RESTORE_FENCE_UNPROVEN"):
        service.governed_mutation(mutation(genesis_request, lease))
    assert_quarantined(factory, genesis_request.continuity_id)
    with factory() as session:
        assert session.get(MutationReceipt, "state-m1").status != "COMMITTED"


def test_restore_rejects_self_consistent_audit_behind_manifest_and_authority(foundation, genesis_request):
    service, factory, authority = foundation
    genesis = service.bootstrap_genesis(genesis_request)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    service.governed_mutation(mutation(genesis_request, lease))
    request = restore_request(service, authority, genesis_request, genesis)
    assert request.manifest.audit_high_water == 3
    with factory.begin() as session:
        session.execute(delete(MutationReceipt))
        session.execute(delete(AuditLedger).where(AuditLedger.audit_seq > 1))
        metadata = session.get(CoreMetadata, 1)
        metadata.audit_seq = 1
        metadata.audit_head_hash = session.get(AuditLedger, 1).record_hash
        metadata.current_state_version = 0
        state = session.get(ControlPlaneState, genesis_request.continuity_id)
        state.state_version = 0
        state.lease_id = None
    with factory() as session:
        assert verify_audit_chain(session)["audit_seq"] == 1
    with pytest.raises(CoreError, match="RESTORE_STATE_GAP|AUDIT_HIGH_WATER_UNPROVEN"):
        service.verify_restore(request)
    assert_quarantined(factory, genesis_request.continuity_id)


@pytest.mark.parametrize("field", ["state_version", "identity_id"])
def test_restore_binds_local_state_and_identity_to_authority(foundation, genesis_request, field):
    service, factory, authority = foundation
    genesis = service.bootstrap_genesis(genesis_request)
    request = restore_request(service, authority, genesis_request, genesis)
    domain = authority.get_domain(genesis_request.continuity_id)
    setattr(domain, field, 42 if field == "state_version" else uuid.uuid4())
    with pytest.raises(CoreError, match="RESTORE_STATE_GAP|RESTORE_IDENTITY_MISMATCH"):
        service.verify_restore(request)
    assert_quarantined(factory, genesis_request.continuity_id)


def test_restore_sync_failure_never_publishes_ready_and_retry_reconciles(
    foundation, genesis_request, monkeypatch,
):
    service, factory, authority = foundation
    genesis = service.bootstrap_genesis(genesis_request)
    request = restore_request(service, authority, genesis_request, genesis)
    original = authority.sync_audit_checkpoint
    calls = []

    def fail_sync(**kwargs):
        calls.append(kwargs)
        raise CoreError("CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE")

    monkeypatch.setattr(authority, "sync_audit_checkpoint", fail_sync)
    with pytest.raises(CoreError):
        service.activate_restore(request)
    assert_quarantined(factory, genesis_request.continuity_id)
    with factory() as session:
        assert session.get(RestoreRecord, request.request_id).status != "ACTIVE"
    with pytest.raises(CoreError):
        service.activate_restore(request)
    assert len(calls) == 2
    assert_quarantined(factory, genesis_request.continuity_id)
    monkeypatch.setattr(authority, "sync_audit_checkpoint", original)
    result = service.activate_restore(request)
    assert not result.read_only
    assert service.identity_status().status == "READY"
    assert service.identity_status().state_version == 1
    with factory() as session:
        assert session.get(CoreMetadata, 1).current_state_version == 1
        rows = list(session.scalars(select(AuditLedger).where(AuditLedger.operation_type == "CONTINUITY_REBASED")))
        assert len(rows) == 1
        assert session.get(RestoreRecord, request.request_id).status == "ACTIVE"
    assert not service.activate_restore(request).read_only
    service.acquire_owner_lease(genesis_request.continuity_id)


def test_active_restore_receipt_does_not_bypass_later_quarantine(foundation, genesis_request):
    service, factory, authority = foundation
    genesis = service.bootstrap_genesis(genesis_request)
    request = restore_request(service, authority, genesis_request, genesis)
    service.activate_restore(request)
    with factory.begin() as session:
        session.get(CoreMetadata, 1).status = "RESTORE_QUARANTINED"
        session.get(ControlPlaneState, genesis_request.continuity_id).status = "RESTORE_QUARANTINED"
    with pytest.raises(CoreError, match="RESTORE_FENCE_UNPROVEN"):
        service.activate_restore(request)


def test_mutation_retry_returns_original_audit_hash_after_later_mutation(foundation, genesis_request):
    service, _, _ = foundation
    service.bootstrap_genesis(genesis_request)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    request = mutation(genesis_request, lease)
    first = service.governed_mutation(request)
    assert service.governed_mutation(request).model_dump() == first.model_dump()
    second = service.governed_mutation(mutation(genesis_request, lease, "state-m2"))
    retry = service.governed_mutation(request)
    assert second.audit_seq > first.audit_seq
    assert retry.model_dump() == first.model_dump()
    service.governed_mutation(mutation(genesis_request, lease, "state-m3"))
    assert service.governed_mutation(request).model_dump() == first.model_dump()


def test_mutation_retry_rejects_receipt_audit_row_binding_mismatch(foundation, genesis_request):
    service, factory, _ = foundation
    service.bootstrap_genesis(genesis_request)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    request = mutation(genesis_request, lease)
    first = service.governed_mutation(request)
    with factory.begin() as session:
        session.get(AuditLedger, first.audit_seq).mutation_id = "different-mutation"
    with pytest.raises(CoreError, match="MUTATION_OUTCOME_UNKNOWN|AUDIT_CHAIN_INVALID"):
        service.governed_mutation(request)


def test_genesis_external_success_local_final_failure_requires_exact_reconciliation(
    foundation, genesis_request,
):
    service, factory, authority = foundation

    def fail_ready_commit(session):
        if any(isinstance(row, CoreMetadata) and row.status == "READY" for row in session.dirty):
            raise CoreError("LOCAL_FINAL_PUBLICATION_FAILED")

    event.listen(factory.class_, "before_commit", fail_ready_commit)
    try:
        with pytest.raises(CoreError, match="LOCAL_FINAL_PUBLICATION_FAILED"):
            service.bootstrap_genesis(genesis_request)
    finally:
        event.remove(factory.class_, "before_commit", fail_ready_commit)
    assert authority.genesis_status(genesis_request.trust_domain_id).state.value == "COMMITTED"
    assert_quarantined(factory, genesis_request.continuity_id)
    with pytest.raises(CoreError):
        service.acquire_owner_lease(genesis_request.continuity_id)
    with factory() as session:
        assert session.get(GenesisAttempt, genesis_request.genesis_request_id).state == "CORE_COMMITTED"
        original_hash = session.get(CoreMetadata, 1).audit_head_hash
    result = service.bootstrap_genesis(genesis_request)
    assert result.status == "COMMITTED"
    assert service.identity_status().status == "READY"
    assert service.identity_status().audit_seq == 1
    assert service.identity_status().audit_head_hash == original_hash
    service.acquire_owner_lease(genesis_request.continuity_id)


def test_restore_external_completion_local_publication_failure_retries_same_receipt(
    foundation, genesis_request,
):
    service, factory, authority = foundation
    genesis = service.bootstrap_genesis(genesis_request)
    request = restore_request(service, authority, genesis_request, genesis)

    def fail_ready_commit(session):
        if any(isinstance(row, RestoreRecord) and row.status == "ACTIVE" for row in session.dirty):
            raise CoreError("LOCAL_FINAL_PUBLICATION_FAILED")

    event.listen(factory.class_, "before_commit", fail_ready_commit)
    try:
        with pytest.raises(CoreError, match="LOCAL_FINAL_PUBLICATION_FAILED"):
            service.activate_restore(request)
    finally:
        event.remove(factory.class_, "before_commit", fail_ready_commit)
    assert authority.recovery_status(request.request_id)["status"] == "ACTIVE"
    assert_quarantined(factory, genesis_request.continuity_id)
    with pytest.raises(CoreError):
        service.acquire_owner_lease(genesis_request.continuity_id)
    with factory() as session:
        assert session.get(RestoreRecord, request.request_id).status == "PREPARED"
        original_hash = session.get(CoreMetadata, 1).audit_head_hash
    assert not service.activate_restore(request).read_only
    assert service.identity_status().audit_seq == 2
    assert service.identity_status().audit_head_hash == original_hash
    service.acquire_owner_lease(genesis_request.continuity_id)


def test_mutation_finalization_reloads_genesis_binding(foundation, genesis_request, monkeypatch):
    service, factory, authority = foundation
    service.bootstrap_genesis(genesis_request)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    original = authority.commit_mutation

    def commit_then_change_binding(**kwargs):
        permit = original(**kwargs)
        with factory.begin() as session:
            session.scalar(select(GenesisRecord)).fingerprint = "f" * 64
        return permit

    monkeypatch.setattr(authority, "commit_mutation", commit_then_change_binding)
    with pytest.raises(CoreError, match="RESTORE_IDENTITY_MISMATCH"):
        service.governed_mutation(mutation(genesis_request, lease))
    assert_quarantined(factory, genesis_request.continuity_id)


def test_restore_rejects_audit_tip_projection_not_bound_to_canonical_hash(foundation, genesis_request):
    service, factory, authority = foundation
    genesis = service.bootstrap_genesis(genesis_request)
    request = restore_request(service, authority, genesis_request, genesis)
    with factory.begin() as session:
        session.get(AuditLedger, 1).state_version = 9
    with pytest.raises(CoreError, match="AUDIT_CHAIN_INVALID"):
        service.verify_restore(request)
    assert_quarantined(factory, genesis_request.continuity_id)


@pytest.mark.parametrize("entry", ["lease", "mutation", "genesis_retry", "restore_retry"])
def test_success_receipts_require_fresh_authority_quorum(foundation, genesis_request, entry):
    service, _, authority = foundation
    genesis = service.bootstrap_genesis(genesis_request)
    request = restore_request(service, authority, genesis_request, genesis)
    if entry == "restore_retry":
        service.activate_restore(request)
    else:
        lease = service.acquire_owner_lease(genesis_request.continuity_id)
        mutation_request = mutation(genesis_request, lease)
        service.governed_mutation(mutation_request)
    authority.available_witnesses = 1
    with pytest.raises(CoreError, match="CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE"):
        if entry == "lease":
            service.acquire_owner_lease(genesis_request.continuity_id)
        elif entry == "mutation":
            service.governed_mutation(mutation_request)
        elif entry == "genesis_retry":
            service.bootstrap_genesis(genesis_request)
        else:
            service.activate_restore(request)


@pytest.mark.parametrize("entry", ["mutation", "restore"])
@pytest.mark.parametrize("audit_position", ["terminal", "genesis"])
def test_terminal_publication_reloads_entire_audit_chain(
    foundation, genesis_request, monkeypatch, entry, audit_position,
):
    service, factory, authority = foundation
    genesis = service.bootstrap_genesis(genesis_request)
    if entry == "mutation":
        lease = service.acquire_owner_lease(genesis_request.continuity_id)
        request = mutation(genesis_request, lease)
        operation = authority.commit_mutation
        method = "commit_mutation"
    else:
        request = restore_request(service, authority, genesis_request, genesis)
        operation = authority.complete_recovery
        method = "complete_recovery"

    def commit_then_change_audit(*args, **kwargs):
        result = operation(*args, **kwargs)
        audit_seq = kwargs["audit_seq"] if audit_position == "terminal" else 1
        with factory.begin() as session:
            session.get(AuditLedger, audit_seq).state_version = 999
        return result

    monkeypatch.setattr(authority, method, commit_then_change_audit)
    with pytest.raises(CoreError, match="AUDIT_CHAIN_INVALID"):
        if entry == "mutation":
            service.governed_mutation(request)
        else:
            service.activate_restore(request)
    assert_quarantined(factory, genesis_request.continuity_id)
    with factory() as session:
        if entry == "mutation":
            assert session.get(MutationReceipt, request.mutation_id).status == "PREPARED"
        else:
            assert session.get(RestoreRecord, request.request_id).status == "PREPARED"


@pytest.mark.parametrize("entry", ["mutation", "restore"])
@pytest.mark.parametrize("receipt_change", ["drift", "delete"])
def test_terminal_publication_reloads_and_binds_receipt(
    foundation, genesis_request, monkeypatch, entry, receipt_change,
):
    service, factory, authority = foundation
    genesis = service.bootstrap_genesis(genesis_request)
    if entry == "mutation":
        lease = service.acquire_owner_lease(genesis_request.continuity_id)
        request = mutation(genesis_request, lease)
        operation, method = authority.commit_mutation, "commit_mutation"
        model, record_id = MutationReceipt, request.mutation_id
    else:
        request = restore_request(service, authority, genesis_request, genesis)
        operation, method = authority.complete_recovery, "complete_recovery"
        model, record_id = RestoreRecord, request.request_id

    def commit_then_change_receipt(*args, **kwargs):
        result = operation(*args, **kwargs)
        with factory.begin() as session:
            record = session.get(model, record_id)
            if receipt_change == "delete":
                session.delete(record)
            elif entry == "mutation":
                record.payload_hash = "f" * 64
                record.assigned_state_version = 999
                record.audit_seq = 2
                record.local_commit_id = "forged"
            else:
                record.manifest_hash = "f" * 64
        return result

    monkeypatch.setattr(authority, method, commit_then_change_receipt)
    with pytest.raises(CoreError, match="MUTATION_OUTCOME_UNKNOWN|RESTORE_REQUEST_CONFLICT|RESTORE_FENCE_UNPROVEN"):
        if entry == "mutation":
            service.governed_mutation(request)
        else:
            service.activate_restore(request)
    assert_quarantined(factory, genesis_request.continuity_id)


@pytest.mark.parametrize("field,value", [
    ("protocol_version", "wrong-protocol"),
    ("id_scheme", "uuidv1"),
    ("witness_set_fingerprint", "f" * 64),
])
def test_write_gate_validates_persisted_genesis_protocol_fields(
    foundation, genesis_request, field, value,
):
    service, factory, _ = foundation
    genesis = service.bootstrap_genesis(genesis_request)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    with factory.begin() as session:
        setattr(session.get(GenesisRecord, genesis.genesis_id), field, value)
    with pytest.raises(CoreError, match="RESTORE_IDENTITY_MISMATCH|GENESIS_OUTCOME_UNKNOWN"):
        service.governed_mutation(mutation(genesis_request, lease))
