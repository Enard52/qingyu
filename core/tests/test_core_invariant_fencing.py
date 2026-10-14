"""Regression coverage for the shared, test-only in-memory authority.

These tests do not exercise a production R1 coordinator (not implemented).
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone
import uuid

import pytest

from app.control_plane.authority import (
    GenesisState, InMemoryControlPlane, MutationState, RecoveryState,
)
from app.canonical import sha256_hex
from app.errors import CoreError


def test_prepared_old_lease_cannot_commit_after_takeover(foundation, genesis_request):
    service, _factory, authority = foundation
    service.bootstrap_genesis(genesis_request)
    lease_a = service.acquire_owner_lease(genesis_request.continuity_id)
    state = authority.get_domain(genesis_request.continuity_id)
    permit_a = authority.prepare_mutation(
        continuity_id=state.continuity_id,
        epoch=state.epoch,
        lease_id=lease_a,
        mutation_id="prepared-a",
        payload={"writer": "a"},
        actor_principal_id="owner-1",
        capability="core_writer",
        storage_generation_id=state.storage_generation_id,
        expected_state_version=state.state_version,
        local_commit_id="local-a",
    )
    service.acquire_owner_lease(genesis_request.continuity_id)
    checkpoint = authority.export_checkpoint(genesis_request.continuity_id)
    with pytest.raises(CoreError, match="LEASE_FENCED"):
        authority.commit_mutation(
            mutation_id="prepared-a",
            permit=permit_a,
            payload={"writer": "a"},
            local_commit_id="local-a",
            audit_head_hash="old-writer-audit-head",
            audit_seq=checkpoint["audit_high_water"] + 1,
        )
    assert authority.export_checkpoint(genesis_request.continuity_id) == checkpoint
    permit_b = _prepare(authority, state.continuity_id, mutation_id="prepared-b")
    committed = _commit(authority, permit_b)
    assert committed.state == MutationState.COMMITTED
    assert authority.get_domain(state.continuity_id).state_version == 1


@pytest.fixture
def ready_authority():
    now = [datetime(2026, 9, 14, tzinfo=timezone.utc)]
    authority = InMemoryControlPlane(clock=lambda: now[0], lease_ttl_seconds=30)
    trust_id, continuity_id, storage_id = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    authority.prepare_genesis(trust_domain_id=trust_id, manifest_hash="manifest", request_id="genesis")
    authority.claim_genesis_storage(trust_domain_id=trust_id, request_id="genesis",
                                   storage_generation_id=storage_id)
    authority.initialize_domain(
        trust_domain_id=trust_id, identity_id=uuid.uuid4(), continuity_id=continuity_id,
        storage_generation_id=storage_id, control_plane_generation_id=uuid.uuid4(),
        owner_principal_id="owner", owner_key_fingerprint="owner-key",
        audit_high_water=1, audit_head_hash="genesis-head",
    )
    authority.record_genesis_core_commit(trust_domain_id=trust_id, request_id="genesis",
                                        storage_generation_id=storage_id, local_commit_id="genesis-local")
    authority.publish_genesis_anchor(trust_domain_id=trust_id, request_id="genesis",
                                     storage_generation_id=storage_id, anchor_hash="anchor")
    authority.complete_genesis(trust_domain_id=trust_id, request_id="genesis",
                               storage_generation_id=storage_id)
    _acquire(authority, continuity_id)
    return authority, continuity_id, now


def _acquire(authority, continuity_id):
    state = authority.get_domain(continuity_id)
    return authority.acquire_lease(
        continuity_id=continuity_id, principal_id=state.owner_principal_id,
        capability="core_governance", storage_generation_id=state.storage_generation_id,
    )


def _prepare(authority, continuity_id, *, mutation_id="mutation", **overrides):
    state = authority.get_domain(continuity_id)
    params = dict(
        continuity_id=continuity_id, epoch=state.epoch, lease_id=state.lease.lease_id,
        mutation_id=mutation_id, payload={"change": mutation_id},
        actor_principal_id=state.owner_principal_id, capability="core_writer",
        storage_generation_id=state.storage_generation_id,
        expected_state_version=state.state_version, local_commit_id="local-" + mutation_id,
    )
    params.update(overrides)
    return authority.prepare_mutation(**params)


def _commit(authority, permit, **overrides):
    state = authority.get_domain(permit.continuity_id)
    params = dict(
        mutation_id=permit.mutation_id, permit=permit,
        payload={"change": permit.mutation_id}, local_commit_id=permit.local_commit_id,
        audit_head_hash="head-" + permit.mutation_id, audit_seq=state.audit_high_water + 1,
    )
    params.update(overrides)
    return authority.commit_mutation(**params)


@pytest.mark.parametrize("seconds", [30, 31])
def test_lease_expiry_blocks_prepare_and_final_commit(ready_authority, seconds):
    authority, continuity_id, now = ready_authority
    permit = _prepare(authority, continuity_id)
    now[0] += timedelta(seconds=seconds)
    before = authority.export_checkpoint(continuity_id)
    with pytest.raises(CoreError, match="LEASE_FENCED"):
        _commit(authority, permit)
    with pytest.raises(CoreError, match="LEASE_FENCED"):
        _prepare(authority, continuity_id, mutation_id="expired")
    assert authority.export_checkpoint(continuity_id) == before
    assert authority._mutations[permit.mutation_id].state == MutationState.PREPARED


@pytest.mark.parametrize("drift,error", [
    ("epoch", "EPOCH_STALE"),
    ("storage_generation_id", "LEASE_FENCED"),
    ("state_version", "OWNER_VERSION_STALE"),
    ("lease_generation", "LEASE_FENCED"),
    ("quarantine", "RESTORE_FENCE_UNPROVEN"),
])
def test_final_commit_revalidates_current_authority_state(ready_authority, drift, error):
    authority, continuity_id, _now = ready_authority
    permit = _prepare(authority, continuity_id)
    state = authority.get_domain(continuity_id)
    if drift == "storage_generation_id":
        state.storage_generation_id = uuid.uuid4()
    elif drift == "lease_generation":
        state.lease = replace(state.lease, lease_generation=state.lease.lease_generation + 1)
    elif drift == "quarantine":
        authority.quarantine_recovery(continuity_id)
    else:
        setattr(state, drift, getattr(state, drift) + 1)
    before = authority.export_checkpoint(continuity_id)
    with pytest.raises(CoreError, match=error):
        _commit(authority, permit)
    assert authority.export_checkpoint(continuity_id) == before
    assert authority._mutations[permit.mutation_id].state == MutationState.PREPARED


def test_two_prepares_at_one_version_cannot_both_commit(ready_authority):
    authority, continuity_id, _now = ready_authority
    first = _prepare(authority, continuity_id, mutation_id="first")
    second = _prepare(authority, continuity_id, mutation_id="second")
    _commit(authority, first)
    before = authority.export_checkpoint(continuity_id)
    with pytest.raises(CoreError, match="OWNER_VERSION_STALE"):
        _commit(authority, second)
    assert authority.export_checkpoint(continuity_id) == before


@pytest.mark.parametrize("field,value", [
    ("payload_hash", "forged"), ("epoch", 10),
    ("lease_id", uuid.UUID("ce59e2e2-658c-4347-9d34-f018c6fe99dc")),
    ("storage_generation_id", uuid.UUID("ce59e2e2-658c-4347-9d34-f018c6fe99dc")),
    ("lease_generation", 100), ("expected_state_version", 10),
    ("assigned_state_version", 10), ("local_commit_id", "forged"),
    ("actor_principal_id", "forged"), ("capability", "core_governance"),
    ("state", MutationState.COMMITTED), ("audit_seq", 99),
])
def test_forged_permit_cannot_change_issued_intent(ready_authority, field, value):
    authority, continuity_id, _now = ready_authority
    permit = _prepare(authority, continuity_id)
    before = authority.export_checkpoint(continuity_id)
    forged = replace(permit, **{field: value})
    with pytest.raises(CoreError, match="MUTATION_RETRY_CONTEXT_CONFLICT"):
        _commit(authority, forged)
    assert authority.export_checkpoint(continuity_id) == before
    assert authority._mutations[permit.mutation_id] == permit


def test_issued_permit_is_an_immutable_detached_snapshot(ready_authority):
    authority, continuity_id, _now = ready_authority
    permit = _prepare(authority, continuity_id)
    with pytest.raises(FrozenInstanceError):
        permit.payload_hash = "forged"
    # Even bypassing the dataclass guard cannot mutate the authoritative record.
    object.__setattr__(permit, "assigned_state_version", 999)
    assert authority._mutations[permit.mutation_id].assigned_state_version == 1
    with pytest.raises(CoreError, match="MUTATION_RETRY_CONTEXT_CONFLICT"):
        _commit(authority, permit)


@pytest.mark.parametrize("change", [
    {"payload": {"unexpected": True}}, {"local_commit_id": "other-local"},
    {"audit_seq": 1}, {"audit_seq": 10}, {"audit_seq": True},
    {"audit_head_hash": ""},
])
def test_final_commit_rejects_unbound_payload_local_id_or_audit(ready_authority, change):
    authority, continuity_id, _now = ready_authority
    permit = _prepare(authority, continuity_id)
    before = authority.export_checkpoint(continuity_id)
    with pytest.raises(CoreError):
        _commit(authority, permit, **change)
    assert authority.export_checkpoint(continuity_id) == before
    assert authority._mutations[permit.mutation_id].state == MutationState.PREPARED


def test_terminal_retry_after_takeover_or_recovery_is_read_only(ready_authority):
    authority, continuity_id, _now = ready_authority
    permit = _prepare(authority, continuity_id)
    committed = _commit(authority, permit)
    _acquire(authority, continuity_id)
    authority.quarantine_recovery(continuity_id)
    before = authority.export_checkpoint(continuity_id)
    retried = _commit(authority, permit, audit_seq=committed.audit_seq)
    assert retried == committed
    assert retried.audit_head_hash == "head-mutation"
    assert authority.export_checkpoint(continuity_id) == before
    for change in ({"payload": {}}, {"local_commit_id": "different"},
                   {"audit_seq": committed.audit_seq + 1}, {"audit_head_hash": "different"}):
        with pytest.raises(CoreError, match="MUTATION_RETRY_CONTEXT_CONFLICT"):
            _commit(authority, permit, **{"audit_seq": committed.audit_seq, **change})
    assert authority.export_checkpoint(continuity_id) == before


@pytest.mark.parametrize("reservation_state", [
    GenesisState.CLAIMED, GenesisState.CORE_COMMITTED, GenesisState.ANCHOR_PUBLISHED,
])
def test_all_write_gates_require_terminal_genesis(ready_authority, reservation_state):
    authority, continuity_id, _now = ready_authority
    permit = _prepare(authority, continuity_id)
    state = authority.get_domain(continuity_id)
    authority._reservations[state.trust_domain_id].state = reservation_state
    before = authority.export_checkpoint(continuity_id)
    with pytest.raises(CoreError, match="GENESIS_OUTCOME_UNKNOWN"):
        _acquire(authority, continuity_id)
    with pytest.raises(CoreError, match="GENESIS_OUTCOME_UNKNOWN"):
        _prepare(authority, continuity_id, mutation_id="new")
    with pytest.raises(CoreError, match="GENESIS_OUTCOME_UNKNOWN"):
        _commit(authority, permit)
    with pytest.raises(CoreError, match="GENESIS_OUTCOME_UNKNOWN"):
        authority.transfer_owner(continuity_id=continuity_id, expected_owner_version=0,
                                 current_owner_principal_id="owner", target_principal_id="next",
                                 target_key_fingerprint="next-key")
    assert authority.export_checkpoint(continuity_id) == before


def test_checkpoint_and_genesis_status_require_fresh_quorum(ready_authority):
    authority, continuity_id, _now = ready_authority
    state = authority.get_domain(continuity_id)
    authority.available_witnesses = 1
    with pytest.raises(CoreError, match="CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE"):
        authority.export_checkpoint(continuity_id)
    with pytest.raises(CoreError, match="CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE"):
        authority.genesis_status(state.trust_domain_id)


@pytest.mark.parametrize("sync_before_failure", [False, True])
def test_recovery_stays_fenced_until_audit_sync_succeeds(
    ready_authority, monkeypatch, sync_before_failure,
):
    authority, continuity_id, _now = ready_authority
    state = authority.get_domain(continuity_id)
    authority.quarantine_recovery(continuity_id)
    authority.claim_recovery(
        request_id="restore", trust_domain_id=state.trust_domain_id,
        continuity_id=continuity_id, current_owner_principal_id=state.owner_principal_id,
        current_owner_record_hash=sha256_hex({"owner_version": state.owner_version,
            "owner_principal_id": state.owner_principal_id,
            "owner_key_fingerprint": state.owner_key_fingerprint}),
        target_storage_generation_id=uuid.uuid4(), restore_manifest_hash="restore-manifest",
    )
    claim = authority.activate_recovery("restore")
    before = authority.export_checkpoint(continuity_id)
    assert before["recovery_state"] == RecoveryState.PREPARED.value
    with pytest.raises(CoreError, match="RESTORE_FENCE_UNPROVEN"):
        _acquire(authority, continuity_id)
    sync = authority.sync_audit_checkpoint
    def fail_sync(**kwargs):
        if sync_before_failure:
            sync(**kwargs)
        raise CoreError("CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE")
    monkeypatch.setattr(authority, "sync_audit_checkpoint", fail_sync)
    with pytest.raises(CoreError, match="CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE"):
        authority.complete_recovery("restore", audit_seq=2, audit_head_hash="rebase")
    expected = {**before, "audit_high_water": 2, "audit_head_hash": "rebase"} if sync_before_failure else before
    assert authority.export_checkpoint(continuity_id) == expected
    assert authority.recovery_status("restore") == claim
    with pytest.raises(CoreError, match="RESTORE_FENCE_UNPROVEN"):
        _acquire(authority, continuity_id)
    monkeypatch.setattr(authority, "sync_audit_checkpoint", sync)
    completed = authority.complete_recovery("restore", audit_seq=2, audit_head_hash="rebase")
    assert completed["status"] == RecoveryState.ACTIVE.value
    assert _acquire(authority, continuity_id).lease_generation == 2
    assert authority.complete_recovery("restore", audit_seq=2, audit_head_hash="rebase") == completed
    with pytest.raises(CoreError, match="RESTORE_REQUEST_CONFLICT"):
        authority.complete_recovery("restore", audit_seq=2, audit_head_hash="forged")
