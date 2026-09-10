from __future__ import annotations

import copy
import uuid

import pytest
from sqlalchemy import select

from app.audit import verify_audit_chain
from app.errors import CoreError
from app.models import ContinuityRegistry, CoreMetadata, AuditLedger
from app.schemas import MutationRequest


def test_genesis_is_idempotent_but_manifest_immutable(foundation, genesis_request):
    service, factory, _authority = foundation
    first = service.bootstrap_genesis(genesis_request)
    second = service.bootstrap_genesis(genesis_request)
    assert first.genesis_id == second.genesis_id
    assert first.qingyu_identity_id == genesis_request.qingyu_identity_id
    with pytest.raises(CoreError, match="GENESIS_ALREADY_EXISTS"):
        service.bootstrap_genesis(genesis_request.model_copy(update={"genesis_nonce": "fedcba9876543210"}))

    with factory() as session:
        assert session.scalar(select(ContinuityRegistry.qingyu_identity_id)) == genesis_request.qingyu_identity_id
        assert session.scalar(select(CoreMetadata.audit_seq)) == 1


def test_alias_is_not_canonical_identity(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    with pytest.raises(CoreError, match="CONTINUITY_ALIAS_NOT_CANONICAL_ID"):
        service.require_canonical_continuity("qingyu-main")
    assert service.resolve_alias("qingyu-main") == genesis_request.continuity_id


def test_epoch_and_old_lease_are_fenced_after_owner_transfer(foundation, genesis_request):
    service, _factory, authority = foundation
    service.bootstrap_genesis(genesis_request)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    status = service.identity_status()
    service.transfer_owner(
        continuity_id=genesis_request.continuity_id,
        current_owner_principal_id="owner-1",
        expected_owner_version=0,
        target_principal_id="owner-2",
        target_key_fingerprint="owner-fingerprint-2",
    )
    with pytest.raises(CoreError, match="EPOCH_STALE|LEASE_FENCED"):
        service.governed_mutation(
            MutationRequest(
                continuity_id=genesis_request.continuity_id,
                continuity_epoch=status.continuity_epoch,
                lease_id=lease,
                mutation_id="stale-write",
                actor_principal_id="owner-1",
                capability="core_writer",
                payload={"x": 1},
            )
        )
    assert service.identity_status().status == "READY"
    assert authority.get_domain(genesis_request.continuity_id).epoch == 1


def test_audit_tamper_is_detected(foundation, genesis_request):
    service, factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    with factory.begin() as session:
        row = session.get(AuditLedger, 1)
        row.canonical_record = {"tampered": True}
    with factory() as session:
        with pytest.raises(CoreError, match="AUDIT_(INTEGRITY_FAILURE|CHAIN_INVALID)"):
            verify_audit_chain(session)


def test_governed_mutation_is_idempotent(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    request = MutationRequest(
        continuity_id=genesis_request.continuity_id,
        continuity_epoch=0,
        lease_id=lease,
        mutation_id="mutation-1",
        actor_principal_id="owner-1",
        capability="core_writer",
        payload={"kind": "foundation-test"},
    )
    first = service.governed_mutation(request)
    second = service.governed_mutation(request)
    assert first.status == "COMMITTED"
    assert second.local_commit_id == first.local_commit_id
    assert second.audit_seq == first.audit_seq


def test_authority_commit_failure_quarantines_without_advancing_local_state(
    foundation, genesis_request
):
    service, factory, authority = foundation
    service.bootstrap_genesis(genesis_request)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)

    original_commit = authority.commit_mutation

    def fail_commit(**kwargs):
        raise CoreError("CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE")

    authority.commit_mutation = fail_commit
    with pytest.raises(CoreError, match="CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE"):
        service.governed_mutation(
            MutationRequest(
                continuity_id=genesis_request.continuity_id,
                continuity_epoch=0,
                lease_id=lease,
                mutation_id="mutation-failure",
                actor_principal_id="owner-1",
                capability="core_writer",
                payload={"x": 1},
            )
        )
    authority.commit_mutation = original_commit
    with factory() as session:
        metadata = session.get(CoreMetadata, 1)
        assert metadata.status == "RESTORE_QUARANTINED"
        assert metadata.current_state_version == 0
