from __future__ import annotations

import uuid
from copy import deepcopy

import pytest

from app.errors import CoreError
from app.foundation_rehearsal import (
    PersistentRehearsalAuthority,
    PostgresAuthorityStateStore,
    build_restore_request,
    verify_backup_metadata,
)
from tests.test_foundation_closure_rehearsal import (
    FoundationPostgresEnvironment,
    genesis_request,
    mutation_request,
)


def persistent_authority(env: FoundationPostgresEnvironment) -> PersistentRehearsalAuthority:
    env.create_database("foundation_authority")
    return PersistentRehearsalAuthority(PostgresAuthorityStateStore(env.url("foundation_authority")))


def restart_authority(env: FoundationPostgresEnvironment) -> PersistentRehearsalAuthority:
    return PersistentRehearsalAuthority(PostgresAuthorityStateStore(env.url("foundation_authority")))


@pytest.mark.integration
def test_quarantine_and_reactivation_survive_authority_restart(tmp_path):
    env = FoundationPostgresEnvironment(tmp_path).create()
    try:
        authority = persistent_authority(env)
        source, _ = env.service("foundation_source", authority)
        request = genesis_request()
        source.bootstrap_genesis(request)
        lease = source.acquire_owner_lease(request.continuity_id)
        source.governed_mutation(mutation_request(request, lease))
        read_v1 = source.core_read_model()
        dump_path = tmp_path / "source.sql"
        env.dump("foundation_source", dump_path)
        trust_anchor = authority.export_checkpoint(request.continuity_id)
        metadata = {
            "backup_path": str(dump_path),
            "trust_anchor": trust_anchor,
            "read_model_hash": read_v1.read_model_hash,
        }

        env.restore("foundation_restore", dump_path)
        authority = restart_authority(env)
        restored, _ = env.service("foundation_restore", authority)
        restore_request = build_restore_request(request_id="restore-persistent-1", read_model=read_v1, target_storage_generation_id=uuid.uuid4())
        verification = restored.verify_restore(restore_request)
        assert verification.read_only is True
        assert authority.export_checkpoint(request.continuity_id)["recovery_state"] == "RESTORE_QUARANTINED"

        authority = restart_authority(env)
        restored_after_restart, _ = env.service("foundation_restore", authority)
        with pytest.raises(CoreError, match="RESTORE_FENCE_UNPROVEN"):
            restored_after_restart.acquire_owner_lease(request.continuity_id)
        assert authority.export_checkpoint(request.continuity_id)["recovery_state"] == "RESTORE_QUARANTINED"

        activated = restored_after_restart.activate_restore(restore_request)
        assert activated.read_only is False
        assert authority.export_checkpoint(request.continuity_id)["recovery_state"] == "ACTIVE"
        active_hash = restored_after_restart.core_read_model().read_model_hash

        authority = restart_authority(env)
        active_after_restart, _ = env.service("foundation_restore", authority)
        assert active_after_restart.core_read_model().read_model_hash == active_hash
        next_lease = active_after_restart.acquire_owner_lease(request.continuity_id)
        result = active_after_restart.governed_mutation(mutation_request(
            request, next_lease, "mutation-after-persistent-reactivation",
            epoch=active_after_restart.core_read_model().generation["continuity_epoch"],
        ))
        assert result.status == "COMMITTED"
        assert authority.persistence_summary()["present"] is True
        assert metadata["read_model_hash"] == read_v1.read_model_hash
    finally:
        env.destroy()


@pytest.mark.integration
def test_durable_genesis_continuation_no_regenesis_and_response_loss(tmp_path):
    env = FoundationPostgresEnvironment(tmp_path).create()
    try:
        authority = persistent_authority(env)
        service, _ = env.service("foundation_source", authority)
        request = genesis_request()
        first = service.bootstrap_genesis(request)
        read_v0 = service.core_read_model()

        authority = restart_authority(env)
        restarted, _ = env.service("foundation_source", authority)
        replay = restarted.bootstrap_genesis(request)
        assert replay.genesis_id == first.genesis_id
        assert replay.qingyu_identity_id == first.qingyu_identity_id
        assert restarted.core_read_model().model_dump(mode="json") == read_v0.model_dump(mode="json")

        changed = request.model_copy(update={"genesis_request_id": "different-genesis", "continuity_id": uuid.uuid4()})
        with pytest.raises(CoreError, match="GENESIS_ALREADY_EXISTS|GENESIS_CONFLICT"):
            restarted.bootstrap_genesis(changed)

        # Simulate response loss after durable GENESIS by constructing a fresh service
        # and authority wrapper; retry must return the original durable result.
        authority = restart_authority(env)
        response_loss_retry, _ = env.service("foundation_source", authority)
        again = response_loss_retry.bootstrap_genesis(request)
        assert again.genesis_id == first.genesis_id
        assert again.storage_generation_id == first.storage_generation_id
    finally:
        env.destroy()


@pytest.mark.integration
def test_restore_anchor_expanded_negatives_and_reactivation_replay(tmp_path):
    env = FoundationPostgresEnvironment(tmp_path).create()
    try:
        authority = persistent_authority(env)
        source, _ = env.service("foundation_source", authority)
        request = genesis_request()
        source.bootstrap_genesis(request)
        lease = source.acquire_owner_lease(request.continuity_id)
        source.governed_mutation(mutation_request(request, lease))
        read_v1 = source.core_read_model()
        dump_path = tmp_path / "source.sql"
        env.dump("foundation_source", dump_path)
        from app.foundation_rehearsal import backup_metadata
        backup = backup_metadata(backup_path=dump_path, source_read_model=read_v1, trust_anchor=authority.export_checkpoint(request.continuity_id))

        wrong_continuity = build_restore_request(request_id="wrong-continuity", read_model=read_v1, target_storage_generation_id=uuid.uuid4())
        wrong_continuity = wrong_continuity.model_copy(update={"manifest": wrong_continuity.manifest.model_copy(update={"continuity_id": uuid.uuid4()})})
        with pytest.raises(CoreError, match="RESTORE_IDENTITY_MISMATCH|CONTINUITY_UNKNOWN"):
            source.verify_restore(wrong_continuity)

        wrong_checkpoint = deepcopy(backup)
        wrong_checkpoint["canonical_payload_sha256"] = "0" * 64
        with pytest.raises(CoreError, match="FOUNDATION_BACKUP_CANONICAL_HASH_MISMATCH"):
            verify_backup_metadata(wrong_checkpoint, backup_path=dump_path, expected_read_model=read_v1, expected_trust_anchor=authority.export_checkpoint(request.continuity_id))

        wrong_schema = deepcopy(backup)
        wrong_schema["schema_version"] = "wrong-version"
        with pytest.raises(CoreError, match="FOUNDATION_BACKUP_METADATA_MALFORMED"):
            verify_backup_metadata(wrong_schema, backup_path=dump_path, expected_read_model=read_v1, expected_trust_anchor=authority.export_checkpoint(request.continuity_id))

        wrong_external_anchor = deepcopy(backup)
        wrong_external_anchor["trust_anchor"] = {**wrong_external_anchor["trust_anchor"], "state_version": 999}
        with pytest.raises(CoreError, match="FOUNDATION_BACKUP_TRUST_ANCHOR_MISMATCH"):
            verify_backup_metadata(wrong_external_anchor, backup_path=dump_path, expected_read_model=read_v1, expected_trust_anchor=authority.export_checkpoint(request.continuity_id))

        env.restore("foundation_restore", dump_path)
        authority = restart_authority(env)
        restored, _ = env.service("foundation_restore", authority)
        restore_request = build_restore_request(request_id="restore-replay", read_model=read_v1, target_storage_generation_id=uuid.uuid4())
        restored.verify_restore(restore_request)
        first = restored.activate_restore(restore_request)
        second = restored.activate_restore(restore_request)
        assert first == second
        changed_instance = restore_request.model_copy(update={"target_storage_generation_id": uuid.uuid4()})
        with pytest.raises(CoreError, match="RESTORE_REQUEST_CONFLICT"):
            restored.activate_restore(changed_instance)
    finally:
        env.destroy()


@pytest.mark.integration
def test_pre_durable_genesis_retry_allowed_and_conflict_rejected(tmp_path):
    env = FoundationPostgresEnvironment(tmp_path).create()
    try:
        authority = persistent_authority(env)
        request = genesis_request()
        first = authority.prepare_genesis(
            trust_domain_id=request.trust_domain_id,
            manifest_hash="a" * 64,
            request_id=request.genesis_request_id,
        )
        second = authority.prepare_genesis(
            trust_domain_id=request.trust_domain_id,
            manifest_hash="a" * 64,
            request_id=request.genesis_request_id,
        )
        assert second == first

        authority = restart_authority(env)
        third = authority.prepare_genesis(
            trust_domain_id=request.trust_domain_id,
            manifest_hash="a" * 64,
            request_id=request.genesis_request_id,
        )
        assert third == first
        with pytest.raises(CoreError, match="GENESIS_CONFLICT"):
            authority.prepare_genesis(
                trust_domain_id=request.trust_domain_id,
                manifest_hash="b" * 64,
                request_id="changed-request",
            )
    finally:
        env.destroy()
