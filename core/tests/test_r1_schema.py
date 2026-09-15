"""Static metadata tests: no PostgreSQL connection or DDL execution."""

from sqlalchemy import CheckConstraint, ForeignKeyConstraint, Index
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from app.control_plane.r1_schema import R1_METADATA, SCHEMA, validate_static_schema


def _table(name: str):
    return R1_METADATA.tables[f"{SCHEMA}.{name}"]


def _checks(name: str) -> str:
    return " ".join(str(c.sqltext) for c in _table(name).constraints
                    if isinstance(c, CheckConstraint))


def test_isolated_authority_schema_and_no_pseudo_quorum() -> None:
    validate_static_schema()
    assert {table.name for table in R1_METADATA.tables.values()} == {
        "cp_origin", "cp_receipt_keys", "cp_generations", "cp_runtime_sessions",
        "cp_continuities", "cp_operations"
    }
    assert all(table.schema == "control_plane" for table in R1_METADATA.tables.values())
    assert not any("witness" in key or "quorum" in key for key in R1_METADATA.tables)


def test_origin_generation_and_key_history_constraints() -> None:
    origin = _table("cp_origin")
    assert {"provisioning_uuid", "authority_domain_id", "cluster_system_identifier",
            "cluster_binding_fingerprint", "signed_provisioning_origin_digest",
            "operator_root_key_id", "initial_revision"} <= set(origin.c.keys())
    assert "singleton_id = 1" in _checks("cp_origin")
    assert "initial_authority_generation = 1" in _checks("cp_origin")
    keys = _table("cp_receipt_keys")
    assert {"public_key", "signed_activation_digest", "signed_transition_digest",
            "revoked_at", "revocation_reason"} <= set(keys.c.keys())
    assert "octet_length(public_key) = 32" in _checks("cp_receipt_keys")
    generations = _table("cp_generations")
    assert {"authority_sequence", "head_hash", "seed_hash", "previous_generation",
            "previous_generation_sequence", "previous_generation_head_hash",
            "signed_dr_artifact_digest", "dr_operation_id"} <= set(generations.c.keys())
    assert "authority_sequence >= 0" in _checks("cp_generations")
    assert "status = 'PENDING' OR (authority_sequence >= 1 AND opened_at IS NOT NULL)" in _checks("cp_generations")
    assert "previous_generation = authority_generation - 1" in _checks("cp_generations")
    assert any(isinstance(i, Index) and i.unique and i.name == "ux_cp_generations_one_active"
               and "status = 'ACTIVE'" in str(i.dialect_options["postgresql"]["where"])
               for i in generations.indexes)


def test_continuity_one_to_one_epoch_owner_and_lease() -> None:
    table = _table("cp_continuities")
    assert {"qingyu_identity_id", "continuity_epoch", "state_version",
            "active_storage_generation_id", "control_plane_generation_id",
            "owner_identity", "owner_key_id", "owner_record_hash", "owner_version",
            "lease_generation", "lease_runtime_id", "lease_storage_generation_id",
            "lease_epoch", "lease_session_id", "lease_acquired_at",
            "lease_last_heartbeat_at", "lease_expires_at", "lease_status",
            "admission_state"} <= set(table.c.keys())
    assert any(c.name == "uq_cp_continuities_identity_1to1" for c in table.constraints)
    assert "lease_epoch = continuity_epoch" in _checks("cp_continuities")
    assert "lease_storage_generation_id = active_storage_generation_id" in _checks("cp_continuities")
    assert "lease_last_heartbeat_at < lease_expires_at" in _checks("cp_continuities")
    assert "DRAINING" in _checks("cp_continuities")
    assert any(c.name == "fk_cp_continuities_runtime_session"
               and {column.name for column in c.columns} == {
                   "authority_domain_id", "continuity_id", "lease_runtime_id",
                   "lease_session_id", "lease_storage_generation_id"}
               for c in table.constraints)


def test_runtime_sessions_detect_duplicate_active_runtime_and_scope_expiry() -> None:
    table = _table("cp_runtime_sessions")
    assert {"caller_runtime_id", "session_id", "continuity_id", "storage_generation_id",
            "process_nonce_hash", "last_heartbeat_at", "expires_at",
            "session_state"} <= set(table.c.keys())
    assert {c.name for c in table.primary_key} == {
        "authority_domain_id", "caller_runtime_id", "session_id"}
    assert "last_heartbeat_at < expires_at" in _checks("cp_runtime_sessions")
    indexes = {i.name: i for i in table.indexes}
    assert indexes["ux_cp_runtime_sessions_active_runtime"].unique
    assert indexes["ux_cp_runtime_sessions_active_continuity"].unique
    assert str(indexes["ux_cp_runtime_sessions_active_runtime"].dialect_options["postgresql"]["where"]) == "session_state = 'ACTIVE'"


def test_operation_ledger_terminal_shape_and_exclusive_barrier() -> None:
    table = _table("cp_operations")
    assert {"operation_id", "request_envelope_hash", "request_envelope", "prepare_ack",
            "staged_result_hash", "core_audit_predecessor_hash", "core_audit_candidate_hash",
            "local_commit_attestation_hash", "result_payload_hash", "result_payload",
            "continuity_epoch", "control_plane_generation_id", "owner_version",
            "lease_generation", "receipt_key_id",
            "authority_sequence", "previous_receipt_hash", "receipt_hash",
            "receipt_payload", "receipt_signature", "decided_at"} <= set(table.c.keys())
    assert {"authority_domain_id", "operation_id"} == {c.name for c in table.primary_key}
    checks = _checks("cp_operations")
    assert "state IN ('PREPARED', 'COMMITTED', 'ABORTED')" in checks
    assert "state = 'PREPARED' AND authority_sequence IS NULL" in checks
    assert "receipt_signature IS NOT NULL AND octet_length(receipt_signature) = 64" in checks
    assert "authority_sequence IS NOT NULL AND authority_sequence > 0" in checks
    indexes = {i.name: i for i in table.indexes}
    assert indexes["ux_cp_operations_one_unresolved"].unique
    assert [c.name for c in indexes["ux_cp_operations_one_unresolved"].columns] == [
        "authority_domain_id", "continuity_id"]
    assert str(indexes["ux_cp_operations_one_unresolved"].dialect_options["postgresql"]["where"]) == "state = 'PREPARED'"
    assert indexes["ux_cp_operations_terminal_sequence"].unique
    assert [c.name for c in indexes["ux_cp_operations_terminal_sequence"].columns] == [
        "authority_domain_id", "authority_generation", "authority_sequence"]
    assert "AUTHORITY_GENESIS_ACTIVATION" in str(table.c.existing_continuity_id.computed.sqltext)
    assert any(isinstance(c, ForeignKeyConstraint)
               and {col.name for col in c.columns} == {
                   "authority_domain_id", "existing_continuity_id"}
               for c in table.constraints)
    assert any(isinstance(c, ForeignKeyConstraint)
               and {col.name for col in c.columns} == {
                   "authority_domain_id", "authority_generation", "authority_instance_id"}
               for c in table.constraints)
    assert "CREATE TABLE control_plane.cp_operations" in str(
        CreateTable(table).compile(dialect=postgresql.dialect()))
