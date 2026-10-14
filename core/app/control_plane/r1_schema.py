"""Static R1 Authority PostgreSQL schema contract, not a migration or runtime store.

No engine, connection, DDL runner, role grant, or legacy-table adoption lives here.
R1-2 must review this metadata against signed provisioning and implement the
independent Alembic origin. Procedures/privileges, not table definitions alone,
must enforce immutable rows, CAS transitions and signature verification.
"""

from __future__ import annotations

from sqlalchemy import (
    BigInteger, CheckConstraint, Column, Computed, DateTime, ForeignKeyConstraint,
    Index, Integer, LargeBinary, MetaData, String, Table, UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID


SCHEMA = "control_plane"
R1_METADATA = MetaData(schema=SCHEMA)
_UUID = UUID(as_uuid=True)
_HASH = String(64)


origin = Table(
    "cp_origin", R1_METADATA,
    Column("singleton_id", Integer, primary_key=True),
    Column("provisioning_uuid", _UUID, nullable=False, unique=True),
    Column("authority_domain_id", _UUID, nullable=False, unique=True),
    Column("authority_instance_id", _UUID, nullable=False),
    Column("initial_authority_generation", BigInteger, nullable=False),
    Column("signed_provisioning_origin_digest", _HASH, nullable=False),
    Column("operator_root_key_id", _HASH, nullable=False),
    Column("cluster_system_identifier", String(32), nullable=False),
    Column("cluster_binding_fingerprint", _HASH, nullable=False),
    Column("database_name", String(128), nullable=False),
    Column("initial_revision", String(64), nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False),
    CheckConstraint("singleton_id = 1", name="ck_cp_origin_singleton"),
    CheckConstraint("initial_authority_generation = 1", name="ck_cp_origin_generation"),
    CheckConstraint("initial_revision = '0001_control_plane_r1_initial'", name="ck_cp_origin_revision"),
)


receipt_keys = Table(
    "cp_receipt_keys", R1_METADATA,
    Column("authority_domain_id", _UUID, primary_key=True),
    Column("receipt_key_id", _HASH, primary_key=True),
    Column("authority_instance_id", _UUID, nullable=False),
    Column("authority_generation", BigInteger, nullable=False),
    Column("public_key", LargeBinary(32), nullable=False),
    Column("signed_activation_digest", _HASH, nullable=False),
    Column("activated_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    Column("revocation_reason", String(512)),
    Column("signed_transition_digest", _HASH),
    ForeignKeyConstraint(["authority_domain_id"],
                         [f"{SCHEMA}.cp_origin.authority_domain_id"],
                         name="fk_cp_receipt_keys_origin"),
    UniqueConstraint("authority_domain_id", "authority_generation", "receipt_key_id",
                     name="uq_cp_receipt_keys_generation_key"),
    CheckConstraint("authority_generation > 0", name="ck_cp_receipt_keys_generation"),
    CheckConstraint("octet_length(public_key) = 32", name="ck_cp_receipt_keys_public_key"),
    CheckConstraint("(revoked_at IS NULL) = (revocation_reason IS NULL)",
                    name="ck_cp_receipt_keys_revocation"),
)


generations = Table(
    "cp_generations", R1_METADATA,
    Column("authority_domain_id", _UUID, primary_key=True),
    Column("authority_generation", BigInteger, primary_key=True),
    Column("authority_instance_id", _UUID, nullable=False),
    Column("receipt_key_id", _HASH, nullable=False),
    Column("status", String(16), nullable=False),
    Column("authority_sequence", BigInteger, nullable=False),
    Column("head_hash", _HASH, nullable=False),
    Column("seed_hash", _HASH, nullable=False),
    Column("signed_provisioning_origin_digest", _HASH),
    Column("previous_generation", BigInteger),
    Column("previous_generation_sequence", BigInteger),
    Column("previous_generation_head_hash", _HASH),
    Column("signed_dr_artifact_digest", _HASH),
    Column("dr_operation_id", _UUID),
    Column("opened_at", DateTime(timezone=True)),
    Column("sealed_at", DateTime(timezone=True)),
    ForeignKeyConstraint(["authority_domain_id"],
                         [f"{SCHEMA}.cp_origin.authority_domain_id"],
                         name="fk_cp_generations_origin"),
    ForeignKeyConstraint(["authority_domain_id", "authority_generation", "receipt_key_id"],
                         [f"{SCHEMA}.cp_receipt_keys.{name}" for name in
                          ("authority_domain_id", "authority_generation", "receipt_key_id")],
                         name="fk_cp_generations_key"),
    UniqueConstraint("authority_domain_id", "authority_generation",
                     "authority_instance_id", name="uq_cp_generations_instance"),
    CheckConstraint("authority_generation > 0", name="ck_cp_generations_positive"),
    CheckConstraint("authority_sequence >= 0", name="ck_cp_generations_sequence"),
    CheckConstraint("status IN ('PENDING', 'ACTIVE', 'SEALED')", name="ck_cp_generations_status"),
    CheckConstraint("status = 'PENDING' OR (authority_sequence >= 1 AND opened_at IS NOT NULL)",
                    name="ck_cp_generations_opened"),
    CheckConstraint("(status = 'SEALED') = (sealed_at IS NOT NULL)",
                    name="ck_cp_generations_sealed"),
    CheckConstraint("(authority_generation = 1 AND signed_provisioning_origin_digest IS NOT NULL "
                    "AND previous_generation IS NULL AND previous_generation_sequence IS NULL "
                    "AND previous_generation_head_hash IS NULL AND signed_dr_artifact_digest IS NULL "
                    "AND dr_operation_id IS NULL) OR (authority_generation > 1 "
                    "AND signed_provisioning_origin_digest IS NULL "
                    "AND previous_generation IS NOT NULL "
                    "AND previous_generation = authority_generation - 1 "
                    "AND previous_generation_sequence > 0 "
                    "AND previous_generation_head_hash IS NOT NULL "
                    "AND signed_dr_artifact_digest IS NOT NULL AND dr_operation_id IS NOT NULL)",
                    name="ck_cp_generations_origin_or_dr"),
    Index("ux_cp_generations_one_active", "authority_domain_id", unique=True,
          postgresql_where=text("status = 'ACTIVE'")),
    Index("ux_cp_generations_dr_operation", "authority_domain_id", "dr_operation_id",
          unique=True, postgresql_where=text("dr_operation_id IS NOT NULL")),
)


runtime_sessions = Table(
    "cp_runtime_sessions", R1_METADATA,
    Column("authority_domain_id", _UUID, primary_key=True),
    Column("caller_runtime_id", _UUID, primary_key=True),
    Column("session_id", _UUID, primary_key=True),
    Column("continuity_id", _UUID, nullable=False),
    Column("storage_generation_id", _UUID, nullable=False),
    Column("process_nonce_hash", _HASH, nullable=False),
    Column("session_state", String(16), nullable=False),
    Column("claimed_at", DateTime(timezone=True), nullable=False),
    Column("last_heartbeat_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    ForeignKeyConstraint(["authority_domain_id"],
                         [f"{SCHEMA}.cp_origin.authority_domain_id"],
                         name="fk_cp_runtime_sessions_origin"),
    UniqueConstraint("authority_domain_id", "continuity_id", "caller_runtime_id",
                     "session_id", name="uq_cp_runtime_sessions_lease_scope"),
    UniqueConstraint("authority_domain_id", "continuity_id", "caller_runtime_id",
                     "session_id", "storage_generation_id",
                     name="uq_cp_runtime_sessions_storage_scope"),
    CheckConstraint("session_state IN ('ACTIVE', 'REVOKED')",
                    name="ck_cp_runtime_sessions_state"),
    CheckConstraint("claimed_at <= last_heartbeat_at AND last_heartbeat_at < expires_at",
                    name="ck_cp_runtime_sessions_times"),
    CheckConstraint("(session_state = 'ACTIVE' AND revoked_at IS NULL) "
                    "OR (session_state = 'REVOKED' AND revoked_at IS NOT NULL)",
                    name="ck_cp_runtime_sessions_revoked"),
    Index("ux_cp_runtime_sessions_active_runtime", "authority_domain_id",
          "caller_runtime_id", unique=True,
          postgresql_where=text("session_state = 'ACTIVE'")),
    Index("ux_cp_runtime_sessions_active_continuity", "authority_domain_id",
          "continuity_id", unique=True,
          postgresql_where=text("session_state = 'ACTIVE'")),
)


continuities = Table(
    "cp_continuities", R1_METADATA,
    Column("authority_domain_id", _UUID, primary_key=True),
    Column("continuity_id", _UUID, primary_key=True),
    Column("qingyu_identity_id", _UUID, nullable=False),
    Column("continuity_epoch", BigInteger, nullable=False),
    Column("state_version", BigInteger, nullable=False),
    Column("active_storage_generation_id", _UUID, nullable=False),
    Column("control_plane_generation_id", _UUID, nullable=False),
    Column("owner_identity", String(256), nullable=False),
    Column("owner_key_id", _HASH, nullable=False),
    Column("owner_record_hash", _HASH, nullable=False),
    Column("owner_version", BigInteger, nullable=False),
    Column("lease_generation", BigInteger, nullable=False),
    Column("lease_runtime_id", _UUID),
    Column("lease_session_id", _UUID),
    Column("lease_storage_generation_id", _UUID),
    Column("lease_epoch", BigInteger),
    Column("lease_acquired_at", DateTime(timezone=True)),
    Column("lease_last_heartbeat_at", DateTime(timezone=True)),
    Column("lease_expires_at", DateTime(timezone=True)),
    Column("lease_status", String(16), nullable=False),
    Column("admission_state", String(16), nullable=False),
    ForeignKeyConstraint(["authority_domain_id"],
                         [f"{SCHEMA}.cp_origin.authority_domain_id"],
                         name="fk_cp_continuities_origin"),
    ForeignKeyConstraint(["authority_domain_id", "continuity_id", "lease_runtime_id",
                          "lease_session_id", "lease_storage_generation_id"],
                         [f"{SCHEMA}.cp_runtime_sessions.{name}" for name in
                          ("authority_domain_id", "continuity_id", "caller_runtime_id",
                           "session_id", "storage_generation_id")],
                         name="fk_cp_continuities_runtime_session"),
    UniqueConstraint("authority_domain_id", "qingyu_identity_id",
                     name="uq_cp_continuities_identity_1to1"),
    CheckConstraint("continuity_epoch > 0 AND state_version >= 0 AND owner_version > 0 "
                    "AND lease_generation >= 0", name="ck_cp_continuities_versions"),
    CheckConstraint("lease_status IN ('NONE', 'ACTIVE', 'REVOKED')",
                    name="ck_cp_continuities_lease_status"),
    CheckConstraint("admission_state IN ('OPEN', 'DRAINING', 'CLOSED')",
                    name="ck_cp_continuities_admission"),
    CheckConstraint("(lease_status = 'ACTIVE' AND lease_runtime_id IS NOT NULL "
                    "AND lease_session_id IS NOT NULL AND lease_storage_generation_id IS NOT NULL "
                    "AND lease_storage_generation_id = active_storage_generation_id "
                    "AND lease_epoch IS NOT NULL AND lease_epoch = continuity_epoch "
                    "AND lease_acquired_at IS NOT NULL AND lease_last_heartbeat_at IS NOT NULL "
                    "AND lease_expires_at IS NOT NULL "
                    "AND lease_acquired_at <= lease_last_heartbeat_at "
                    "AND lease_last_heartbeat_at < lease_expires_at) "
                    "OR (lease_status <> 'ACTIVE' AND lease_runtime_id IS NULL "
                    "AND lease_session_id IS NULL AND lease_storage_generation_id IS NULL "
                    "AND lease_epoch IS NULL AND lease_acquired_at IS NULL "
                    "AND lease_last_heartbeat_at IS NULL AND lease_expires_at IS NULL)",
                    name="ck_cp_continuities_active_lease_scope"),
)


operations = Table(
    "cp_operations", R1_METADATA,
    Column("authority_domain_id", _UUID, primary_key=True),
    Column("operation_id", _UUID, primary_key=True),
    Column("authority_generation", BigInteger, nullable=False),
    Column("authority_instance_id", _UUID, nullable=False),
    Column("qingyu_identity_id", _UUID, nullable=False),
    Column("continuity_id", _UUID, nullable=False),
    # GENESIS must durably PREPARE before a continuity becomes real. A generated
    # nullable FK exempts only that operation type; every other operation still
    # requires an existing continuity. The terminal GENESIS procedure creates
    # the continuity atomically with its COMMITTED receipt.
    Column("existing_continuity_id", _UUID,
           Computed("CASE WHEN operation_type = 'AUTHORITY_GENESIS_ACTIVATION' "
                    "THEN NULL ELSE continuity_id END", persisted=True)),
    Column("operation_type", String(64), nullable=False),
    Column("request_envelope_hash", _HASH, nullable=False),
    Column("request_envelope", JSONB, nullable=False),
    Column("caller_runtime_id", _UUID, nullable=False),
    Column("storage_generation_id", _UUID, nullable=False),
    Column("actor_or_owner_identity", String(256), nullable=False),
    Column("expected_continuity_epoch", BigInteger, nullable=False),
    Column("expected_state_version", BigInteger, nullable=False),
    Column("expected_owner_version", BigInteger, nullable=False),
    Column("state", String(16), nullable=False),
    Column("prepared_at", DateTime(timezone=True), nullable=False),
    Column("prepare_ack", JSONB, nullable=False),
    Column("staged_result_hash", _HASH, nullable=False),
    Column("core_audit_predecessor_hash", _HASH, nullable=False),
    Column("core_audit_candidate_hash", _HASH, nullable=False),
    Column("local_commit_attestation_hash", _HASH),
    Column("result_code", String(64)),
    Column("result_payload_hash", _HASH),
    Column("result_payload", JSONB),
    Column("continuity_epoch", BigInteger),
    Column("control_plane_generation_id", _UUID),
    Column("owner_version", BigInteger),
    Column("lease_generation", BigInteger),
    Column("receipt_key_id", _HASH),
    Column("authority_sequence", BigInteger),
    Column("previous_receipt_hash", _HASH),
    Column("receipt_hash", _HASH),
    Column("receipt_payload", JSONB),
    Column("receipt_signature", LargeBinary(64)),
    Column("decided_at", DateTime(timezone=True)),
    ForeignKeyConstraint(["authority_domain_id", "authority_generation",
                          "authority_instance_id"],
                         [f"{SCHEMA}.cp_generations.{name}" for name in
                          ("authority_domain_id", "authority_generation",
                           "authority_instance_id")],
                         name="fk_cp_operations_generation"),
    ForeignKeyConstraint(["authority_domain_id", "existing_continuity_id"],
                         [f"{SCHEMA}.cp_continuities.{name}" for name in
                          ("authority_domain_id", "continuity_id")],
                         name="fk_cp_operations_continuity"),
    CheckConstraint("state IN ('PREPARED', 'COMMITTED', 'ABORTED')",
                    name="ck_cp_operations_state"),
    CheckConstraint("expected_continuity_epoch >= 0 AND expected_state_version >= 0 "
                    "AND expected_owner_version >= 0", name="ck_cp_operations_expected_versions"),
    CheckConstraint("(state = 'PREPARED' AND authority_sequence IS NULL "
                    "AND previous_receipt_hash IS NULL AND receipt_hash IS NULL "
                    "AND receipt_payload IS NULL AND receipt_signature IS NULL "
                    "AND decided_at IS NULL AND result_code IS NULL AND result_payload_hash IS NULL "
                    "AND result_payload IS NULL AND continuity_epoch IS NULL "
                    "AND control_plane_generation_id IS NULL AND owner_version IS NULL "
                    "AND lease_generation IS NULL AND receipt_key_id IS NULL) "
                    "OR (state IN ('COMMITTED', 'ABORTED') "
                    "AND authority_sequence IS NOT NULL AND authority_sequence > 0 "
                    "AND previous_receipt_hash IS NOT NULL "
                    "AND receipt_hash IS NOT NULL AND receipt_payload IS NOT NULL "
                    "AND receipt_signature IS NOT NULL "
                    "AND octet_length(receipt_signature) = 64 AND decided_at IS NOT NULL "
                    "AND result_code IS NOT NULL AND result_payload_hash IS NOT NULL "
                    "AND result_payload IS NOT NULL AND continuity_epoch IS NOT NULL "
                    "AND continuity_epoch > 0 AND control_plane_generation_id IS NOT NULL "
                    "AND owner_version IS NOT NULL AND owner_version > 0 "
                    "AND receipt_key_id IS NOT NULL)", name="ck_cp_operations_terminal_shape"),
    Index("ux_cp_operations_one_unresolved", "authority_domain_id", "continuity_id",
          unique=True, postgresql_where=text("state = 'PREPARED'")),
    Index("ux_cp_operations_terminal_sequence", "authority_domain_id",
          "authority_generation", "authority_sequence", unique=True,
          postgresql_where=text("authority_sequence IS NOT NULL")),
    Index("ux_cp_operations_receipt_hash", "authority_domain_id", "receipt_hash",
          unique=True, postgresql_where=text("receipt_hash IS NOT NULL")),
)


def validate_static_schema() -> None:
    """Check the in-process contract; never introspect or mutate a database."""
    expected = {"cp_origin", "cp_receipt_keys", "cp_generations",
                "cp_runtime_sessions", "cp_continuities", "cp_operations"}
    actual = {table.name for table in R1_METADATA.tables.values()}
    if actual != expected or any(table.schema != SCHEMA for table in R1_METADATA.tables.values()):
        raise ValueError("R1 Authority metadata table/schema drift")
    if any(name in actual for name in ("cp_witnesses", "cp_quorum_acks")):
        raise ValueError("pseudo-quorum objects forbidden")
    R1_METADATA.sorted_tables  # Resolve all foreign keys; does not touch a DB.
