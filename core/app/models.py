from __future__ import annotations

from datetime import datetime
import uuid

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    JSON,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import Uuid

from .db import Base


def utcnow() -> datetime:
    return datetime.utcnow()


class CoreMetadata(Base):
    __tablename__ = "core_metadata"
    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    trust_domain_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True), unique=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="UNINITIALIZED")
    active_storage_generation_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    control_plane_generation_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    current_state_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    audit_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    audit_head_hash: Mapped[str | None] = mapped_column(String(64))
    genesis_fingerprint: Mapped[str | None] = mapped_column(String(64))
    witness_set_version: Mapped[str | None] = mapped_column(String(64))
    initial_owner_fingerprint: Mapped[str | None] = mapped_column(String(128))
    current_owner_principal_id: Mapped[str | None] = mapped_column(String(256))
    current_owner_key_fingerprint: Mapped[str | None] = mapped_column(String(128))
    owner_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (
        CheckConstraint("id = 1", name="ck_core_metadata_singleton"),
        CheckConstraint("current_state_version >= 0", name="ck_core_metadata_state_version"),
        CheckConstraint("audit_seq >= 0", name="ck_core_metadata_audit_seq"),
        CheckConstraint("owner_version >= 0", name="ck_core_metadata_owner_version"),
    )


class GenesisRecord(Base):
    __tablename__ = "genesis_records"
    genesis_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    trust_domain_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, unique=True)
    qingyu_identity_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, unique=True)
    continuity_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False, unique=True)
    continuity_alias: Mapped[str] = mapped_column(String(128), nullable=False)
    genesis_version: Mapped[str] = mapped_column(String(64), nullable=False)
    id_scheme: Mapped[str] = mapped_column(String(32), nullable=False, default="uuidv4")
    initial_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    genesis_nonce: Mapped[str] = mapped_column(String(128), nullable=False)
    constitution_genesis_ref: Mapped[str | None] = mapped_column(String(256))
    constitution_genesis_hash: Mapped[str | None] = mapped_column(String(64))
    initial_owner_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    witness_set_version: Mapped[str] = mapped_column(String(64), nullable=False)
    witness_set_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    quorum_threshold: Mapped[int] = mapped_column(Integer, nullable=False, default=2)
    protocol_version: Mapped[str] = mapped_column(String(64), nullable=False, default="core-foundation-v1")
    actor_principal_id: Mapped[str] = mapped_column(String(256), nullable=False)
    governance_provenance: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (
        CheckConstraint("initial_epoch = 0", name="ck_genesis_initial_epoch"),
        CheckConstraint("quorum_threshold = 2", name="ck_genesis_quorum"),
    )


class IdentityRegistry(Base):
    __tablename__ = "identity_registry"
    qingyu_identity_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True
    )
    genesis_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("genesis_records.genesis_id"), nullable=False, unique=True
    )
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ContinuityRegistry(Base):
    __tablename__ = "continuity_registry"
    continuity_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True)
    qingyu_identity_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("identity_registry.qingyu_identity_id"),
        nullable=False,
        unique=True,
    )
    continuity_alias: Mapped[str | None] = mapped_column(String(128), unique=True)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (
        UniqueConstraint("qingyu_identity_id", name="uq_continuity_identity_one_to_one"),
    )


class ContinuityAlias(Base):
    __tablename__ = "continuity_aliases"
    alias: Mapped[str] = mapped_column(String(128), primary_key=True)
    continuity_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("continuity_registry.continuity_id"), nullable=False
    )
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    tombstoned_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class ControlPlaneState(Base):
    __tablename__ = "control_plane_state"
    continuity_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("continuity_registry.continuity_id"), primary_key=True
    )
    current_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    state_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    owner_version: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    owner_principal_id: Mapped[str] = mapped_column(String(256), nullable=False)
    owner_key_fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    lease_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    lease_generation: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="READY")
    active_storage_generation_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    control_plane_generation_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (
        CheckConstraint("current_epoch >= 0", name="ck_control_epoch"),
        CheckConstraint("state_version >= 0", name="ck_control_state_version"),
        CheckConstraint("owner_version >= 0", name="ck_control_owner_version"),
        CheckConstraint("lease_generation >= 0", name="ck_control_lease_generation"),
    )


class AuditLedger(Base):
    __tablename__ = "audit_ledger"
    audit_seq: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    trust_domain_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    continuity_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    continuity_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)
    state_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    operation_type: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_principal_id: Mapped[str] = mapped_column(String(256), nullable=False)
    capability: Mapped[str] = mapped_column(String(128), nullable=False)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    mutation_id: Mapped[str | None] = mapped_column(String(128))
    result_code: Mapped[str] = mapped_column(String(64), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_record_hash: Mapped[str | None] = mapped_column(String(64))
    record_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    canonical_record: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (
        CheckConstraint("audit_seq >= 1", name="ck_audit_seq_positive"),
        Index("ix_audit_continuity_seq", "continuity_id", "audit_seq"),
    )


class MutationReceipt(Base):
    __tablename__ = "mutation_receipts"
    mutation_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    continuity_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("continuity_registry.continuity_id"), nullable=False
    )
    continuity_epoch: Mapped[int] = mapped_column(BigInteger, nullable=False)
    storage_generation_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    payload_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expected_state_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    assigned_state_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    audit_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    local_commit_id: Mapped[str] = mapped_column(String(128), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
    __table_args__ = (
        CheckConstraint("continuity_epoch >= 0", name="ck_receipt_epoch"),
        CheckConstraint("assigned_state_version >= 1", name="ck_receipt_state_version"),
    )


class GenesisAttempt(Base):
    __tablename__ = "genesis_attempts"
    request_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    trust_domain_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_generation_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False)
    local_commit_id: Mapped[str | None] = mapped_column(String(128))
    outcome_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)


class RestoreRecord(Base):
    __tablename__ = "restore_records"
    request_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    trust_domain_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    continuity_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    manifest_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    target_storage_generation_id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    reason_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, nullable=False)
