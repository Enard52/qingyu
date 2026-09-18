from __future__ import annotations

from datetime import datetime
from typing import Any
import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .canonical import looks_like_uuid, uuid4_opaque


class CoreModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class GenesisRequest(CoreModel):
    trust_domain_id: uuid.UUID
    qingyu_identity_id: uuid.UUID
    continuity_id: uuid.UUID
    continuity_alias: str = "qingyu-main"
    genesis_request_id: str = Field(min_length=1, max_length=128)
    genesis_version: str = "core-foundation-v1"
    genesis_nonce: str = Field(min_length=16, max_length=128)
    initial_owner_fingerprint: str = Field(min_length=16, max_length=128)
    actor_principal_id: str = Field(min_length=1, max_length=256)
    constitution_genesis_ref: str | None = None
    constitution_genesis_hash: str | None = None
    governance_provenance: dict[str, Any] = Field(default_factory=dict)

    @field_validator("trust_domain_id", "qingyu_identity_id", "continuity_id")
    @classmethod
    def require_uuid4(cls, value: uuid.UUID) -> uuid.UUID:
        return uuid4_opaque(value)

    @field_validator("continuity_alias")
    @classmethod
    def alias_is_human_readable(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or looks_like_uuid(normalized):
            raise ValueError("continuity_alias must not be a canonical UUID")
        return normalized


class MutationRequest(CoreModel):
    continuity_id: uuid.UUID
    continuity_epoch: int | None = None
    lease_id: uuid.UUID | None = None
    mutation_id: str = Field(min_length=1, max_length=128)
    actor_principal_id: str = Field(min_length=1, max_length=256)
    capability: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("continuity_id")
    @classmethod
    def require_uuid4(cls, value: uuid.UUID) -> uuid.UUID:
        return uuid4_opaque(value)


class IdentityStatus(CoreModel):
    status: str
    trust_domain_id: uuid.UUID | None
    qingyu_identity_id: uuid.UUID | None
    continuity_id: uuid.UUID | None
    continuity_alias: str | None
    continuity_epoch: int | None
    state_version: int | None
    owner_version: int | None
    active_storage_generation_id: uuid.UUID | None
    audit_seq: int
    audit_head_hash: str | None


class CoreReadModel(CoreModel):
    schema_version: str = "core-read-model-v1"
    status: str
    identity_reference: dict[str, Any]
    generation: dict[str, Any]
    governed_state: dict[str, Any]
    lineage: dict[str, Any]
    provenance: dict[str, Any]
    read_model_hash: str
    read_only: bool = True


class RestoreManifest(CoreModel):
    trust_domain_id: uuid.UUID
    qingyu_identity_id: uuid.UUID
    continuity_id: uuid.UUID
    genesis_fingerprint: str
    initial_owner_fingerprint: str
    manifest_hash: str
    audit_high_water: int
    audit_head_hash: str | None
    control_plane_generation_id: uuid.UUID
    storage_generation_id: uuid.UUID
    witness_set_version: str


class RestoreRequest(CoreModel):
    request_id: str = Field(min_length=1, max_length=128)
    manifest: RestoreManifest
    current_owner_principal_id: str = Field(min_length=1, max_length=256)
    current_owner_record_hash: str = Field(min_length=16, max_length=128)
    target_storage_generation_id: uuid.UUID


class MutationResult(CoreModel):
    mutation_id: str
    status: str
    continuity_epoch: int
    state_version: int
    audit_seq: int
    audit_head_hash: str
    local_commit_id: str


class RestoreVerification(CoreModel):
    same_identity: bool
    read_only: bool
    reason: str | None = None
    continuity_epoch: int | None = None
    audit: dict[str, object] | None = None

