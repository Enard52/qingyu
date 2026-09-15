"""Canonical R1 Authority origin; never a child of legacy 0001_control_plane.

Revision ID: 0001_control_plane_r1_initial
Revises:

The intended entrypoint verifies the signed provisioning intent, creation
completion, exact migration artifact, target cluster and empty database before
this revision runs. The entrypoint currently remains fail-closed while the
independent target inspector is unfinished. This revision creates the Authority
schema and its origin marker in one PostgreSQL transaction. Its authored DDL
comes from a separately pinned historical snapshot, never live app metadata.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from uuid import UUID

from alembic import op
from sqlalchemy import insert

from app.control_plane.r1_provisioning import INITIAL_REVISION, VerifiedOrigin
from app.control_plane import r1_schema_snapshot as snapshot
from app.control_plane.r1_schema_snapshot import (
    DDL_PREFIX, DDL_SUFFIX, R1_METADATA, origin, verify_schema_snapshot,
    verify_initial_migration_artifact,
)


revision = "0001_control_plane_r1_initial"
down_revision = None
branch_labels = None
depends_on = None


def _signed_origin() -> VerifiedOrigin:
    """Reject missing/unexpected context before issuing any migration SQL."""
    candidate = op.get_context().config.attributes.get("r1_verified_origin")
    if not isinstance(candidate, VerifiedOrigin):
        raise RuntimeError("R1 migration requires preflight-verified signed origin")
    intent, completion = candidate.intent, candidate.completion
    if (revision != INITIAL_REVISION
            or intent.get("canonical_initial_revision") != revision
            or intent.get("authority_generation") != 1
            or completion.get("authority_generation") != 1
            or intent.get("roles", {}).get("owner") != "control_plane_owner"
            or intent.get("roles", {}).get("migrator") != "control_plane_migrator"
            or intent.get("provisioning_uuid") != completion.get("provisioning_uuid")
            or intent.get("authority_domain_id") != completion.get("authority_domain_id")
            or intent.get("authority_instance_id") != completion.get("authority_instance_id")
            or intent.get("database_name") != completion.get("database_name")
            or intent.get("initial_migration_artifact_digest") != completion.get(
                "initial_migration_artifact_digest")
            or not isinstance(candidate.signed_provisioning_origin_digest, str)
            or len(candidate.signed_provisioning_origin_digest) != 64):
        raise RuntimeError("R1 signed origin or initial revision mismatch")
    expected_path = (Path(snapshot.__file__).resolve().parents[2] /
                     "control_plane_alembic" / "versions" /
                     "0001_control_plane_r1_initial.py")
    if Path(__file__).resolve() != expected_path:
        raise RuntimeError("R1 revision is outside signed migration artifact")
    verify_schema_snapshot()
    verify_initial_migration_artifact(intent["initial_migration_artifact_digest"])
    if (snapshot.verify_schema_snapshot() != intent["authored_ddl_snapshot_digest"]
            or snapshot.initial_migration_dependency_sha256()
            != intent["initial_migration_dependency_digest"]
            or snapshot.schema_contract_sha256() != intent["schema_contract_digest"]):
        raise RuntimeError("R1 signed initial migration digest mismatch")
    return candidate


def upgrade() -> None:
    signed = _signed_origin()
    intent, completion = signed.intent, signed.completion
    bind = op.get_bind()
    # The separately provisioned migrator may assume the NOLOGIN owner only
    # inside this transaction. The initial schema, objects and version table
    # must not be owned by the restricted Authority Service runtime role.
    for statement in DDL_PREFIX:
        op.execute(statement)
    R1_METADATA.create_all(bind=bind, checkfirst=False)
    bind.execute(insert(origin).values(
        singleton_id=1,
        provisioning_uuid=UUID(intent["provisioning_uuid"]),
        authority_domain_id=UUID(intent["authority_domain_id"]),
        authority_instance_id=UUID(intent["authority_instance_id"]),
        initial_authority_generation=1,
        signed_provisioning_origin_digest=signed.signed_provisioning_origin_digest,
        operator_root_key_id=intent["operator_root_key_id"],
        cluster_system_identifier=completion["server_system_identifier"],
        cluster_binding_fingerprint=completion["cluster_binding_fingerprint"],
        database_name=intent["database_name"],
        initial_revision=revision,
        created_at=datetime.fromisoformat(
            completion["creation_event_timestamp"].replace("Z", "+00:00")),
    ))
    # Alembic owns public.cp_alembic_version as the migrator and writes its
    # revision after upgrade() returns. Do not leave owner role active for that
    # write; live role/ownership acceptance must still verify this contract.
    for statement in DDL_SUFFIX:
        op.execute(statement)


def downgrade() -> None:
    raise RuntimeError("R1 Authority origin is forward-only; downgrade is prohibited")
