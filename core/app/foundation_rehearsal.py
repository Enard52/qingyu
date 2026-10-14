from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import hashlib
import uuid

from .canonical import sha256_hex
from .errors import CoreError
from .schemas import CoreReadModel, GenesisRequest, RestoreManifest, RestoreRequest

REHEARSAL_ENVIRONMENT = "B1_FOUNDATION_CANDIDATE_REHEARSAL"
REHEARSAL_OWNER_PREFIX = "r1-b1-foundation-"
PRODUCTION_MARKERS = {"production", "prod", "qingyu-production", "b2-production"}


@dataclass(frozen=True)
class RehearsalTarget:
    owner: str
    host: str
    port: int
    database: str
    container: str
    network: str
    volume: str
    environment_marker: str = REHEARSAL_ENVIRONMENT


@dataclass(frozen=True)
class BackupArtifact:
    path: Path
    metadata: dict[str, Any]


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def assert_rehearsal_isolation(target: RehearsalTarget) -> None:
    if target.environment_marker != REHEARSAL_ENVIRONMENT:
        raise CoreError("FOUNDATION_REHEARSAL_ENVIRONMENT_REQUIRED")
    if not target.owner.startswith(REHEARSAL_OWNER_PREFIX):
        raise CoreError("FOUNDATION_REHEARSAL_OWNER_REQUIRED")
    if target.host != "127.0.0.1":
        raise CoreError("FOUNDATION_REHEARSAL_LOOPBACK_REQUIRED")
    if not isinstance(target.port, int) or target.port <= 0 or target.port > 65535:
        raise CoreError("FOUNDATION_REHEARSAL_PORT_INVALID")
    lowered = " ".join([target.owner, target.database, target.container, target.network, target.volume]).lower()
    if any(marker in lowered for marker in PRODUCTION_MARKERS):
        raise CoreError("FOUNDATION_REHEARSAL_PRODUCTION_MARKER_FORBIDDEN")


def assert_rehearsal_genesis_request(request: GenesisRequest) -> None:
    provenance = request.governance_provenance
    if provenance.get("environment") != REHEARSAL_ENVIRONMENT:
        raise CoreError("FOUNDATION_REHEARSAL_GENESIS_MARKER_REQUIRED")
    if provenance.get("production_activated") is not False:
        raise CoreError("FOUNDATION_REHEARSAL_MUST_NOT_ACTIVATE_PRODUCTION")
    if provenance.get("requires_b2_activation") is not True:
        raise CoreError("FOUNDATION_REHEARSAL_B2_ACTIVATION_REQUIRED")
    if "production" in request.continuity_alias.lower():
        raise CoreError("FOUNDATION_REHEARSAL_ALIAS_MUST_NOT_BE_PRODUCTION")


def rehearsal_identity_summary(request: GenesisRequest, read_model: CoreReadModel) -> dict[str, Any]:
    assert_rehearsal_genesis_request(request)
    provenance = read_model.provenance.get("governance_provenance", {})
    if provenance.get("environment") != REHEARSAL_ENVIRONMENT:
        raise CoreError("FOUNDATION_REHEARSAL_READ_MODEL_MARKER_REQUIRED")
    return {
        "environment": REHEARSAL_ENVIRONMENT,
        "trust_domain_id": str(request.trust_domain_id),
        "qingyu_identity_id": str(request.qingyu_identity_id),
        "continuity_id": str(request.continuity_id),
        "candidate_artifact_directly_activates_production": False,
        "production_activated": False,
        "requires_future_b2_owner_activation": True,
        "read_model_hash": read_model.read_model_hash,
    }


def canonical_read_model(read_model: CoreReadModel) -> dict[str, Any]:
    payload = read_model.model_dump(mode="json")
    payload.pop("read_model_hash", None)
    return payload


def build_restore_manifest(read_model: CoreReadModel) -> RestoreManifest:
    checkpoint = read_model.provenance["checkpoint"]
    identity = read_model.identity_reference
    generation = read_model.generation
    governed = read_model.governed_state
    return RestoreManifest(
        trust_domain_id=uuid.UUID(identity["trust_domain_id"]),
        qingyu_identity_id=uuid.UUID(identity["qingyu_identity_id"]),
        continuity_id=uuid.UUID(identity["continuity_id"]),
        genesis_fingerprint=identity["genesis_fingerprint"],
        initial_owner_fingerprint=checkpoint["initial_owner_fingerprint"],
        manifest_hash=identity["manifest_hash"],
        audit_high_water=governed["audit_high_water"],
        audit_head_hash=governed["audit_head_hash"],
        control_plane_generation_id=uuid.UUID(generation["control_plane_generation_id"]),
        storage_generation_id=uuid.UUID(generation["storage_generation_id"]),
        witness_set_version=read_model.lineage["witness_set_version"],
    )


def owner_record_hash(read_model: CoreReadModel) -> str:
    checkpoint = read_model.provenance["checkpoint"]
    return sha256_hex({
        "owner_version": checkpoint["owner_version"],
        "owner_principal_id": checkpoint["owner_principal_id"],
        "owner_key_fingerprint": checkpoint["owner_key_fingerprint"],
    })


def build_restore_request(
    *,
    request_id: str,
    read_model: CoreReadModel,
    target_storage_generation_id: uuid.UUID,
) -> RestoreRequest:
    checkpoint = read_model.provenance["checkpoint"]
    return RestoreRequest(
        request_id=request_id,
        manifest=build_restore_manifest(read_model),
        current_owner_principal_id=checkpoint["owner_principal_id"],
        current_owner_record_hash=owner_record_hash(read_model),
        target_storage_generation_id=target_storage_generation_id,
    )


def backup_metadata(
    *,
    backup_path: Path,
    source_read_model: CoreReadModel,
    trust_anchor: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema_version": "qingyu-foundation-rehearsal-backup-v1",
        "environment": REHEARSAL_ENVIRONMENT,
        "backup_sha256": file_sha256(backup_path),
        "read_model_hash": source_read_model.read_model_hash,
        "canonical_payload_sha256": sha256_hex(canonical_read_model(source_read_model)),
        "restore_manifest": build_restore_manifest(source_read_model).model_dump(mode="json"),
        "trust_anchor": trust_anchor,
    }


def verify_backup_metadata(metadata: dict[str, Any], *, backup_path: Path, expected_read_model: CoreReadModel, expected_trust_anchor: dict[str, Any]) -> None:
    required = {"schema_version", "environment", "backup_sha256", "read_model_hash", "canonical_payload_sha256", "restore_manifest", "trust_anchor"}
    if set(metadata) < required:
        raise CoreError("FOUNDATION_BACKUP_METADATA_INCOMPLETE")
    if metadata["schema_version"] != "qingyu-foundation-rehearsal-backup-v1":
        raise CoreError("FOUNDATION_BACKUP_METADATA_MALFORMED")
    if metadata["environment"] != REHEARSAL_ENVIRONMENT:
        raise CoreError("FOUNDATION_BACKUP_WRONG_ENVIRONMENT")
    if metadata["backup_sha256"] != file_sha256(backup_path):
        raise CoreError("FOUNDATION_BACKUP_DIGEST_MISMATCH")
    if metadata["read_model_hash"] != expected_read_model.read_model_hash:
        raise CoreError("FOUNDATION_BACKUP_STATE_HASH_MISMATCH")
    if metadata["canonical_payload_sha256"] != sha256_hex(canonical_read_model(expected_read_model)):
        raise CoreError("FOUNDATION_BACKUP_CANONICAL_HASH_MISMATCH")
    if metadata["restore_manifest"] != build_restore_manifest(expected_read_model).model_dump(mode="json"):
        raise CoreError("FOUNDATION_BACKUP_RESTORE_MANIFEST_MISMATCH")
    if metadata["trust_anchor"] != expected_trust_anchor:
        raise CoreError("FOUNDATION_BACKUP_TRUST_ANCHOR_MISMATCH")


class PostgresAuthorityStateStore:
    """Rehearsal-only durable authority state store.

    This is not a production authority service and does not create production
    trust. It prevents B1 Foundation rehearsal correctness from depending on a
    Python object's lifetime by checkpointing the existing development control
    plane state into the isolated PostgreSQL target.
    """

    schema_version = "qingyu-foundation-rehearsal-authority-state-v1"

    def __init__(self, sqlalchemy_url: str, *, key: str = "foundation-rehearsal-authority"):
        self.sqlalchemy_url = sqlalchemy_url
        self.key = key
        from sqlalchemy import create_engine, text
        self._engine = create_engine(sqlalchemy_url, pool_pre_ping=True)
        with self._engine.begin() as connection:
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS foundation_rehearsal_authority_state (
                    key TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    payload BYTEA NOT NULL,
                    payload_sha256 TEXT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )
            """))

    def load(self) -> dict[str, Any] | None:
        from sqlalchemy import text
        with self._engine.begin() as connection:
            row = connection.execute(text("""
                SELECT schema_version, payload, payload_sha256
                FROM foundation_rehearsal_authority_state
                WHERE key = :key
            """), {"key": self.key}).mappings().first()
        if row is None:
            return None
        payload = bytes(row["payload"])
        if row["schema_version"] != self.schema_version:
            raise CoreError("FOUNDATION_AUTHORITY_STATE_SCHEMA_MISMATCH")
        if hashlib.sha256(payload).hexdigest() != row["payload_sha256"]:
            raise CoreError("FOUNDATION_AUTHORITY_STATE_DIGEST_MISMATCH")
        import pickle
        return pickle.loads(payload)

    def save(self, snapshot: dict[str, Any]) -> str:
        import pickle
        from sqlalchemy import text
        payload = pickle.dumps(snapshot, protocol=5)
        digest = hashlib.sha256(payload).hexdigest()
        with self._engine.begin() as connection:
            connection.execute(text("""
                INSERT INTO foundation_rehearsal_authority_state
                    (key, schema_version, payload, payload_sha256, updated_at)
                VALUES (:key, :schema_version, :payload, :payload_sha256, now())
                ON CONFLICT (key) DO UPDATE SET
                    schema_version = EXCLUDED.schema_version,
                    payload = EXCLUDED.payload,
                    payload_sha256 = EXCLUDED.payload_sha256,
                    updated_at = now()
            """), {"key": self.key, "schema_version": self.schema_version,
                   "payload": payload, "payload_sha256": digest})
        return digest

    def summary(self) -> dict[str, Any]:
        from sqlalchemy import text
        with self._engine.begin() as connection:
            row = connection.execute(text("""
                SELECT schema_version, payload_sha256, octet_length(payload) AS payload_bytes, updated_at
                FROM foundation_rehearsal_authority_state
                WHERE key = :key
            """), {"key": self.key}).mappings().first()
        if row is None:
            return {"present": False, "key": self.key}
        return {"present": True, "key": self.key, "schema_version": row["schema_version"],
                "payload_sha256": row["payload_sha256"], "payload_bytes": row["payload_bytes"],
                "updated_at": row["updated_at"].isoformat()}


class PersistentRehearsalAuthority:
    backend_name = "postgres-rehearsal-authority"

    _MUTATING_METHODS = {
        "prepare_genesis", "claim_genesis_storage", "initialize_domain",
        "record_genesis_core_commit", "publish_genesis_anchor", "complete_genesis",
        "acquire_lease", "prepare_mutation", "commit_mutation", "abort_mutation",
        "sync_audit_checkpoint", "quarantine_recovery", "transfer_owner",
        "claim_recovery", "activate_recovery", "complete_recovery",
    }

    def __init__(self, store: PostgresAuthorityStateStore, *, available_witnesses: int = 3):
        from .control_plane.authority import InMemoryControlPlane
        self.store = store
        self._authority = InMemoryControlPlane(available_witnesses=available_witnesses)
        snapshot = self.store.load()
        if snapshot is None:
            self._persist()
        else:
            self._restore(snapshot)

    @property
    def witness_set_version(self):
        return self._authority.witness_set_version

    @property
    def protocol_version(self):
        return self._authority.protocol_version

    @property
    def quorum_threshold(self):
        return self._authority.quorum_threshold

    @property
    def available_witnesses(self):
        return self._authority.available_witnesses

    def _snapshot(self) -> dict[str, Any]:
        return {
            "schema_version": PostgresAuthorityStateStore.schema_version,
            "available_witnesses": self._authority.available_witnesses,
            "lease_ttl": self._authority._lease_ttl,
            "reservations": self._authority._reservations,
            "domains": self._authority._domains,
            "mutations": self._authority._mutations,
            "recovery_claims": self._authority._recovery_claims,
            "lease_generations": self._authority._lease_generations,
        }

    def _restore(self, snapshot: dict[str, Any]) -> None:
        if snapshot.get("schema_version") != PostgresAuthorityStateStore.schema_version:
            raise CoreError("FOUNDATION_AUTHORITY_STATE_SCHEMA_MISMATCH")
        self._authority.available_witnesses = snapshot["available_witnesses"]
        self._authority._lease_ttl = snapshot["lease_ttl"]
        self._authority._reservations = snapshot["reservations"]
        self._authority._domains = snapshot["domains"]
        self._authority._mutations = snapshot["mutations"]
        self._authority._recovery_claims = snapshot["recovery_claims"]
        self._authority._lease_generations = snapshot["lease_generations"]

    def _persist(self) -> str:
        return self.store.save(self._snapshot())

    def persistence_summary(self) -> dict[str, Any]:
        summary = self.store.summary()
        summary["backend_name"] = self.backend_name
        summary["durable_authority_state"] = True
        return summary

    def __getattr__(self, name: str):
        target = getattr(self._authority, name)
        if not callable(target):
            return target
        def call(*args: Any, **kwargs: Any):
            result = target(*args, **kwargs)
            if name in self._MUTATING_METHODS:
                self._persist()
            return result
        return call
