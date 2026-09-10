"""Independent PostgreSQL control-plane authority.

This adapter is deliberately separate from Core's database and schema. Every
governance transition is protected by a row lock plus a conditional update;
the authority can therefore fence two Core processes sharing one store.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator
import uuid

try:  # Keep the test/dev memory backend importable without PostgreSQL extras.
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - exercised in minimal local envs
    psycopg = None  # type: ignore[assignment]
    dict_row = None  # type: ignore[assignment]

from ..canonical import sha256_hex, uuid4_opaque
from ..errors import CoreError
from .authority import DomainState, GenesisReservation, GenesisState, Lease, MutationPermit, MutationState, RecoveryState


DDL = """
CREATE TABLE IF NOT EXISTS cp_genesis (
 trust_domain_id uuid PRIMARY KEY, manifest_hash text NOT NULL, request_id text NOT NULL,
 state text NOT NULL, claimed_storage_generation_id uuid, local_commit_id text,
 anchor_hash text, UNIQUE(request_id)
);
CREATE TABLE IF NOT EXISTS cp_domains (
 continuity_id uuid PRIMARY KEY, trust_domain_id uuid NOT NULL UNIQUE, identity_id uuid NOT NULL UNIQUE,
 epoch bigint NOT NULL, state_version bigint NOT NULL, owner_version bigint NOT NULL,
 owner_principal_id text NOT NULL, owner_key_fingerprint text NOT NULL,
 initial_owner_fingerprint text NOT NULL, storage_generation_id uuid NOT NULL,
 control_plane_generation_id uuid NOT NULL, lease_id uuid, lease_principal_id text,
 lease_capability text, lease_storage_generation_id uuid, lease_epoch bigint, lease_generation bigint,
 recovery_state text NOT NULL, recovery_claim_request_id text, audit_high_water bigint NOT NULL,
 audit_head_hash text
);
CREATE TABLE IF NOT EXISTS cp_mutations (
 mutation_id text PRIMARY KEY, continuity_id uuid NOT NULL, epoch bigint NOT NULL,
 lease_id uuid NOT NULL, storage_generation_id uuid NOT NULL, payload_hash text NOT NULL,
 expected_state_version bigint NOT NULL, assigned_state_version bigint NOT NULL,
 state text NOT NULL, local_commit_id text, audit_head_hash text, audit_seq bigint
);
CREATE TABLE IF NOT EXISTS cp_recovery_claims (
 request_id text PRIMARY KEY, trust_domain_id uuid NOT NULL, continuity_id uuid NOT NULL,
 restore_manifest_hash text NOT NULL, target_storage_generation_id uuid NOT NULL,
 status text NOT NULL, previous_epoch bigint NOT NULL, target_epoch bigint
);
"""


class PostgresControlPlane:
    backend_name = "postgres"
    witness_set_version = "postgres-control-plane-v1"
    protocol_version = "control-plane-v1"
    quorum_threshold = 2

    def __init__(self, dsn: str):
        if psycopg is None:
            raise CoreError("CONTROL_PLANE_POSTGRES_DRIVER_UNAVAILABLE")
        # Settings accepts SQLAlchemy URLs; psycopg accepts the plain scheme.
        self.dsn = dsn.replace("postgresql+psycopg://", "postgresql://", 1)

    @contextmanager
    def _tx(self) -> Iterator[psycopg.Connection]:
        try:
            with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
                yield conn
                conn.commit()
        except psycopg.Error as exc:
            raise CoreError("CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE") from exc

    def migrate(self) -> None:
        """Apply only the independent authority schema migration."""
        with self._tx() as conn:
            for statement in DDL.split(";"):
                if statement.strip():
                    conn.execute(statement)

    @staticmethod
    def _require_uuid(value: uuid.UUID) -> uuid.UUID:
        return uuid4_opaque(value)

    @staticmethod
    def _genesis(row: dict[str, Any]) -> GenesisReservation:
        return GenesisReservation(uuid.UUID(str(row["trust_domain_id"])), row["manifest_hash"], row["request_id"], GenesisState(row["state"]), uuid.UUID(str(row["claimed_storage_generation_id"])) if row["claimed_storage_generation_id"] else None, row["local_commit_id"], row["anchor_hash"])

    @staticmethod
    def _domain(row: dict[str, Any]) -> DomainState:
        lease = None
        if row["lease_id"]:
            lease = Lease(uuid.UUID(str(row["lease_id"])), uuid.UUID(str(row["continuity_id"])), int(row["lease_epoch"]), row["lease_principal_id"], row["lease_capability"], uuid.UUID(str(row["lease_storage_generation_id"])), int(row["lease_generation"]))
        return DomainState(uuid.UUID(str(row["trust_domain_id"])), uuid.UUID(str(row["continuity_id"])), uuid.UUID(str(row["identity_id"])), int(row["epoch"]), int(row["state_version"]), int(row["owner_version"]), row["owner_principal_id"], row["owner_key_fingerprint"], row["initial_owner_fingerprint"], uuid.UUID(str(row["storage_generation_id"])), uuid.UUID(str(row["control_plane_generation_id"])), lease, RecoveryState(row["recovery_state"]), row["recovery_claim_request_id"], int(row["audit_high_water"]), row["audit_head_hash"])

    def prepare_genesis(self, *, trust_domain_id: uuid.UUID, manifest_hash: str, request_id: str) -> GenesisReservation:
        tid = self._require_uuid(trust_domain_id)
        with self._tx() as c:
            c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s FOR UPDATE", (tid,)); row = c.fetchone()
            if row is None:
                c.execute("INSERT INTO cp_genesis(trust_domain_id,manifest_hash,request_id,state) VALUES(%s,%s,%s,%s) RETURNING *", (tid, manifest_hash, request_id, GenesisState.PREPARED_UNCLAIMED.value)); return self._genesis(c.fetchone())
            if row["manifest_hash"] == manifest_hash and row["request_id"] == request_id: return self._genesis(row)
            raise CoreError("GENESIS_CONFLICT")

    def claim_genesis_storage(self, *, trust_domain_id: uuid.UUID, request_id: str, storage_generation_id: uuid.UUID) -> GenesisReservation:
        with self._tx() as c:
            c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s FOR UPDATE", (self._require_uuid(trust_domain_id),)); row = c.fetchone()
            if not row or row["request_id"] != request_id: raise CoreError("GENESIS_CONFLICT")
            sg = self._require_uuid(storage_generation_id)
            if row["claimed_storage_generation_id"] and row["claimed_storage_generation_id"] != sg: raise CoreError("GENESIS_STORAGE_NOT_CLAIMED")
            if not row["claimed_storage_generation_id"]: c.execute("UPDATE cp_genesis SET claimed_storage_generation_id=%s,state=%s WHERE trust_domain_id=%s", (sg, GenesisState.CLAIMED.value, self._require_uuid(trust_domain_id))); c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s", (self._require_uuid(trust_domain_id),)); row = c.fetchone()
            return self._genesis(row)

    def _claimed(self, c: psycopg.Connection, tid: uuid.UUID, request_id: str, sg: uuid.UUID) -> dict[str, Any]:
        c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s FOR UPDATE", (self._require_uuid(tid),)); row = c.fetchone()
        if not row or row["request_id"] != request_id: raise CoreError("GENESIS_CONFLICT")
        if row["claimed_storage_generation_id"] != self._require_uuid(sg): raise CoreError("GENESIS_STORAGE_NOT_CLAIMED")
        return row

    def record_genesis_core_commit(self, *, trust_domain_id: uuid.UUID, request_id: str, storage_generation_id: uuid.UUID, local_commit_id: str) -> GenesisReservation:
        with self._tx() as c:
            row = self._claimed(c, trust_domain_id, request_id, storage_generation_id)
            if row["state"] in (GenesisState.CORE_COMMITTED.value, GenesisState.ANCHOR_PUBLISHED.value, GenesisState.COMMITTED.value) and row["local_commit_id"] != local_commit_id: raise CoreError("GENESIS_CONFLICT")
            if row["state"] == GenesisState.CLAIMED.value: c.execute("UPDATE cp_genesis SET local_commit_id=%s,state=%s WHERE trust_domain_id=%s", (local_commit_id, GenesisState.CORE_COMMITTED.value, self._require_uuid(trust_domain_id)))
            c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s", (self._require_uuid(trust_domain_id),)); return self._genesis(c.fetchone())

    def publish_genesis_anchor(self, *, trust_domain_id: uuid.UUID, request_id: str, storage_generation_id: uuid.UUID, anchor_hash: str) -> GenesisReservation:
        with self._tx() as c:
            row = self._claimed(c, trust_domain_id, request_id, storage_generation_id)
            if row["anchor_hash"] and row["anchor_hash"] != anchor_hash: raise CoreError("GENESIS_ANCHOR_MISMATCH")
            if row["state"] not in (GenesisState.CORE_COMMITTED.value, GenesisState.ANCHOR_PUBLISHED.value, GenesisState.COMMITTED.value): raise CoreError("GENESIS_OUTCOME_UNKNOWN")
            if row["state"] != GenesisState.COMMITTED.value: c.execute("UPDATE cp_genesis SET anchor_hash=%s,state=%s WHERE trust_domain_id=%s", (anchor_hash, GenesisState.ANCHOR_PUBLISHED.value, self._require_uuid(trust_domain_id)))
            c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s", (self._require_uuid(trust_domain_id),)); return self._genesis(c.fetchone())

    def complete_genesis(self, *, trust_domain_id: uuid.UUID, request_id: str, storage_generation_id: uuid.UUID) -> GenesisReservation:
        with self._tx() as c:
            row = self._claimed(c, trust_domain_id, request_id, storage_generation_id)
            if row["state"] not in (GenesisState.ANCHOR_PUBLISHED.value, GenesisState.COMMITTED.value): raise CoreError("GENESIS_OUTCOME_UNKNOWN")
            c.execute("UPDATE cp_genesis SET state=%s WHERE trust_domain_id=%s", (GenesisState.COMMITTED.value, self._require_uuid(trust_domain_id))); c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s", (self._require_uuid(trust_domain_id),)); return self._genesis(c.fetchone())

    def genesis_status(self, trust_domain_id: uuid.UUID) -> GenesisReservation | None:
        with self._tx() as c:
            c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s", (self._require_uuid(trust_domain_id),)); row = c.fetchone(); return self._genesis(row) if row else None

    def initialize_domain(self, *, trust_domain_id: uuid.UUID, identity_id: uuid.UUID, continuity_id: uuid.UUID, storage_generation_id: uuid.UUID, control_plane_generation_id: uuid.UUID, owner_principal_id: str, owner_key_fingerprint: str, audit_high_water: int = 0, audit_head_hash: str | None = None) -> DomainState:
        with self._tx() as c:
            c.execute("SELECT * FROM cp_domains WHERE continuity_id=%s FOR UPDATE", (self._require_uuid(continuity_id),)); row = c.fetchone()
            if row:
                if row["trust_domain_id"] != self._require_uuid(trust_domain_id) or row["identity_id"] != self._require_uuid(identity_id):
                    raise CoreError("IDENTITY_CONTINUITY_BINDING_MISMATCH")
                return self._domain(row)
            vals = (self._require_uuid(continuity_id), self._require_uuid(trust_domain_id), self._require_uuid(identity_id), self._require_uuid(storage_generation_id), self._require_uuid(control_plane_generation_id), owner_principal_id, owner_key_fingerprint, audit_high_water, audit_head_hash)
            c.execute("INSERT INTO cp_domains(continuity_id,trust_domain_id,identity_id,epoch,state_version,owner_version,owner_principal_id,owner_key_fingerprint,initial_owner_fingerprint,storage_generation_id,control_plane_generation_id,recovery_state,audit_high_water,audit_head_hash) VALUES(%s,%s,%s,0,0,0,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *", (vals[0], vals[1], vals[2], vals[5], vals[6], vals[6], vals[3], vals[4], RecoveryState.ACTIVE.value, vals[7], vals[8])); return self._domain(c.fetchone())

    def get_domain(self, continuity_id: uuid.UUID) -> DomainState:
        with self._tx() as c:
            c.execute("SELECT * FROM cp_domains WHERE continuity_id=%s", (self._require_uuid(continuity_id),)); row = c.fetchone()
            if not row: raise CoreError("CONTINUITY_UNKNOWN")
            return self._domain(row)

    def acquire_lease(self, *, continuity_id: uuid.UUID, principal_id: str, capability: str, storage_generation_id: uuid.UUID) -> Lease:
        with self._tx() as c:
            c.execute("SELECT * FROM cp_domains WHERE continuity_id=%s FOR UPDATE", (self._require_uuid(continuity_id),)); row = c.fetchone()
            if not row: raise CoreError("CONTINUITY_UNKNOWN")
            if row["recovery_state"] != RecoveryState.ACTIVE.value or row["owner_principal_id"] != principal_id or capability not in {"core_governance", "core_writer"} or row["storage_generation_id"] != self._require_uuid(storage_generation_id): raise CoreError("LEASE_FENCED")
            lid = uuid.uuid4(); gen = int(row["lease_generation"] or 0) + 1
            c.execute("UPDATE cp_domains SET lease_id=%s,lease_principal_id=%s,lease_capability=%s,lease_storage_generation_id=%s,lease_epoch=%s,lease_generation=%s WHERE continuity_id=%s", (lid, principal_id, capability, self._require_uuid(storage_generation_id), row["epoch"], gen, self._require_uuid(continuity_id)))
            return Lease(lid, self._require_uuid(continuity_id), int(row["epoch"]), principal_id, capability, self._require_uuid(storage_generation_id), gen)

    def prepare_mutation(self, *, continuity_id: uuid.UUID, epoch: int | None, lease_id: uuid.UUID | None, mutation_id: str, payload: Any, actor_principal_id: str, capability: str, storage_generation_id: uuid.UUID, expected_state_version: int) -> MutationPermit:
        if epoch is None: raise CoreError("EPOCH_REQUIRED")
        if lease_id is None: raise CoreError("LEASE_REQUIRED")
        with self._tx() as c:
            c.execute("SELECT * FROM cp_domains WHERE continuity_id=%s FOR UPDATE", (self._require_uuid(continuity_id),)); d = c.fetchone()
            if not d: raise CoreError("CONTINUITY_UNKNOWN")
            if epoch < d["epoch"]: raise CoreError("EPOCH_STALE")
            if epoch > d["epoch"]: raise CoreError("EPOCH_NOT_ISSUED")
            if d["lease_id"] != self._require_uuid(lease_id) or d["lease_principal_id"] != actor_principal_id or capability not in {"core_governance", "core_writer"} or d["storage_generation_id"] != self._require_uuid(storage_generation_id): raise CoreError("LEASE_FENCED")
            if expected_state_version != d["state_version"]: raise CoreError("OWNER_VERSION_STALE")
            ph = sha256_hex(payload); c.execute("SELECT * FROM cp_mutations WHERE mutation_id=%s FOR UPDATE", (mutation_id,)); old = c.fetchone()
            if old:
                if old["payload_hash"] != ph: raise CoreError("MUTATION_RETRY_CONFLICT")
                if old["state"] == MutationState.COMMITTED.value: return MutationPermit(mutation_id, self._require_uuid(continuity_id), int(old["epoch"]), self._require_uuid(old["lease_id"]), self._require_uuid(old["storage_generation_id"]), ph, int(old["expected_state_version"]), int(old["assigned_state_version"]), MutationState.COMMITTED)
                if old["state"] == MutationState.ABORTED.value: c.execute("UPDATE cp_mutations SET state=%s,expected_state_version=%s,assigned_state_version=%s WHERE mutation_id=%s", (MutationState.PREPARED.value, expected_state_version, int(d["state_version"])+1, mutation_id))
                else: return MutationPermit(mutation_id, self._require_uuid(continuity_id), epoch, self._require_uuid(lease_id), self._require_uuid(storage_generation_id), ph, expected_state_version, int(old["assigned_state_version"]), MutationState.PREPARED)
            else: c.execute("INSERT INTO cp_mutations(mutation_id,continuity_id,epoch,lease_id,storage_generation_id,payload_hash,expected_state_version,assigned_state_version,state) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)", (mutation_id, self._require_uuid(continuity_id), epoch, self._require_uuid(lease_id), self._require_uuid(storage_generation_id), ph, expected_state_version, int(d["state_version"])+1, MutationState.PREPARED.value))
            return MutationPermit(mutation_id, self._require_uuid(continuity_id), epoch, self._require_uuid(lease_id), self._require_uuid(storage_generation_id), ph, expected_state_version, int(d["state_version"])+1, MutationState.PREPARED)

    def commit_mutation(self, *, mutation_id: str, local_commit_id: str, audit_head_hash: str, audit_seq: int | None = None) -> MutationPermit:
        with self._tx() as c:
            c.execute("SELECT * FROM cp_mutations WHERE mutation_id=%s FOR UPDATE", (mutation_id,)); m = c.fetchone()
            if not m: raise CoreError("MUTATION_OUTCOME_UNKNOWN")
            if m["state"] == MutationState.ABORTED.value: raise CoreError("MUTATION_RETRY_CONFLICT")
            if m["state"] == MutationState.COMMITTED.value: return MutationPermit(mutation_id, self._require_uuid(m["continuity_id"]), int(m["epoch"]), self._require_uuid(m["lease_id"]), self._require_uuid(m["storage_generation_id"]), m["payload_hash"], int(m["expected_state_version"]), int(m["assigned_state_version"]), MutationState.COMMITTED)
            c.execute("UPDATE cp_domains SET state_version=%s,audit_high_water=%s,audit_head_hash=%s WHERE continuity_id=%s AND epoch=%s AND storage_generation_id=%s AND state_version=%s", (m["assigned_state_version"], audit_seq if audit_seq is not None else 0, audit_head_hash, m["continuity_id"], m["epoch"], m["storage_generation_id"], m["expected_state_version"]))
            if c.rowcount != 1: raise CoreError("LEASE_FENCED")
            c.execute("UPDATE cp_mutations SET state=%s,local_commit_id=%s,audit_head_hash=%s,audit_seq=%s WHERE mutation_id=%s", (MutationState.COMMITTED.value, local_commit_id, audit_head_hash, audit_seq, mutation_id))
            return MutationPermit(mutation_id, self._require_uuid(m["continuity_id"]), int(m["epoch"]), self._require_uuid(m["lease_id"]), self._require_uuid(m["storage_generation_id"]), m["payload_hash"], int(m["expected_state_version"]), int(m["assigned_state_version"]), MutationState.COMMITTED)

    def sync_audit_checkpoint(self, *, continuity_id: uuid.UUID, audit_seq: int, audit_head_hash: str | None) -> None:
        with self._tx() as c:
            c.execute("UPDATE cp_domains SET audit_high_water=%s,audit_head_hash=%s WHERE continuity_id=%s AND audit_high_water<=%s", (audit_seq, audit_head_hash, self._require_uuid(continuity_id), audit_seq))
            if c.rowcount != 1: raise CoreError("CONTROL_PLANE_ROLLBACK_DETECTED")

    def quarantine_recovery(self, continuity_id: uuid.UUID) -> None:
        with self._tx() as c: c.execute("UPDATE cp_domains SET recovery_state=%s,lease_id=NULL WHERE continuity_id=%s", (RecoveryState.QUARANTINED.value, self._require_uuid(continuity_id)))

    def abort_mutation(self, mutation_id: str) -> MutationPermit:
        with self._tx() as c:
            c.execute("SELECT * FROM cp_mutations WHERE mutation_id=%s FOR UPDATE", (mutation_id,)); m = c.fetchone()
            if not m: raise CoreError("MUTATION_OUTCOME_UNKNOWN")
            if m["state"] != MutationState.COMMITTED.value:
                c.execute("UPDATE cp_mutations SET state=%s WHERE mutation_id=%s", (MutationState.ABORTED.value, mutation_id)); m["state"] = MutationState.ABORTED.value
            return MutationPermit(mutation_id, self._require_uuid(m["continuity_id"]), int(m["epoch"]), self._require_uuid(m["lease_id"]), self._require_uuid(m["storage_generation_id"]), m["payload_hash"], int(m["expected_state_version"]), int(m["assigned_state_version"]), MutationState(m["state"]))

    def transfer_owner(self, *, continuity_id: uuid.UUID, expected_owner_version: int, current_owner_principal_id: str, target_principal_id: str, target_key_fingerprint: str) -> DomainState:
        with self._tx() as c:
            c.execute("UPDATE cp_domains SET owner_version=owner_version+1,owner_principal_id=%s,owner_key_fingerprint=%s,epoch=epoch+1,state_version=state_version+1,lease_id=NULL WHERE continuity_id=%s AND owner_version=%s AND owner_principal_id=%s RETURNING *", (target_principal_id, target_key_fingerprint, self._require_uuid(continuity_id), expected_owner_version, current_owner_principal_id)); row = c.fetchone()
            if not row: raise CoreError("OWNER_TRANSFER_CONFLICT")
            return self._domain(row)

    def claim_recovery(self, *, request_id: str, trust_domain_id: uuid.UUID, continuity_id: uuid.UUID, current_owner_principal_id: str, current_owner_record_hash: str, target_storage_generation_id: uuid.UUID, restore_manifest_hash: str) -> dict[str, Any]:
        with self._tx() as c:
            c.execute("SELECT * FROM cp_domains WHERE continuity_id=%s FOR UPDATE", (self._require_uuid(continuity_id),)); d = c.fetchone()
            if not d or d["trust_domain_id"] != self._require_uuid(trust_domain_id): raise CoreError("RESTORE_AUTHORIZATION_SCOPE_MISMATCH")
            expected = sha256_hex({"owner_version": d["owner_version"], "owner_principal_id": d["owner_principal_id"], "owner_key_fingerprint": d["owner_key_fingerprint"]})
            if current_owner_principal_id != d["owner_principal_id"] or current_owner_record_hash != expected: raise CoreError("RESTORE_OWNER_UNPROVEN")
            c.execute("SELECT * FROM cp_recovery_claims WHERE request_id=%s FOR UPDATE", (request_id,)); old = c.fetchone()
            if old:
                if old["restore_manifest_hash"] != restore_manifest_hash: raise CoreError("RESTORE_REQUEST_CONFLICT")
                return dict(old)
            c.execute("SELECT 1 FROM cp_recovery_claims WHERE continuity_id=%s AND status<>%s", (self._require_uuid(continuity_id), "ABORTED"))
            if c.fetchone(): raise CoreError("CONTROL_PLANE_RECOVERY_CLAIM_CONFLICT")
            c.execute("INSERT INTO cp_recovery_claims(request_id,trust_domain_id,continuity_id,restore_manifest_hash,target_storage_generation_id,status,previous_epoch) VALUES(%s,%s,%s,%s,%s,%s,%s) RETURNING *", (request_id, self._require_uuid(trust_domain_id), self._require_uuid(continuity_id), restore_manifest_hash, self._require_uuid(target_storage_generation_id), RecoveryState.PREPARED.value, d["epoch"])); return dict(c.fetchone())

    def activate_recovery(self, request_id: str) -> dict[str, Any]:
        with self._tx() as c:
            c.execute("SELECT * FROM cp_recovery_claims WHERE request_id=%s FOR UPDATE", (request_id,)); claim = c.fetchone()
            if not claim: raise CoreError("RESTORE_AUTHORIZATION_INVALID")
            if claim["status"] == RecoveryState.ACTIVE.value: return dict(claim)
            c.execute("UPDATE cp_domains SET epoch=epoch+1,state_version=state_version+1,storage_generation_id=%s,lease_id=NULL,recovery_state=%s,recovery_claim_request_id=%s WHERE continuity_id=%s AND epoch=%s RETURNING epoch", (claim["target_storage_generation_id"], RecoveryState.ACTIVE.value, request_id, claim["continuity_id"], claim["previous_epoch"])); row = c.fetchone()
            if not row: raise CoreError("CONTROL_PLANE_RECOVERY_CLAIM_CONFLICT")
            c.execute("UPDATE cp_recovery_claims SET target_epoch=%s,status=%s WHERE request_id=%s RETURNING *", (row["epoch"], RecoveryState.ACTIVE.value, request_id)); return dict(c.fetchone())

    def recovery_status(self, request_id: str) -> dict[str, Any] | None:
        with self._tx() as c: c.execute("SELECT * FROM cp_recovery_claims WHERE request_id=%s", (request_id,)); row = c.fetchone(); return dict(row) if row else None

    def export_checkpoint(self, continuity_id: uuid.UUID) -> dict[str, Any]:
        state = self.get_domain(continuity_id)
        return {"trust_domain_id": str(state.trust_domain_id), "continuity_id": str(state.continuity_id), "epoch": state.epoch, "state_version": state.state_version, "owner_version": state.owner_version, "owner_principal_id": state.owner_principal_id, "owner_key_fingerprint": state.owner_key_fingerprint, "storage_generation_id": str(state.storage_generation_id), "control_plane_generation_id": str(state.control_plane_generation_id), "audit_high_water": state.audit_high_water, "audit_head_hash": state.audit_head_hash, "witness_set_version": self.witness_set_version}
