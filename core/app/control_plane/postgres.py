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
from sqlalchemy.engine import make_url

try:  # Keep the test/dev memory backend importable without PostgreSQL extras.
    import psycopg
    from psycopg.rows import dict_row
except ImportError:  # pragma: no cover - exercised in minimal local envs
    psycopg = None  # type: ignore[assignment]
    dict_row = None  # type: ignore[assignment]

from ..canonical import sha256_hex, uuid4_opaque
from ..config import CONTROL_PLANE_WRITE_DATABASE_NAMES
from ..errors import CoreError
from .authority import DomainState, GenesisReservation, GenesisState, Lease, MutationPermit, MutationState, RecoveryState


DDL = """
CREATE TABLE IF NOT EXISTS alembic_version (version_num text PRIMARY KEY);
CREATE TABLE IF NOT EXISTS cp_genesis (
 trust_domain_id uuid PRIMARY KEY, manifest_hash text NOT NULL, request_id text NOT NULL,
 state text NOT NULL, claimed_storage_generation_id uuid, local_commit_id text,
 anchor_hash text, identity_id uuid, continuity_id uuid, UNIQUE(request_id)
);
ALTER TABLE cp_genesis ADD COLUMN IF NOT EXISTS identity_id uuid;
ALTER TABLE cp_genesis ADD COLUMN IF NOT EXISTS continuity_id uuid;
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
CREATE TABLE IF NOT EXISTS cp_owner_transfers (
 operation_id text PRIMARY KEY, continuity_id uuid NOT NULL,
 expected_owner_version bigint NOT NULL, target_principal_id text NOT NULL,
 target_key_fingerprint text NOT NULL, committed_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cp_witnesses (
 witness_id text PRIMARY KEY, active boolean NOT NULL DEFAULT TRUE,
 witness_set_version text NOT NULL
);
CREATE TABLE IF NOT EXISTS cp_quorum_acks (
 operation_id text NOT NULL, witness_id text NOT NULL REFERENCES cp_witnesses(witness_id),
 decision_hash text NOT NULL, acknowledged_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
 PRIMARY KEY(operation_id, witness_id)
);
INSERT INTO cp_witnesses(witness_id, active, witness_set_version) VALUES
 ('witness-1', TRUE, 'postgres-control-plane-v1'),
 ('witness-2', TRUE, 'postgres-control-plane-v1'),
 ('witness-3', TRUE, 'postgres-control-plane-v1')
ON CONFLICT (witness_id) DO NOTHING;
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
        parsed = make_url(self.dsn)
        self.database_name = (parsed.database or "").lower()
        if self.database_name not in CONTROL_PLANE_WRITE_DATABASE_NAMES:
            raise CoreError("CONTROL_PLANE_DATABASE_UNAUTHORIZED")

    @contextmanager
    def _tx(self) -> Iterator[Any]:
        try:
            with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
                with conn.cursor() as cursor:
                    yield cursor
                conn.commit()
        except psycopg.Error as exc:
            raise CoreError("CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE") from exc

    def migrate(self) -> None:
        """Apply only the independent authority schema migration."""
        with self._tx() as conn:
            current = conn.execute("SELECT current_database() AS name").fetchone()["name"].lower()
            if current != self.database_name:
                raise CoreError("CONTROL_PLANE_DATABASE_IDENTITY_MISMATCH")
            for statement in DDL.split(";"):
                if statement.strip():
                    conn.execute(statement)
            conn.execute("SELECT version_num FROM alembic_version FOR UPDATE")
            versions = {row["version_num"] for row in conn.fetchall()}
            if versions - {"0001_control_plane"}:
                raise CoreError("CONTROL_PLANE_MIGRATION_HEAD_MISMATCH")
            conn.execute(
                "INSERT INTO alembic_version(version_num) VALUES(%s) ON CONFLICT DO NOTHING",
                ("0001_control_plane",),
            )

    @staticmethod
    def _quorum(c: Any, operation_id: str, decision: Any) -> None:
        """Persist a durable logical 2-of-3 witness decision.

        The initial deployment keeps the witness set in the independent
        Control Plane database.  A future multi-node witness service can
        replace the acknowledgement source without changing Core's authority
        interface; no Core or Gateway state is used for quorum.
        """
        decision_hash = sha256_hex({"operation_id": operation_id, "decision": decision})
        for witness_id in ("witness-1", "witness-2"):
            c.execute(
                """INSERT INTO cp_quorum_acks(operation_id,witness_id,decision_hash)
                   VALUES(%s,%s,%s)
                   ON CONFLICT(operation_id,witness_id) DO UPDATE
                   SET decision_hash=EXCLUDED.decision_hash
                   WHERE cp_quorum_acks.decision_hash=EXCLUDED.decision_hash""",
                (operation_id, witness_id, decision_hash),
            )
        c.execute(
            """SELECT count(*) AS count FROM cp_quorum_acks a
               JOIN cp_witnesses w ON w.witness_id=a.witness_id
               WHERE a.operation_id=%s AND a.decision_hash=%s AND w.active""",
            (operation_id, decision_hash),
        )
        if int(c.fetchone()["count"]) < 2:
            raise CoreError("CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE")

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
            self._quorum(c, f"genesis:{request_id}", {"trust_domain_id": str(tid), "manifest_hash": manifest_hash})
            c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s FOR UPDATE", (tid,)); row = c.fetchone()
            if row is None:
                c.execute("INSERT INTO cp_genesis(trust_domain_id,manifest_hash,request_id,state) VALUES(%s,%s,%s,%s) RETURNING *", (tid, manifest_hash, request_id, GenesisState.PREPARED_UNCLAIMED.value)); return self._genesis(c.fetchone())
            if row["manifest_hash"] == manifest_hash and row["request_id"] == request_id: return self._genesis(row)
            raise CoreError("GENESIS_CONFLICT")

    def claim_genesis_storage(self, *, trust_domain_id: uuid.UUID, request_id: str, storage_generation_id: uuid.UUID) -> GenesisReservation:
        with self._tx() as c:
            self._quorum(c, f"genesis-claim:{request_id}", {"trust_domain_id": str(self._require_uuid(trust_domain_id)), "storage_generation_id": str(self._require_uuid(storage_generation_id))})
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
            self._quorum(c, f"genesis-commit:{request_id}", local_commit_id)
            row = self._claimed(c, trust_domain_id, request_id, storage_generation_id)
            if row["state"] in (GenesisState.CORE_COMMITTED.value, GenesisState.ANCHOR_PUBLISHED.value, GenesisState.COMMITTED.value) and row["local_commit_id"] != local_commit_id: raise CoreError("GENESIS_CONFLICT")
            if row["state"] == GenesisState.CLAIMED.value: c.execute("UPDATE cp_genesis SET local_commit_id=%s,state=%s WHERE trust_domain_id=%s", (local_commit_id, GenesisState.CORE_COMMITTED.value, self._require_uuid(trust_domain_id)))
            c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s", (self._require_uuid(trust_domain_id),)); return self._genesis(c.fetchone())

    def publish_genesis_anchor(self, *, trust_domain_id: uuid.UUID, request_id: str, storage_generation_id: uuid.UUID, anchor_hash: str) -> GenesisReservation:
        with self._tx() as c:
            self._quorum(c, f"genesis-anchor:{request_id}", anchor_hash)
            row = self._claimed(c, trust_domain_id, request_id, storage_generation_id)
            if row["anchor_hash"] and row["anchor_hash"] != anchor_hash: raise CoreError("GENESIS_ANCHOR_MISMATCH")
            if row["state"] not in (GenesisState.CORE_COMMITTED.value, GenesisState.ANCHOR_PUBLISHED.value, GenesisState.COMMITTED.value): raise CoreError("GENESIS_OUTCOME_UNKNOWN")
            if row["state"] != GenesisState.COMMITTED.value: c.execute("UPDATE cp_genesis SET anchor_hash=%s,state=%s WHERE trust_domain_id=%s", (anchor_hash, GenesisState.ANCHOR_PUBLISHED.value, self._require_uuid(trust_domain_id)))
            c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s", (self._require_uuid(trust_domain_id),)); return self._genesis(c.fetchone())

    def complete_genesis(self, *, trust_domain_id: uuid.UUID, request_id: str, storage_generation_id: uuid.UUID) -> GenesisReservation:
        with self._tx() as c:
            self._quorum(c, f"genesis-complete:{request_id}", str(self._require_uuid(trust_domain_id)))
            row = self._claimed(c, trust_domain_id, request_id, storage_generation_id)
            if row["state"] not in (GenesisState.ANCHOR_PUBLISHED.value, GenesisState.COMMITTED.value): raise CoreError("GENESIS_OUTCOME_UNKNOWN")
            c.execute("UPDATE cp_genesis SET state=%s WHERE trust_domain_id=%s", (GenesisState.COMMITTED.value, self._require_uuid(trust_domain_id))); c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s", (self._require_uuid(trust_domain_id),)); return self._genesis(c.fetchone())

    def genesis_status(self, trust_domain_id: uuid.UUID) -> GenesisReservation | None:
        with self._tx() as c:
            c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s", (self._require_uuid(trust_domain_id),)); row = c.fetchone(); return self._genesis(row) if row else None

    def initialize_domain(self, *, trust_domain_id: uuid.UUID, identity_id: uuid.UUID, continuity_id: uuid.UUID, storage_generation_id: uuid.UUID, control_plane_generation_id: uuid.UUID, owner_principal_id: str, owner_key_fingerprint: str, audit_high_water: int = 0, audit_head_hash: str | None = None) -> DomainState:
        with self._tx() as c:
            self._quorum(c, f"enroll:{continuity_id}", {"identity_id": str(self._require_uuid(identity_id)), "continuity_id": str(self._require_uuid(continuity_id))})
            c.execute("SELECT * FROM cp_genesis WHERE trust_domain_id=%s FOR UPDATE", (self._require_uuid(trust_domain_id),)); genesis = c.fetchone()
            if genesis is None:
                raise CoreError("GENESIS_CONFLICT")
            if genesis["identity_id"] and genesis["identity_id"] != self._require_uuid(identity_id): raise CoreError("IDENTITY_CONTINUITY_BINDING_MISMATCH")
            if genesis["continuity_id"] and genesis["continuity_id"] != self._require_uuid(continuity_id): raise CoreError("IDENTITY_CONTINUITY_BINDING_MISMATCH")
            if genesis["claimed_storage_generation_id"] and genesis["claimed_storage_generation_id"] != self._require_uuid(storage_generation_id): raise CoreError("GENESIS_STORAGE_NOT_CLAIMED")
            c.execute("UPDATE cp_genesis SET identity_id=COALESCE(identity_id,%s),continuity_id=COALESCE(continuity_id,%s) WHERE trust_domain_id=%s", (self._require_uuid(identity_id), self._require_uuid(continuity_id), self._require_uuid(trust_domain_id)))
            c.execute("SELECT * FROM cp_domains WHERE continuity_id=%s FOR UPDATE", (self._require_uuid(continuity_id),)); row = c.fetchone()
            if row:
                if row["trust_domain_id"] != self._require_uuid(trust_domain_id) or row["identity_id"] != self._require_uuid(identity_id):
                    raise CoreError("IDENTITY_CONTINUITY_BINDING_MISMATCH")
                if row["storage_generation_id"] != self._require_uuid(storage_generation_id) or row["control_plane_generation_id"] != self._require_uuid(control_plane_generation_id) or row["owner_principal_id"] != owner_principal_id or row["initial_owner_fingerprint"] != owner_key_fingerprint:
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
            self._quorum(c, f"lease:{continuity_id}:{principal_id}", {"capability": capability, "storage_generation_id": str(self._require_uuid(storage_generation_id))})
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
            self._quorum(c, f"mutation-prepare:{mutation_id}", mutation_id)
            c.execute("SELECT * FROM cp_domains WHERE continuity_id=%s FOR UPDATE", (self._require_uuid(continuity_id),)); d = c.fetchone()
            if not d: raise CoreError("CONTINUITY_UNKNOWN")
            ph = sha256_hex(payload)
            c.execute("SELECT * FROM cp_mutations WHERE mutation_id=%s FOR UPDATE", (mutation_id,)); existing = c.fetchone()
            if existing and existing["payload_hash"] != ph: raise CoreError("MUTATION_RETRY_CONFLICT")
            if existing and existing["state"] == MutationState.COMMITTED.value:
                if existing["continuity_id"] != self._require_uuid(continuity_id): raise CoreError("MUTATION_RETRY_CONTEXT_CONFLICT")
                return MutationPermit(mutation_id, self._require_uuid(existing["continuity_id"]), int(existing["epoch"]), self._require_uuid(existing["lease_id"]), self._require_uuid(existing["storage_generation_id"]), ph, int(existing["expected_state_version"]), int(existing["assigned_state_version"]), MutationState.COMMITTED)
            if epoch < d["epoch"]: raise CoreError("EPOCH_STALE")
            if epoch > d["epoch"]: raise CoreError("EPOCH_NOT_ISSUED")
            if d["lease_id"] != self._require_uuid(lease_id) or d["lease_principal_id"] != actor_principal_id or capability not in {"core_governance", "core_writer"} or d["storage_generation_id"] != self._require_uuid(storage_generation_id): raise CoreError("LEASE_FENCED")
            if expected_state_version != d["state_version"]: raise CoreError("OWNER_VERSION_STALE")
            old = existing
            if old:
                if old["payload_hash"] != ph: raise CoreError("MUTATION_RETRY_CONFLICT")
                if (
                    old["continuity_id"] != self._require_uuid(continuity_id)
                    or int(old["epoch"]) != epoch
                    or old["lease_id"] != self._require_uuid(lease_id)
                    or old["storage_generation_id"] != self._require_uuid(storage_generation_id)
                ):
                    raise CoreError("MUTATION_RETRY_CONTEXT_CONFLICT")
                if old["state"] == MutationState.COMMITTED.value: return MutationPermit(mutation_id, self._require_uuid(continuity_id), int(old["epoch"]), self._require_uuid(old["lease_id"]), self._require_uuid(old["storage_generation_id"]), ph, int(old["expected_state_version"]), int(old["assigned_state_version"]), MutationState.COMMITTED)
                if old["state"] == MutationState.ABORTED.value: c.execute("UPDATE cp_mutations SET state=%s,expected_state_version=%s,assigned_state_version=%s WHERE mutation_id=%s", (MutationState.PREPARED.value, expected_state_version, int(d["state_version"])+1, mutation_id))
                else: return MutationPermit(mutation_id, self._require_uuid(continuity_id), epoch, self._require_uuid(lease_id), self._require_uuid(storage_generation_id), ph, expected_state_version, int(old["assigned_state_version"]), MutationState.PREPARED)
            else: c.execute("INSERT INTO cp_mutations(mutation_id,continuity_id,epoch,lease_id,storage_generation_id,payload_hash,expected_state_version,assigned_state_version,state) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)", (mutation_id, self._require_uuid(continuity_id), epoch, self._require_uuid(lease_id), self._require_uuid(storage_generation_id), ph, expected_state_version, int(d["state_version"])+1, MutationState.PREPARED.value))
            return MutationPermit(mutation_id, self._require_uuid(continuity_id), epoch, self._require_uuid(lease_id), self._require_uuid(storage_generation_id), ph, expected_state_version, int(d["state_version"])+1, MutationState.PREPARED)

    def commit_mutation(self, *, mutation_id: str, local_commit_id: str, audit_head_hash: str, audit_seq: int | None = None) -> MutationPermit:
        with self._tx() as c:
            self._quorum(c, f"mutation-commit:{mutation_id}", mutation_id)
            c.execute("SELECT * FROM cp_mutations WHERE mutation_id=%s FOR UPDATE", (mutation_id,)); m = c.fetchone()
            if not m: raise CoreError("MUTATION_OUTCOME_UNKNOWN")
            if m["state"] == MutationState.ABORTED.value: raise CoreError("MUTATION_RETRY_CONFLICT")
            if m["state"] == MutationState.COMMITTED.value: return MutationPermit(mutation_id, self._require_uuid(m["continuity_id"]), int(m["epoch"]), self._require_uuid(m["lease_id"]), self._require_uuid(m["storage_generation_id"]), m["payload_hash"], int(m["expected_state_version"]), int(m["assigned_state_version"]), MutationState.COMMITTED)
            c.execute("SELECT audit_high_water FROM cp_domains WHERE continuity_id=%s AND epoch=%s AND storage_generation_id=%s AND state_version=%s FOR UPDATE", (m["continuity_id"], m["epoch"], m["storage_generation_id"], m["expected_state_version"]))
            domain = c.fetchone()
            if not domain: raise CoreError("LEASE_FENCED")
            current_audit = int(domain["audit_high_water"])
            next_audit = current_audit + 1 if audit_seq is None else int(audit_seq)
            if next_audit < current_audit: raise CoreError("CONTROL_PLANE_ROLLBACK_DETECTED")
            c.execute("UPDATE cp_domains SET state_version=%s,audit_high_water=%s,audit_head_hash=%s WHERE continuity_id=%s AND epoch=%s AND storage_generation_id=%s AND state_version=%s", (m["assigned_state_version"], next_audit, audit_head_hash, m["continuity_id"], m["epoch"], m["storage_generation_id"], m["expected_state_version"]))
            if c.rowcount != 1: raise CoreError("LEASE_FENCED")
            c.execute("UPDATE cp_mutations SET state=%s,local_commit_id=%s,audit_head_hash=%s,audit_seq=%s WHERE mutation_id=%s", (MutationState.COMMITTED.value, local_commit_id, audit_head_hash, audit_seq, mutation_id))
            return MutationPermit(mutation_id, self._require_uuid(m["continuity_id"]), int(m["epoch"]), self._require_uuid(m["lease_id"]), self._require_uuid(m["storage_generation_id"]), m["payload_hash"], int(m["expected_state_version"]), int(m["assigned_state_version"]), MutationState.COMMITTED)

    def sync_audit_checkpoint(self, *, continuity_id: uuid.UUID, audit_seq: int, audit_head_hash: str | None) -> None:
        with self._tx() as c:
            self._quorum(c, f"audit:{continuity_id}:{audit_seq}", audit_head_hash)
            c.execute("UPDATE cp_domains SET audit_high_water=%s,audit_head_hash=%s WHERE continuity_id=%s AND (audit_high_water<%s OR (audit_high_water=%s AND (audit_head_hash IS NOT DISTINCT FROM %s)))", (audit_seq, audit_head_hash, self._require_uuid(continuity_id), audit_seq, audit_seq, audit_head_hash))
            if c.rowcount != 1: raise CoreError("CONTROL_PLANE_ROLLBACK_DETECTED")

    def quarantine_recovery(self, continuity_id: uuid.UUID) -> None:
        with self._tx() as c:
            self._quorum(c, f"quarantine:{continuity_id}", RecoveryState.QUARANTINED.value)
            c.execute("UPDATE cp_domains SET recovery_state=%s,lease_id=NULL WHERE continuity_id=%s", (RecoveryState.QUARANTINED.value, self._require_uuid(continuity_id)))
            c.execute("UPDATE cp_mutations SET state=%s WHERE continuity_id=%s AND state=%s", (MutationState.ABORTED.value, self._require_uuid(continuity_id), MutationState.PREPARED.value))

    def abort_mutation(self, mutation_id: str) -> MutationPermit:
        with self._tx() as c:
            self._quorum(c, f"mutation-abort:{mutation_id}", MutationState.ABORTED.value)
            c.execute("SELECT * FROM cp_mutations WHERE mutation_id=%s FOR UPDATE", (mutation_id,)); m = c.fetchone()
            if not m: raise CoreError("MUTATION_OUTCOME_UNKNOWN")
            if m["state"] != MutationState.COMMITTED.value:
                c.execute("UPDATE cp_mutations SET state=%s WHERE mutation_id=%s", (MutationState.ABORTED.value, mutation_id)); m["state"] = MutationState.ABORTED.value
            return MutationPermit(mutation_id, self._require_uuid(m["continuity_id"]), int(m["epoch"]), self._require_uuid(m["lease_id"]), self._require_uuid(m["storage_generation_id"]), m["payload_hash"], int(m["expected_state_version"]), int(m["assigned_state_version"]), MutationState(m["state"]))

    def transfer_owner(self, *, continuity_id: uuid.UUID, expected_owner_version: int, current_owner_principal_id: str, target_principal_id: str, target_key_fingerprint: str, request_id: str | None = None) -> DomainState:
        with self._tx() as c:
            operation_id = request_id or f"owner-transfer:{continuity_id}:{expected_owner_version}"
            self._quorum(c, operation_id, {"target_principal_id": target_principal_id, "target_key_fingerprint": target_key_fingerprint})
            c.execute("SELECT * FROM cp_owner_transfers WHERE operation_id=%s", (operation_id,)); prior = c.fetchone()
            if prior:
                if prior["continuity_id"] != self._require_uuid(continuity_id) or prior["target_principal_id"] != target_principal_id or prior["target_key_fingerprint"] != target_key_fingerprint:
                    raise CoreError("OWNER_TRANSFER_CONFLICT")
                c.execute("SELECT * FROM cp_domains WHERE continuity_id=%s", (self._require_uuid(continuity_id),)); row = c.fetchone()
                if row: return self._domain(row)
            c.execute("UPDATE cp_domains SET owner_version=owner_version+1,owner_principal_id=%s,owner_key_fingerprint=%s,epoch=epoch+1,state_version=state_version+1,lease_id=NULL WHERE continuity_id=%s AND owner_version=%s AND owner_principal_id=%s RETURNING *", (target_principal_id, target_key_fingerprint, self._require_uuid(continuity_id), expected_owner_version, current_owner_principal_id)); row = c.fetchone()
            if not row: raise CoreError("OWNER_TRANSFER_CONFLICT")
            c.execute("UPDATE cp_mutations SET state=%s WHERE continuity_id=%s AND state=%s", (MutationState.ABORTED.value, self._require_uuid(continuity_id), MutationState.PREPARED.value))
            c.execute("INSERT INTO cp_owner_transfers(operation_id,continuity_id,expected_owner_version,target_principal_id,target_key_fingerprint) VALUES(%s,%s,%s,%s,%s)", (operation_id, self._require_uuid(continuity_id), expected_owner_version, target_principal_id, target_key_fingerprint))
            return self._domain(row)

    def claim_recovery(self, *, request_id: str, trust_domain_id: uuid.UUID, continuity_id: uuid.UUID, current_owner_principal_id: str, current_owner_record_hash: str, target_storage_generation_id: uuid.UUID, restore_manifest_hash: str) -> dict[str, Any]:
        with self._tx() as c:
            self._quorum(c, f"recovery-claim:{request_id}", {"continuity_id": str(self._require_uuid(continuity_id)), "restore_manifest_hash": restore_manifest_hash})
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
            self._quorum(c, f"recovery-activate:{request_id}", RecoveryState.ACTIVE.value)
            c.execute("SELECT * FROM cp_recovery_claims WHERE request_id=%s FOR UPDATE", (request_id,)); claim = c.fetchone()
            if not claim: raise CoreError("RESTORE_AUTHORIZATION_INVALID")
            if claim["status"] == RecoveryState.ACTIVE.value: return dict(claim)
            c.execute("UPDATE cp_domains SET epoch=epoch+1,state_version=state_version+1,storage_generation_id=%s,lease_id=NULL,recovery_state=%s,recovery_claim_request_id=%s WHERE continuity_id=%s AND epoch=%s RETURNING epoch", (claim["target_storage_generation_id"], RecoveryState.ACTIVE.value, request_id, claim["continuity_id"], claim["previous_epoch"])); row = c.fetchone()
            if not row: raise CoreError("CONTROL_PLANE_RECOVERY_CLAIM_CONFLICT")
            c.execute("UPDATE cp_mutations SET state=%s WHERE continuity_id=%s AND state=%s", (MutationState.ABORTED.value, claim["continuity_id"], MutationState.PREPARED.value))
            c.execute("UPDATE cp_recovery_claims SET target_epoch=%s,status=%s WHERE request_id=%s RETURNING *", (row["epoch"], RecoveryState.ACTIVE.value, request_id)); return dict(c.fetchone())

    def recovery_status(self, request_id: str) -> dict[str, Any] | None:
        with self._tx() as c: c.execute("SELECT * FROM cp_recovery_claims WHERE request_id=%s", (request_id,)); row = c.fetchone(); return dict(row) if row else None

    def export_checkpoint(self, continuity_id: uuid.UUID) -> dict[str, Any]:
        state = self.get_domain(continuity_id)
        return {"trust_domain_id": str(state.trust_domain_id), "identity_id": str(state.identity_id), "continuity_id": str(state.continuity_id), "epoch": state.epoch, "state_version": state.state_version, "owner_version": state.owner_version, "owner_principal_id": state.owner_principal_id, "owner_key_fingerprint": state.owner_key_fingerprint, "storage_generation_id": str(state.storage_generation_id), "control_plane_generation_id": str(state.control_plane_generation_id), "audit_high_water": state.audit_high_water, "audit_head_hash": state.audit_head_hash, "witness_set_version": self.witness_set_version}
