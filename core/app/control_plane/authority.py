from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
import hashlib
import threading
import uuid
from typing import Any

from ..canonical import canonical_json, sha256_hex, uuid4_opaque
from ..errors import CoreError


class GenesisState(StrEnum):
    EMPTY = "EMPTY"
    PREPARED_UNCLAIMED = "PREPARED_UNCLAIMED"
    CLAIMED = "CLAIMED"
    CORE_COMMITTED = "CORE_COMMITTED"
    ANCHOR_PUBLISHED = "ANCHOR_PUBLISHED"
    COMMITTED = "COMMITTED"


class MutationState(StrEnum):
    PREPARED = "PREPARED"
    COMMITTED = "COMMITTED"
    ABORTED = "ABORTED"


class RecoveryState(StrEnum):
    QUARANTINED = "RESTORE_QUARANTINED"
    PREPARED = "RECOVERY_PREPARED"
    ACTIVE = "ACTIVE"


@dataclass(slots=True)
class GenesisReservation:
    trust_domain_id: uuid.UUID
    manifest_hash: str
    request_id: str
    state: GenesisState = GenesisState.PREPARED_UNCLAIMED
    claimed_storage_generation_id: uuid.UUID | None = None
    local_commit_id: str | None = None
    anchor_hash: str | None = None


@dataclass(slots=True)
class Lease:
    lease_id: uuid.UUID
    continuity_id: uuid.UUID
    epoch: int
    principal_id: str
    capability: str
    storage_generation_id: uuid.UUID
    lease_generation: int


@dataclass(slots=True)
class MutationPermit:
    mutation_id: str
    continuity_id: uuid.UUID
    epoch: int
    lease_id: uuid.UUID
    storage_generation_id: uuid.UUID
    payload_hash: str
    expected_state_version: int
    assigned_state_version: int
    state: MutationState = MutationState.PREPARED


@dataclass(slots=True)
class DomainState:
    trust_domain_id: uuid.UUID
    continuity_id: uuid.UUID
    identity_id: uuid.UUID
    epoch: int
    state_version: int
    owner_version: int
    owner_principal_id: str
    owner_key_fingerprint: str
    initial_owner_fingerprint: str
    storage_generation_id: uuid.UUID
    control_plane_generation_id: uuid.UUID
    lease: Lease | None = None
    recovery_state: RecoveryState = RecoveryState.ACTIVE
    recovery_claim_request_id: str | None = None
    audit_high_water: int = 0
    audit_head_hash: str | None = None


class UnavailableControlPlane:
    """Production default: no local fallback can grant governance authority."""

    backend_name = "unavailable"

    def __getattr__(self, _name: str):
        def unavailable(*_args: Any, **_kwargs: Any):
            raise CoreError("CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE")

        return unavailable


class InMemoryControlPlane:
    """Deterministic 2-of-3 witness quorum used only by tests/dev fixtures.

    The authority is intentionally a separate object from the Core DB. A Core
    backup cannot clone this state. Production must replace it with a
    linearizable, independently durable control-plane service.
    """

    backend_name = "memory"
    witness_set_version = "witness-set-v1"
    protocol_version = "control-plane-v1"
    quorum_threshold = 2

    def __init__(self, *, available_witnesses: int = 3):
        self._lock = threading.RLock()
        self.available_witnesses = available_witnesses
        self._reservations: dict[uuid.UUID, GenesisReservation] = {}
        self._domains: dict[uuid.UUID, DomainState] = {}
        self._mutations: dict[str, MutationPermit] = {}
        self._recovery_claims: dict[str, dict[str, Any]] = {}

    def _require_quorum(self) -> None:
        if self.available_witnesses < self.quorum_threshold:
            raise CoreError("CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE")

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def prepare_genesis(
        self,
        *,
        trust_domain_id: uuid.UUID,
        manifest_hash: str,
        request_id: str,
    ) -> GenesisReservation:
        self._require_quorum()
        trust_domain_id = uuid4_opaque(trust_domain_id)
        with self._lock:
            current = self._reservations.get(trust_domain_id)
            if current is None:
                current = GenesisReservation(
                    trust_domain_id=trust_domain_id,
                    manifest_hash=manifest_hash,
                    request_id=request_id,
                )
                self._reservations[trust_domain_id] = current
                return current
            if current.manifest_hash == manifest_hash and current.request_id == request_id:
                return current
            raise CoreError("GENESIS_CONFLICT")

    def claim_genesis_storage(
        self,
        *,
        trust_domain_id: uuid.UUID,
        request_id: str,
        storage_generation_id: uuid.UUID,
    ) -> GenesisReservation:
        self._require_quorum()
        with self._lock:
            reservation = self._reservations.get(uuid4_opaque(trust_domain_id))
            if reservation is None:
                raise CoreError("GENESIS_CONFLICT")
            if reservation.request_id != request_id:
                raise CoreError("GENESIS_CONFLICT")
            if reservation.claimed_storage_generation_id is None:
                reservation.claimed_storage_generation_id = uuid4_opaque(storage_generation_id)
                reservation.state = GenesisState.CLAIMED
                return reservation
            if reservation.claimed_storage_generation_id == uuid4_opaque(storage_generation_id):
                return reservation
            raise CoreError("GENESIS_STORAGE_NOT_CLAIMED")

    def record_genesis_core_commit(
        self,
        *,
        trust_domain_id: uuid.UUID,
        request_id: str,
        storage_generation_id: uuid.UUID,
        local_commit_id: str,
    ) -> GenesisReservation:
        self._require_quorum()
        with self._lock:
            reservation = self._claimed_reservation(
                trust_domain_id, request_id, storage_generation_id
            )
            if reservation.state in {
                GenesisState.CORE_COMMITTED,
                GenesisState.ANCHOR_PUBLISHED,
                GenesisState.COMMITTED,
            }:
                if reservation.local_commit_id != local_commit_id:
                    raise CoreError("GENESIS_CONFLICT")
                return reservation
            reservation.local_commit_id = local_commit_id
            reservation.state = GenesisState.CORE_COMMITTED
            return reservation

    def publish_genesis_anchor(
        self,
        *,
        trust_domain_id: uuid.UUID,
        request_id: str,
        storage_generation_id: uuid.UUID,
        anchor_hash: str,
    ) -> GenesisReservation:
        self._require_quorum()
        with self._lock:
            reservation = self._claimed_reservation(
                trust_domain_id, request_id, storage_generation_id
            )
            if reservation.state == GenesisState.COMMITTED:
                if reservation.anchor_hash != anchor_hash:
                    raise CoreError("GENESIS_ANCHOR_MISMATCH")
                return reservation
            if reservation.state not in {
                GenesisState.CORE_COMMITTED,
                GenesisState.ANCHOR_PUBLISHED,
            }:
                raise CoreError("GENESIS_OUTCOME_UNKNOWN")
            if reservation.anchor_hash and reservation.anchor_hash != anchor_hash:
                raise CoreError("GENESIS_ANCHOR_MISMATCH")
            reservation.anchor_hash = anchor_hash
            reservation.state = GenesisState.ANCHOR_PUBLISHED
            return reservation

    def complete_genesis(
        self,
        *,
        trust_domain_id: uuid.UUID,
        request_id: str,
        storage_generation_id: uuid.UUID,
    ) -> GenesisReservation:
        self._require_quorum()
        with self._lock:
            reservation = self._claimed_reservation(
                trust_domain_id, request_id, storage_generation_id
            )
            if reservation.state not in {
                GenesisState.ANCHOR_PUBLISHED,
                GenesisState.COMMITTED,
            }:
                raise CoreError("GENESIS_OUTCOME_UNKNOWN")
            reservation.state = GenesisState.COMMITTED
            return reservation

    def genesis_status(self, trust_domain_id: uuid.UUID) -> GenesisReservation | None:
        with self._lock:
            return self._reservations.get(uuid4_opaque(trust_domain_id))

    def _claimed_reservation(
        self,
        trust_domain_id: uuid.UUID,
        request_id: str,
        storage_generation_id: uuid.UUID,
    ) -> GenesisReservation:
        reservation = self._reservations.get(uuid4_opaque(trust_domain_id))
        if reservation is None or reservation.request_id != request_id:
            raise CoreError("GENESIS_CONFLICT")
        if reservation.claimed_storage_generation_id != uuid4_opaque(storage_generation_id):
            raise CoreError("GENESIS_STORAGE_NOT_CLAIMED")
        return reservation

    def initialize_domain(
        self,
        *,
        trust_domain_id: uuid.UUID,
        identity_id: uuid.UUID,
        continuity_id: uuid.UUID,
        storage_generation_id: uuid.UUID,
        control_plane_generation_id: uuid.UUID,
        owner_principal_id: str,
        owner_key_fingerprint: str,
        audit_high_water: int = 0,
        audit_head_hash: str | None = None,
    ) -> DomainState:
        self._require_quorum()
        with self._lock:
            existing = self._domains.get(uuid4_opaque(continuity_id))
            if existing:
                if (
                    existing.identity_id != uuid4_opaque(identity_id)
                    or existing.trust_domain_id != uuid4_opaque(trust_domain_id)
                ):
                    raise CoreError("IDENTITY_CONTINUITY_BINDING_MISMATCH")
                return existing
            state = DomainState(
                trust_domain_id=uuid4_opaque(trust_domain_id),
                continuity_id=uuid4_opaque(continuity_id),
                identity_id=uuid4_opaque(identity_id),
                epoch=0,
                state_version=0,
                owner_version=0,
                owner_principal_id=owner_principal_id,
                owner_key_fingerprint=owner_key_fingerprint,
                initial_owner_fingerprint=owner_key_fingerprint,
                storage_generation_id=uuid4_opaque(storage_generation_id),
                control_plane_generation_id=uuid4_opaque(control_plane_generation_id),
                audit_high_water=audit_high_water,
                audit_head_hash=audit_head_hash,
            )
            self._domains[state.continuity_id] = state
            return state

    def get_domain(self, continuity_id: uuid.UUID) -> DomainState:
        with self._lock:
            state = self._domains.get(uuid4_opaque(continuity_id))
            if state is None:
                raise CoreError("CONTINUITY_UNKNOWN")
            return state

    def acquire_lease(
        self,
        *,
        continuity_id: uuid.UUID,
        principal_id: str,
        capability: str,
        storage_generation_id: uuid.UUID,
    ) -> Lease:
        self._require_quorum()
        with self._lock:
            state = self.get_domain(continuity_id)
            if state.recovery_state != RecoveryState.ACTIVE:
                raise CoreError("RESTORE_FENCE_UNPROVEN")
            if principal_id != state.owner_principal_id:
                raise CoreError("LEASE_FENCED")
            if capability not in {"core_governance", "core_writer"}:
                raise CoreError("LEASE_FENCED")
            if uuid4_opaque(storage_generation_id) != state.storage_generation_id:
                raise CoreError("LEASE_FENCED")
            lease = Lease(
                lease_id=uuid.uuid4(),
                continuity_id=state.continuity_id,
                epoch=state.epoch,
                principal_id=principal_id,
                capability=capability,
                storage_generation_id=state.storage_generation_id,
                lease_generation=(
                    state.lease.lease_generation + 1 if state.lease is not None else 1
                ),
            )
            state.lease = lease
            return lease

    def prepare_mutation(
        self,
        *,
        continuity_id: uuid.UUID,
        epoch: int | None,
        lease_id: uuid.UUID | None,
        mutation_id: str,
        payload: Any,
        actor_principal_id: str,
        capability: str,
        storage_generation_id: uuid.UUID,
        expected_state_version: int,
    ) -> MutationPermit:
        self._require_quorum()
        with self._lock:
            state = self.get_domain(continuity_id)
            if epoch is None:
                raise CoreError("EPOCH_REQUIRED")
            if epoch < state.epoch:
                raise CoreError("EPOCH_STALE")
            if epoch > state.epoch:
                raise CoreError("EPOCH_NOT_ISSUED")
            if lease_id is None:
                raise CoreError("LEASE_REQUIRED")
            if state.lease is None or state.lease.lease_id != uuid4_opaque(lease_id):
                raise CoreError("LEASE_FENCED")
            if state.lease.principal_id != actor_principal_id:
                raise CoreError("LEASE_FENCED")
            if capability not in {"core_governance", "core_writer"}:
                raise CoreError("LEASE_FENCED")
            if state.storage_generation_id != uuid4_opaque(storage_generation_id):
                raise CoreError("LEASE_FENCED")
            if expected_state_version != state.state_version:
                raise CoreError("OWNER_VERSION_STALE")
            payload_hash = sha256_hex(payload)
            previous = self._mutations.get(mutation_id)
            if previous is not None:
                if previous.payload_hash != payload_hash:
                    raise CoreError("MUTATION_RETRY_CONFLICT")
                if (
                    previous.continuity_id != state.continuity_id
                    or previous.epoch != state.epoch
                    or previous.lease_id != uuid4_opaque(lease_id)
                    or previous.storage_generation_id != state.storage_generation_id
                ):
                    raise CoreError("MUTATION_RETRY_CONTEXT_CONFLICT")
                if previous.state == MutationState.COMMITTED:
                    if expected_state_version < previous.assigned_state_version:
                        raise CoreError("MUTATION_RETRY_CONTEXT_CONFLICT")
                    return previous
                if previous.expected_state_version != expected_state_version:
                    raise CoreError("MUTATION_RETRY_CONTEXT_CONFLICT")
                if previous.state == MutationState.ABORTED:
                    previous = MutationPermit(
                        mutation_id=mutation_id,
                        continuity_id=state.continuity_id,
                        epoch=state.epoch,
                        lease_id=state.lease.lease_id,
                        storage_generation_id=state.storage_generation_id,
                        payload_hash=payload_hash,
                        expected_state_version=expected_state_version,
                        assigned_state_version=state.state_version + 1,
                    )
                    self._mutations[mutation_id] = previous
                return previous
            permit = MutationPermit(
                mutation_id=mutation_id,
                continuity_id=state.continuity_id,
                epoch=state.epoch,
                lease_id=state.lease.lease_id,
                storage_generation_id=state.storage_generation_id,
                payload_hash=payload_hash,
                expected_state_version=expected_state_version,
                assigned_state_version=state.state_version + 1,
            )
            self._mutations[mutation_id] = permit
            return permit

    def commit_mutation(
        self,
        *,
        mutation_id: str,
        local_commit_id: str,
        audit_head_hash: str,
        audit_seq: int | None = None,
    ) -> MutationPermit:
        self._require_quorum()
        with self._lock:
            permit = self._mutations.get(mutation_id)
            if permit is None:
                raise CoreError("MUTATION_OUTCOME_UNKNOWN")
            if permit.state == MutationState.COMMITTED:
                return permit
            if permit.state == MutationState.ABORTED:
                raise CoreError("MUTATION_RETRY_CONFLICT")
            state = self.get_domain(permit.continuity_id)
            if state.epoch != permit.epoch or state.storage_generation_id != permit.storage_generation_id:
                raise CoreError("LEASE_FENCED")
            state.state_version = permit.assigned_state_version
            state.audit_high_water = (
                audit_seq if audit_seq is not None else state.audit_high_water + 1
            )
            state.audit_head_hash = audit_head_hash
            permit.state = MutationState.COMMITTED
            return permit

    def sync_audit_checkpoint(
        self,
        *,
        continuity_id: uuid.UUID,
        audit_seq: int,
        audit_head_hash: str | None,
    ) -> None:
        self._require_quorum()
        with self._lock:
            state = self.get_domain(continuity_id)
            if audit_seq < state.audit_high_water:
                raise CoreError("CONTROL_PLANE_ROLLBACK_DETECTED")
            state.audit_high_water = audit_seq
            state.audit_head_hash = audit_head_hash

    def quarantine_recovery(self, continuity_id: uuid.UUID) -> None:
        self._require_quorum()
        with self._lock:
            state = self.get_domain(continuity_id)
            state.recovery_state = RecoveryState.QUARANTINED
            state.lease = None

    def abort_mutation(self, mutation_id: str) -> MutationPermit:
        self._require_quorum()
        with self._lock:
            permit = self._mutations.get(mutation_id)
            if permit is None:
                raise CoreError("MUTATION_OUTCOME_UNKNOWN")
            if permit.state == MutationState.COMMITTED:
                return permit
            permit.state = MutationState.ABORTED
            return permit

    def transfer_owner(
        self,
        *,
        continuity_id: uuid.UUID,
        expected_owner_version: int,
        current_owner_principal_id: str,
        target_principal_id: str,
        target_key_fingerprint: str,
        request_id: str | None = None,
    ) -> DomainState:
        self._require_quorum()
        with self._lock:
            state = self.get_domain(continuity_id)
            if state.owner_principal_id != current_owner_principal_id:
                raise CoreError("OWNER_TRANSFER_CONFLICT")
            if state.owner_version != expected_owner_version:
                raise CoreError("OWNER_VERSION_STALE")
            state.owner_version += 1
            state.owner_principal_id = target_principal_id
            state.owner_key_fingerprint = target_key_fingerprint
            state.epoch += 1
            state.state_version += 1
            state.lease = None
            return state

    def claim_recovery(
        self,
        *,
        request_id: str,
        trust_domain_id: uuid.UUID,
        continuity_id: uuid.UUID,
        current_owner_principal_id: str,
        current_owner_record_hash: str,
        target_storage_generation_id: uuid.UUID,
        restore_manifest_hash: str,
    ) -> dict[str, Any]:
        self._require_quorum()
        with self._lock:
            state = self.get_domain(continuity_id)
            if state.trust_domain_id != uuid4_opaque(trust_domain_id):
                raise CoreError("RESTORE_AUTHORIZATION_SCOPE_MISMATCH")
            expected_owner_hash = sha256_hex(
                {
                    "owner_version": state.owner_version,
                    "owner_principal_id": state.owner_principal_id,
                    "owner_key_fingerprint": state.owner_key_fingerprint,
                }
            )
            if (
                current_owner_principal_id != state.owner_principal_id
                or current_owner_record_hash != expected_owner_hash
            ):
                raise CoreError("RESTORE_OWNER_UNPROVEN")
            prior = self._recovery_claims.get(request_id)
            if prior is not None:
                if prior["restore_manifest_hash"] != restore_manifest_hash:
                    raise CoreError("RESTORE_REQUEST_CONFLICT")
                return prior
            for claim in self._recovery_claims.values():
                if claim["continuity_id"] == state.continuity_id and claim["status"] != "ABORTED":
                    raise CoreError("CONTROL_PLANE_RECOVERY_CLAIM_CONFLICT")
            claim = {
                "request_id": request_id,
                "trust_domain_id": str(state.trust_domain_id),
                "continuity_id": str(state.continuity_id),
                "restore_manifest_hash": restore_manifest_hash,
                "target_storage_generation_id": str(uuid4_opaque(target_storage_generation_id)),
                "status": RecoveryState.PREPARED.value,
                "previous_epoch": state.epoch,
                "target_epoch": None,
            }
            self._recovery_claims[request_id] = claim
            return claim

    def activate_recovery(self, request_id: str) -> dict[str, Any]:
        self._require_quorum()
        with self._lock:
            claim = self._recovery_claims.get(request_id)
            if claim is None:
                raise CoreError("RESTORE_AUTHORIZATION_INVALID")
            if claim["status"] == RecoveryState.ACTIVE.value:
                return claim
            state = self.get_domain(uuid.UUID(claim["continuity_id"]))
            if state.recovery_state == RecoveryState.ACTIVE and state.epoch != claim["previous_epoch"]:
                raise CoreError("CONTROL_PLANE_RECOVERY_CLAIM_CONFLICT")
            state.epoch += 1
            state.state_version += 1
            state.storage_generation_id = uuid.UUID(claim["target_storage_generation_id"])
            state.lease = None
            state.recovery_state = RecoveryState.ACTIVE
            state.recovery_claim_request_id = request_id
            claim["target_epoch"] = state.epoch
            claim["status"] = RecoveryState.ACTIVE.value
            return claim

    def recovery_status(self, request_id: str) -> dict[str, Any] | None:
        with self._lock:
            claim = self._recovery_claims.get(request_id)
            return dict(claim) if claim is not None else None

    def export_checkpoint(self, continuity_id: uuid.UUID) -> dict[str, Any]:
        with self._lock:
            state = self.get_domain(continuity_id)
            return {
                "trust_domain_id": str(state.trust_domain_id),
                "identity_id": str(state.identity_id),
                "continuity_id": str(state.continuity_id),
                "epoch": state.epoch,
                "state_version": state.state_version,
                "owner_version": state.owner_version,
                "owner_principal_id": state.owner_principal_id,
                "owner_key_fingerprint": state.owner_key_fingerprint,
                "storage_generation_id": str(state.storage_generation_id),
                "control_plane_generation_id": str(state.control_plane_generation_id),
                "audit_high_water": state.audit_high_water,
                "audit_head_hash": state.audit_head_hash,
                "witness_set_version": self.witness_set_version,
            }

    def clone(self) -> "InMemoryControlPlane":
        """Return a fresh authority object, explicitly modeling a wrong clone.

        A Core database backup must never clone the actual authority. Tests use
        this helper to prove that only the shared authority can fence writers.
        """
        return InMemoryControlPlane(available_witnesses=self.available_witnesses)
