from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from enum import StrEnum
import math
import threading
import uuid
from typing import Any, Callable

from ..canonical import sha256_hex, uuid4_opaque
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


@dataclass(frozen=True, slots=True)
class Lease:
    lease_id: uuid.UUID
    continuity_id: uuid.UUID
    epoch: int
    principal_id: str
    capability: str
    storage_generation_id: uuid.UUID
    lease_generation: int
    expires_at: datetime | None = None


@dataclass(frozen=True, slots=True)
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
    lease_generation: int = 0
    actor_principal_id: str = ""
    capability: str = ""
    local_commit_id: str = ""
    audit_seq: int | None = None
    audit_head_hash: str | None = None


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

    def __init__(
        self, *, available_witnesses: int = 3,
        clock: Callable[[], datetime] | None = None,
        lease_ttl_seconds: float = 60.0,
    ):
        if (isinstance(lease_ttl_seconds, bool)
                or not math.isfinite(lease_ttl_seconds) or lease_ttl_seconds <= 0):
            raise ValueError("lease TTL must be finite and positive")
        self._lock = threading.RLock()
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lease_ttl = timedelta(seconds=lease_ttl_seconds)
        self.available_witnesses = available_witnesses
        self._reservations: dict[uuid.UUID, GenesisReservation] = {}
        self._domains: dict[uuid.UUID, DomainState] = {}
        self._mutations: dict[str, MutationPermit] = {}
        self._recovery_claims: dict[str, dict[str, Any]] = {}
        self._lease_generations: dict[uuid.UUID, int] = {}

    def _require_quorum(self) -> None:
        if self.available_witnesses < self.quorum_threshold:
            raise CoreError("CONTROL_PLANE_WITNESS_QUORUM_UNAVAILABLE")

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise CoreError("LEASE_FENCED")
        return now

    def _require_canonical_write_eligibility(self, state: DomainState) -> None:
        """One authority-owned write gate; callers hold the authority lock."""
        self._require_quorum()
        reservation = self._reservations.get(state.trust_domain_id)
        if reservation is None or reservation.state != GenesisState.COMMITTED:
            raise CoreError("GENESIS_OUTCOME_UNKNOWN")
        if state.recovery_state != RecoveryState.ACTIVE:
            raise CoreError("RESTORE_FENCE_UNPROVEN")

    def require_canonical_write_eligibility(self, continuity_id: uuid.UUID) -> None:
        with self._lock:
            self._require_canonical_write_eligibility(self.get_domain(continuity_id))

    def _require_current_lease(
        self, state: DomainState, *, epoch: int | None, lease_id: uuid.UUID | None,
        actor_principal_id: str, capability: str, storage_generation_id: uuid.UUID,
        lease_generation: int | None = None,
    ) -> Lease:
        if epoch is None:
            raise CoreError("EPOCH_REQUIRED")
        if epoch < state.epoch:
            raise CoreError("EPOCH_STALE")
        if epoch > state.epoch:
            raise CoreError("EPOCH_NOT_ISSUED")
        if lease_id is None:
            raise CoreError("LEASE_REQUIRED")
        lease = state.lease
        if (
            lease is None or lease.lease_id != uuid4_opaque(lease_id)
            or lease.continuity_id != state.continuity_id
            or lease.epoch != state.epoch
            or lease.principal_id != actor_principal_id
            or actor_principal_id != state.owner_principal_id
            or capability not in {"core_governance", "core_writer"}
            or lease.capability not in {"core_governance", capability}
            or lease.storage_generation_id != state.storage_generation_id
            or uuid4_opaque(storage_generation_id) != state.storage_generation_id
            or (lease_generation is not None and lease_generation != lease.lease_generation)
            or lease.expires_at is None or lease.expires_at <= self._now()
        ):
            raise CoreError("LEASE_FENCED")
        return lease

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
            self._require_quorum()
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
            self._require_canonical_write_eligibility(state)
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
                lease_generation=self._lease_generations.get(state.continuity_id, 0) + 1,
                expires_at=self._now() + self._lease_ttl,
            )
            state.lease = lease
            self._lease_generations[state.continuity_id] = lease.lease_generation
            return replace(lease)

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
        local_commit_id: str,
    ) -> MutationPermit:
        self._require_quorum()
        with self._lock:
            self._require_quorum()
            state = self.get_domain(continuity_id)
            payload_hash = sha256_hex(payload)
            if not isinstance(local_commit_id, str) or not local_commit_id.strip():
                raise CoreError("MUTATION_RETRY_CONTEXT_CONFLICT")
            previous = self._mutations.get(mutation_id)
            if previous is not None:
                if previous.payload_hash != payload_hash:
                    raise CoreError("MUTATION_RETRY_CONFLICT")
                if (
                    previous.continuity_id != state.continuity_id
                    or previous.epoch != epoch
                    or previous.lease_id != lease_id
                    or previous.storage_generation_id != uuid4_opaque(storage_generation_id)
                    or previous.actor_principal_id != actor_principal_id
                    or previous.capability != capability
                    or previous.local_commit_id != local_commit_id
                ):
                    raise CoreError("MUTATION_RETRY_CONTEXT_CONFLICT")
                if previous.state == MutationState.COMMITTED:
                    if (expected_state_version != previous.expected_state_version
                            and expected_state_version != state.state_version):
                        raise CoreError("MUTATION_RETRY_CONTEXT_CONFLICT")
                    # Historical terminal lookup never grants a new write.
                    return replace(previous)
                if previous.expected_state_version != expected_state_version:
                    raise CoreError("MUTATION_RETRY_CONTEXT_CONFLICT")
            self._require_canonical_write_eligibility(state)
            lease = self._require_current_lease(
                state, epoch=epoch, lease_id=lease_id,
                actor_principal_id=actor_principal_id, capability=capability,
                storage_generation_id=storage_generation_id,
                lease_generation=previous.lease_generation if previous is not None else None,
            )
            if expected_state_version != state.state_version:
                raise CoreError("OWNER_VERSION_STALE")
            if previous is not None and previous.state == MutationState.PREPARED:
                return replace(previous)
            permit = MutationPermit(
                mutation_id=mutation_id,
                continuity_id=state.continuity_id,
                epoch=state.epoch,
                lease_id=lease.lease_id,
                storage_generation_id=state.storage_generation_id,
                payload_hash=payload_hash,
                expected_state_version=expected_state_version,
                assigned_state_version=state.state_version + 1,
                lease_generation=lease.lease_generation,
                actor_principal_id=actor_principal_id,
                capability=capability,
                local_commit_id=local_commit_id,
            )
            self._mutations[mutation_id] = permit
            return replace(permit)

    def commit_mutation(
        self,
        *,
        mutation_id: str,
        permit: MutationPermit,
        payload: Any,
        local_commit_id: str,
        audit_head_hash: str,
        audit_seq: int | None = None,
    ) -> MutationPermit:
        self._require_quorum()
        with self._lock:
            self._require_quorum()
            issued = self._mutations.get(mutation_id)
            if issued is None:
                raise CoreError("MUTATION_OUTCOME_UNKNOWN")
            if (not isinstance(permit, MutationPermit)
                    or (permit != issued and not (
                        issued.state == MutationState.COMMITTED
                        and permit == replace(issued, state=MutationState.PREPARED,
                                              audit_seq=None, audit_head_hash=None)))
                    or issued.payload_hash != sha256_hex(payload)
                    or issued.local_commit_id != local_commit_id):
                raise CoreError("MUTATION_RETRY_CONTEXT_CONFLICT")
            if issued.state == MutationState.COMMITTED:
                if audit_seq != issued.audit_seq or audit_head_hash != issued.audit_head_hash:
                    raise CoreError("MUTATION_RETRY_CONTEXT_CONFLICT")
                return replace(issued)
            if issued.state == MutationState.ABORTED:
                raise CoreError("MUTATION_RETRY_CONFLICT")
            state = self.get_domain(issued.continuity_id)
            self._require_canonical_write_eligibility(state)
            self._require_current_lease(
                state, epoch=issued.epoch, lease_id=issued.lease_id,
                actor_principal_id=issued.actor_principal_id, capability=issued.capability,
                storage_generation_id=issued.storage_generation_id,
                lease_generation=issued.lease_generation,
            )
            if (issued.expected_state_version != state.state_version
                    or issued.assigned_state_version != state.state_version + 1):
                raise CoreError("OWNER_VERSION_STALE")
            if (isinstance(audit_seq, bool) or not isinstance(audit_seq, int)
                    or audit_seq != state.audit_high_water + 1
                    or not isinstance(audit_head_hash, str) or not audit_head_hash):
                raise CoreError("AUDIT_HIGH_WATER_UNPROVEN")
            # Every rejecting check is above this point. Final fencing and the
            # state/audit transition occur under this same authority lock.
            committed = replace(issued, state=MutationState.COMMITTED,
                                audit_seq=audit_seq, audit_head_hash=audit_head_hash)
            state.state_version = issued.assigned_state_version
            state.audit_high_water = audit_seq
            state.audit_head_hash = audit_head_hash
            self._mutations[mutation_id] = committed
            return replace(committed)

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
            if (isinstance(audit_seq, bool) or not isinstance(audit_seq, int)
                    or audit_seq < state.audit_high_water):
                raise CoreError("CONTROL_PLANE_ROLLBACK_DETECTED")
            if audit_seq == state.audit_high_water and audit_head_hash != state.audit_head_hash:
                raise CoreError("AUDIT_HIGH_WATER_UNPROVEN")
            if audit_seq > 0 and (not isinstance(audit_head_hash, str) or not audit_head_hash):
                raise CoreError("AUDIT_HIGH_WATER_UNPROVEN")
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
                return replace(permit)
            permit = replace(permit, state=MutationState.ABORTED)
            self._mutations[mutation_id] = permit
            return replace(permit)

    def transfer_owner(
        self,
        *,
        continuity_id: uuid.UUID,
        expected_owner_version: int,
        current_owner_principal_id: str,
        target_principal_id: str,
        target_key_fingerprint: str,
    ) -> DomainState:
        self._require_quorum()
        with self._lock:
            state = self.get_domain(continuity_id)
            self._require_canonical_write_eligibility(state)
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
                if (prior["restore_manifest_hash"] != restore_manifest_hash
                        or prior["trust_domain_id"] != str(state.trust_domain_id)
                        or prior["continuity_id"] != str(state.continuity_id)
                        or prior["target_storage_generation_id"]
                        != str(uuid4_opaque(target_storage_generation_id))):
                    raise CoreError("RESTORE_REQUEST_CONFLICT")
                return deepcopy(prior)
            reservation = self._reservations.get(state.trust_domain_id)
            if reservation is None or reservation.state != GenesisState.COMMITTED:
                raise CoreError("GENESIS_OUTCOME_UNKNOWN")
            if state.recovery_state != RecoveryState.QUARANTINED:
                raise CoreError("RESTORE_FENCE_UNPROVEN")
            for claim in self._recovery_claims.values():
                if (claim["continuity_id"] == str(state.continuity_id)
                        and claim["status"] == RecoveryState.PREPARED.value):
                    raise CoreError("CONTROL_PLANE_RECOVERY_CLAIM_CONFLICT")
            target_storage_generation_id = uuid4_opaque(target_storage_generation_id)
            if target_storage_generation_id == state.storage_generation_id:
                raise CoreError("RESTORE_REQUEST_CONFLICT")
            claim = {
                "request_id": request_id,
                "trust_domain_id": str(state.trust_domain_id),
                "continuity_id": str(state.continuity_id),
                "restore_manifest_hash": restore_manifest_hash,
                "target_storage_generation_id": str(target_storage_generation_id),
                "status": RecoveryState.PREPARED.value,
                "previous_epoch": state.epoch,
                "previous_state_version": state.state_version,
                "source_checkpoint": self.export_checkpoint(state.continuity_id),
                "target_epoch": None,
                "target_state_version": None,
                "audit_seq": None,
                "audit_head_hash": None,
            }
            self._recovery_claims[request_id] = claim
            return deepcopy(claim)

    def activate_recovery(self, request_id: str) -> dict[str, Any]:
        self._require_quorum()
        with self._lock:
            claim = self._recovery_claims.get(request_id)
            if claim is None:
                raise CoreError("RESTORE_AUTHORIZATION_INVALID")
            if claim["target_epoch"] is not None:
                return deepcopy(claim)
            state = self.get_domain(uuid.UUID(claim["continuity_id"]))
            if (state.recovery_state != RecoveryState.QUARANTINED
                    or self.export_checkpoint(state.continuity_id) != claim["source_checkpoint"]):
                raise CoreError("CONTROL_PLANE_RECOVERY_CLAIM_CONFLICT")
            state.epoch += 1
            state.state_version += 1
            state.storage_generation_id = uuid.UUID(claim["target_storage_generation_id"])
            state.lease = None
            # The target is fenced until its local rebase audit is reconciled.
            state.recovery_state = RecoveryState.PREPARED
            state.recovery_claim_request_id = request_id
            claim["target_epoch"] = state.epoch
            claim["target_state_version"] = state.state_version
            return deepcopy(claim)

    def complete_recovery(
        self, request_id: str, *, audit_seq: int, audit_head_hash: str,
    ) -> dict[str, Any]:
        """Publish the rebase audit and release the recovery fence atomically."""
        with self._lock:
            self._require_quorum()
            claim = self._recovery_claims.get(request_id)
            if claim is None or claim["target_epoch"] is None:
                raise CoreError("RESTORE_AUTHORIZATION_INVALID")
            if claim["status"] == RecoveryState.ACTIVE.value:
                if audit_seq != claim["audit_seq"] or audit_head_hash != claim["audit_head_hash"]:
                    raise CoreError("RESTORE_REQUEST_CONFLICT")
                return deepcopy(claim)
            state = self.get_domain(uuid.UUID(claim["continuity_id"]))
            source = claim["source_checkpoint"]
            current_audit = (state.audit_high_water, state.audit_head_hash)
            admissible_audits = {
                (source["audit_high_water"], source["audit_head_hash"]),
                (audit_seq, audit_head_hash),
            }
            if (state.recovery_state != RecoveryState.PREPARED
                    or state.recovery_claim_request_id != request_id
                    or state.epoch != claim["target_epoch"]
                    or state.state_version != claim["target_state_version"]
                    or str(state.storage_generation_id) != claim["target_storage_generation_id"]
                    or current_audit not in admissible_audits
                    or audit_seq != source["audit_high_water"] + 1):
                raise CoreError("RESTORE_STATE_GAP")
            self.sync_audit_checkpoint(
                continuity_id=state.continuity_id,
                audit_seq=audit_seq, audit_head_hash=audit_head_hash,
            )
            state.recovery_state = RecoveryState.ACTIVE
            claim["status"] = RecoveryState.ACTIVE.value
            claim["audit_seq"] = audit_seq
            claim["audit_head_hash"] = audit_head_hash
            return deepcopy(claim)

    def recovery_status(self, request_id: str) -> dict[str, Any] | None:
        with self._lock:
            self._require_quorum()
            claim = self._recovery_claims.get(request_id)
            return deepcopy(claim) if claim is not None else None

    def export_checkpoint(self, continuity_id: uuid.UUID) -> dict[str, Any]:
        with self._lock:
            self._require_quorum()
            state = self.get_domain(continuity_id)
            return {
                "trust_domain_id": str(state.trust_domain_id),
                "continuity_id": str(state.continuity_id),
                "identity_id": str(state.identity_id),
                "initial_owner_fingerprint": state.initial_owner_fingerprint,
                "epoch": state.epoch,
                "state_version": state.state_version,
                "owner_version": state.owner_version,
                "owner_principal_id": state.owner_principal_id,
                "owner_key_fingerprint": state.owner_key_fingerprint,
                "storage_generation_id": str(state.storage_generation_id),
                "control_plane_generation_id": str(state.control_plane_generation_id),
                "audit_high_water": state.audit_high_water,
                "audit_head_hash": state.audit_head_hash,
                "recovery_state": state.recovery_state.value,
                "recovery_claim_request_id": state.recovery_claim_request_id,
                "witness_set_version": self.witness_set_version,
            }

    def clone(self) -> "InMemoryControlPlane":
        """Return a fresh authority object, explicitly modeling a wrong clone.

        A Core database backup must never clone the actual authority. Tests use
        this helper to prove that only the shared authority can fence writers.
        """
        return InMemoryControlPlane(available_witnesses=self.available_witnesses)
