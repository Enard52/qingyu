from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .audit import append_audit, verify_audit_chain
from .canonical import sha256_hex, uuid4_opaque
from .control_plane.authority import (
    InMemoryControlPlane,
    MutationPermit,
    UnavailableControlPlane,
)
from .errors import CoreError
from .models import (
    ContinuityAlias,
    ContinuityRegistry,
    ControlPlaneState,
    CoreMetadata,
    GenesisAttempt,
    GenesisRecord,
    IdentityRegistry,
    MutationReceipt,
    RestoreRecord,
)
from .schemas import (
    GenesisRequest,
    IdentityStatus,
    MutationRequest,
    MutationResult,
    RestoreRequest,
    RestoreVerification,
)


@dataclass(slots=True)
class GenesisResult:
    genesis_id: uuid.UUID
    qingyu_identity_id: uuid.UUID
    continuity_id: uuid.UUID
    continuity_alias: str
    continuity_epoch: int
    status: str
    fingerprint: str
    manifest_hash: str
    storage_generation_id: uuid.UUID


class CoreFoundationService:
    """Identity and governance foundation; no domain-memory models live here."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        authority: InMemoryControlPlane | UnavailableControlPlane,
    ):
        self.session_factory = session_factory
        self.authority = authority

    def _session(self) -> Session:
        return self.session_factory()

    @staticmethod
    def _manifest(request: GenesisRequest) -> dict[str, object]:
        return {
            "trust_domain_id": str(request.trust_domain_id),
            "qingyu_identity_id": str(request.qingyu_identity_id),
            "continuity_id": str(request.continuity_id),
            "continuity_alias": request.continuity_alias,
            "genesis_version": request.genesis_version,
            "id_scheme": "uuidv4",
            "initial_epoch": 0,
            "initial_owner_fingerprint": request.initial_owner_fingerprint,
            "witness_set_version": "witness-set-v1",
            "quorum_threshold": 2,
            "protocol_version": "control-plane-v1",
            "constitution_genesis_ref": request.constitution_genesis_ref,
            "constitution_genesis_hash": request.constitution_genesis_hash,
            "genesis_nonce": request.genesis_nonce,
            "actor_principal_id": request.actor_principal_id,
            "governance_provenance": request.governance_provenance,
        }

    def _quarantine(self, *, reason: str) -> None:
        session = self._session()
        try:
            with session.begin():
                metadata = session.execute(
                    select(CoreMetadata).where(CoreMetadata.id == 1).with_for_update()
                ).scalar_one_or_none()
                if metadata is not None:
                    metadata.status = "RESTORE_QUARANTINED"
        finally:
            session.close()

    def bootstrap_genesis(self, request: GenesisRequest) -> GenesisResult:
        manifest = self._manifest(request)
        manifest_hash = sha256_hex(manifest)
        # Resolve a completed local bootstrap before asking the authority for a
        # new storage claim. This makes the same request safely idempotent even
        # though storage generation identifiers are freshly proposed per call.
        precheck = self._session()
        try:
            existing = precheck.scalar(select(GenesisRecord).limit(1))
            if existing is not None:
                if existing.manifest_hash != manifest_hash:
                    raise CoreError("GENESIS_ALREADY_EXISTS")
                metadata = precheck.get(CoreMetadata, 1)
                reservation = self.authority.genesis_status(existing.trust_domain_id)
                if (
                    reservation is None
                    or reservation.state.value != "COMMITTED"
                    or metadata is None
                    or reservation.claimed_storage_generation_id != metadata.active_storage_generation_id
                ):
                    self._quarantine(reason="GENESIS_OUTCOME_UNKNOWN")
                    raise CoreError("GENESIS_OUTCOME_UNKNOWN")
                return GenesisResult(
                    genesis_id=existing.genesis_id,
                    qingyu_identity_id=existing.qingyu_identity_id,
                    continuity_id=existing.continuity_id,
                    continuity_alias=existing.continuity_alias,
                    continuity_epoch=0,
                    status="COMMITTED",
                    fingerprint=existing.fingerprint,
                    manifest_hash=existing.manifest_hash,
                    storage_generation_id=(metadata.active_storage_generation_id if metadata else uuid.uuid4()),
                )
        finally:
            precheck.close()
        storage_generation_id = uuid.uuid4()
        control_plane_generation_id = uuid.uuid4()
        reservation = self.authority.prepare_genesis(
            trust_domain_id=request.trust_domain_id,
            manifest_hash=manifest_hash,
            request_id=request.genesis_request_id,
        )
        reservation = self.authority.claim_genesis_storage(
            trust_domain_id=request.trust_domain_id,
            request_id=request.genesis_request_id,
            storage_generation_id=storage_generation_id,
        )
        if reservation.claimed_storage_generation_id != storage_generation_id:
            raise CoreError("GENESIS_STORAGE_NOT_CLAIMED")

        genesis_id = uuid.uuid4()
        fingerprint = sha256_hex(
            {
                "manifest_hash": manifest_hash,
                "trust_domain_id": str(request.trust_domain_id),
                "witness_set_version": "witness-set-v1",
                "quorum_threshold": 2,
            }
        )
        local_commit_id = uuid.uuid4().hex
        genesis_audit_seq = 0
        genesis_audit_head_hash: str | None = None
        session = self._session()
        try:
            with session.begin():
                metadata = session.execute(
                    select(CoreMetadata).where(CoreMetadata.id == 1).with_for_update()
                ).scalar_one_or_none()
                if metadata is None:
                    raise CoreError("CORE_SCHEMA_NOT_INITIALIZED")
                existing = session.scalar(select(GenesisRecord).limit(1))
                if existing is not None:
                    if existing.manifest_hash == manifest_hash:
                        reservation = self.authority.genesis_status(existing.trust_domain_id)
                        if (
                            reservation is None
                            or reservation.state.value != "COMMITTED"
                            or metadata.active_storage_generation_id is None
                            or reservation.claimed_storage_generation_id != metadata.active_storage_generation_id
                        ):
                            metadata.status = "RESTORE_QUARANTINED"
                            raise CoreError("GENESIS_OUTCOME_UNKNOWN")
                        return GenesisResult(
                            genesis_id=existing.genesis_id,
                            qingyu_identity_id=existing.qingyu_identity_id,
                            continuity_id=existing.continuity_id,
                            continuity_alias=existing.continuity_alias,
                            continuity_epoch=0,
                            status="COMMITTED",
                            fingerprint=existing.fingerprint,
                            manifest_hash=existing.manifest_hash,
                            storage_generation_id=metadata.active_storage_generation_id,
                        )
                    raise CoreError("GENESIS_ALREADY_EXISTS")
                identity_count = session.scalar(select(func.count()).select_from(IdentityRegistry)) or 0
                continuity_count = session.scalar(select(func.count()).select_from(ContinuityRegistry)) or 0
                audit_count = session.scalar(select(func.count()).select_from(GenesisAttempt)) or 0
                if metadata.status != "UNINITIALIZED" or identity_count or continuity_count or audit_count:
                    metadata.status = "RESTORE_QUARANTINED"
                    raise CoreError("GENESIS_NOT_INITIALIZED")

                metadata.trust_domain_id = request.trust_domain_id
                metadata.status = "UNINITIALIZED"
                metadata.active_storage_generation_id = storage_generation_id
                metadata.control_plane_generation_id = control_plane_generation_id
                metadata.genesis_fingerprint = fingerprint
                metadata.witness_set_version = "witness-set-v1"
                metadata.initial_owner_fingerprint = request.initial_owner_fingerprint
                metadata.current_owner_principal_id = request.actor_principal_id
                metadata.current_owner_key_fingerprint = request.initial_owner_fingerprint
                metadata.owner_version = 0

                genesis = GenesisRecord(
                    genesis_id=genesis_id,
                    trust_domain_id=request.trust_domain_id,
                    qingyu_identity_id=request.qingyu_identity_id,
                    continuity_id=request.continuity_id,
                    continuity_alias=request.continuity_alias,
                    genesis_version=request.genesis_version,
                    id_scheme="uuidv4",
                    initial_epoch=0,
                    manifest_hash=manifest_hash,
                    fingerprint=fingerprint,
                    genesis_nonce=request.genesis_nonce,
                    constitution_genesis_ref=request.constitution_genesis_ref,
                    constitution_genesis_hash=request.constitution_genesis_hash,
                    initial_owner_fingerprint=request.initial_owner_fingerprint,
                    witness_set_version="witness-set-v1",
                    witness_set_fingerprint=sha256_hex(
                        {"witness_set_version": "witness-set-v1", "threshold": 2}
                    ),
                    quorum_threshold=2,
                    protocol_version="control-plane-v1",
                    actor_principal_id=request.actor_principal_id,
                    governance_provenance=request.governance_provenance,
                )
                session.add(genesis)
                session.flush()
                session.add(
                    IdentityRegistry(
                        qingyu_identity_id=request.qingyu_identity_id,
                        genesis_id=genesis_id,
                    )
                )
                session.flush()
                session.add(
                    ContinuityRegistry(
                        continuity_id=request.continuity_id,
                        qingyu_identity_id=request.qingyu_identity_id,
                        continuity_alias=request.continuity_alias,
                    )
                )
                session.flush()
                session.add(
                    ContinuityAlias(
                        alias=request.continuity_alias,
                        continuity_id=request.continuity_id,
                        active=True,
                    )
                )
                session.add(
                    ControlPlaneState(
                        continuity_id=request.continuity_id,
                        current_epoch=0,
                        state_version=0,
                        owner_version=0,
                        owner_principal_id=request.actor_principal_id,
                        owner_key_fingerprint=request.initial_owner_fingerprint,
                        lease_id=None,
                        lease_generation=0,
                        status="READY",
                        active_storage_generation_id=storage_generation_id,
                        control_plane_generation_id=control_plane_generation_id,
                    )
                )
                genesis_audit = append_audit(
                    session,
                    trust_domain_id=request.trust_domain_id,
                    continuity_id=request.continuity_id,
                    continuity_epoch=0,
                    state_version=0,
                    operation_type="GENESIS",
                    actor_principal_id=request.actor_principal_id,
                    capability="core_governance",
                    request_id=request.genesis_request_id,
                    mutation_id=None,
                    result_code="COMMITTED",
                    payload={
                        "manifest_hash": manifest_hash,
                        "fingerprint": fingerprint,
                        "storage_generation_id": str(storage_generation_id),
                        "control_plane_generation_id": str(control_plane_generation_id),
                    },
                )
                genesis_audit_seq = genesis_audit.audit_seq
                genesis_audit_head_hash = genesis_audit.record_hash
                session.add(
                    GenesisAttempt(
                        request_id=request.genesis_request_id,
                        trust_domain_id=request.trust_domain_id,
                        manifest_hash=manifest_hash,
                        storage_generation_id=storage_generation_id,
                        state="CORE_COMMITTED",
                        local_commit_id=local_commit_id,
                        outcome_code="PENDING_AUTHORITY",
                    )
                )
                metadata.status = "READY"
        except IntegrityError as exc:
            raise CoreError("GENESIS_ALREADY_EXISTS") from exc
        finally:
            session.close()

        try:
            self.authority.initialize_domain(
                trust_domain_id=request.trust_domain_id,
                identity_id=request.qingyu_identity_id,
                continuity_id=request.continuity_id,
                storage_generation_id=storage_generation_id,
                control_plane_generation_id=control_plane_generation_id,
                owner_principal_id=request.actor_principal_id,
                owner_key_fingerprint=request.initial_owner_fingerprint,
                audit_high_water=genesis_audit_seq,
                audit_head_hash=genesis_audit_head_hash,
            )
            self.authority.record_genesis_core_commit(
                trust_domain_id=request.trust_domain_id,
                request_id=request.genesis_request_id,
                storage_generation_id=storage_generation_id,
                local_commit_id=local_commit_id,
            )
            anchor_hash = sha256_hex(
                {
                    **manifest,
                    "genesis_fingerprint": fingerprint,
                    "storage_generation_id": str(storage_generation_id),
                    "control_plane_generation_id": str(control_plane_generation_id),
                }
            )
            self.authority.publish_genesis_anchor(
                trust_domain_id=request.trust_domain_id,
                request_id=request.genesis_request_id,
                storage_generation_id=storage_generation_id,
                anchor_hash=anchor_hash,
            )
            self.authority.complete_genesis(
                trust_domain_id=request.trust_domain_id,
                request_id=request.genesis_request_id,
                storage_generation_id=storage_generation_id,
            )
        except CoreError:
            self._quarantine(reason="GENESIS_OUTCOME_UNKNOWN")
            raise

        session = self._session()
        try:
            with session.begin():
                attempt = session.get(GenesisAttempt, request.genesis_request_id)
                if attempt:
                    attempt.state = "COMMITTED"
                    attempt.outcome_code = "COMMITTED"
                metadata = session.execute(
                    select(CoreMetadata).where(CoreMetadata.id == 1)
                ).scalar_one()
                metadata.status = "READY"
        finally:
            session.close()
        return GenesisResult(
            genesis_id=genesis_id,
            qingyu_identity_id=request.qingyu_identity_id,
            continuity_id=request.continuity_id,
            continuity_alias=request.continuity_alias,
            continuity_epoch=0,
            status="COMMITTED",
            fingerprint=fingerprint,
            manifest_hash=manifest_hash,
            storage_generation_id=storage_generation_id,
        )

    def identity_status(self) -> IdentityStatus:
        session = self._session()
        try:
            metadata = session.execute(
                select(CoreMetadata).where(CoreMetadata.id == 1)
            ).scalar_one_or_none()
            genesis = session.scalar(select(GenesisRecord).limit(1))
            continuity = (
                session.scalar(select(ContinuityRegistry).limit(1)) if genesis else None
            )
            control = (
                session.get(ControlPlaneState, continuity.continuity_id)
                if continuity
                else None
            )
            return IdentityStatus(
                status=metadata.status if metadata else "SCHEMA_UNINITIALIZED",
                trust_domain_id=metadata.trust_domain_id if metadata else None,
                qingyu_identity_id=genesis.qingyu_identity_id if genesis else None,
                continuity_id=genesis.continuity_id if genesis else None,
                continuity_alias=continuity.continuity_alias if continuity else None,
                continuity_epoch=control.current_epoch if control else None,
                state_version=control.state_version if control else None,
                owner_version=control.owner_version if control else None,
                active_storage_generation_id=(
                    control.active_storage_generation_id if control else None
                ),
                audit_seq=metadata.audit_seq if metadata else 0,
                audit_head_hash=metadata.audit_head_hash if metadata else None,
            )
        finally:
            session.close()

    def resolve_alias(self, alias: str) -> uuid.UUID:
        session = self._session()
        try:
            row = session.get(ContinuityAlias, alias)
            if row is None or not row.active:
                raise CoreError("CONTINUITY_UNKNOWN")
            return row.continuity_id
        finally:
            session.close()

    def require_canonical_continuity(self, continuity: uuid.UUID | str) -> uuid.UUID:
        if isinstance(continuity, str) and continuity.strip().lower() == "qingyu-main":
            raise CoreError("CONTINUITY_ALIAS_NOT_CANONICAL_ID")
        try:
            parsed = continuity if isinstance(continuity, uuid.UUID) else uuid.UUID(str(continuity))
        except (ValueError, AttributeError, TypeError) as exc:
            raise CoreError("INVALID_CONTINUITY_ID_FORMAT") from exc
        if parsed.version != 4:
            raise CoreError("INVALID_CONTINUITY_ID_FORMAT")
        return parsed

    def acquire_owner_lease(self, continuity_id: uuid.UUID) -> uuid.UUID:
        continuity_id = self.require_canonical_continuity(continuity_id)
        session = self._session()
        audit_seq = 0
        audit_head_hash: str | None = None
        lease_id: uuid.UUID | None = None
        try:
            with session.begin():
                state = session.get(ControlPlaneState, continuity_id, with_for_update=True)
                if state is None:
                    raise CoreError("CONTINUITY_UNKNOWN")
                if state.status != "READY":
                    raise CoreError("RESTORE_FENCE_UNPROVEN")
                lease = self.authority.acquire_lease(
                    continuity_id=continuity_id,
                    principal_id=state.owner_principal_id,
                    capability="core_governance",
                    storage_generation_id=state.active_storage_generation_id,
                )
                state.lease_id = lease.lease_id
                state.lease_generation = lease.lease_generation
                audit = append_audit(
                    session,
                    trust_domain_id=session.get(CoreMetadata, 1).trust_domain_id,
                    continuity_id=continuity_id,
                    continuity_epoch=state.current_epoch,
                    state_version=state.state_version,
                    operation_type="LEASE_ACQUIRE",
                    actor_principal_id=state.owner_principal_id,
                    capability="core_governance",
                    request_id=uuid.uuid4().hex,
                    mutation_id=None,
                    result_code="COMMITTED",
                    payload={"lease_id": str(lease.lease_id), "lease_generation": lease.lease_generation},
                )
                audit_seq = audit.audit_seq
                audit_head_hash = audit.record_hash
                lease_id = lease.lease_id
            self.authority.sync_audit_checkpoint(
                continuity_id=continuity_id,
                audit_seq=audit_seq,
                audit_head_hash=audit_head_hash,
            )
            return lease_id
        finally:
            session.close()

    def transfer_owner(
        self,
        *,
        continuity_id: uuid.UUID,
        current_owner_principal_id: str,
        expected_owner_version: int,
        target_principal_id: str,
        target_key_fingerprint: str,
        request_id: str | None = None,
    ) -> IdentityStatus:
        continuity_id = self.require_canonical_continuity(continuity_id)
        request_id = request_id or uuid.uuid4().hex
        authority_state = self.authority.transfer_owner(
            continuity_id=continuity_id,
            expected_owner_version=expected_owner_version,
            current_owner_principal_id=current_owner_principal_id,
            target_principal_id=target_principal_id,
            target_key_fingerprint=target_key_fingerprint,
        )
        session = self._session()
        audit_seq = 0
        audit_head_hash: str | None = None
        try:
            with session.begin():
                state = session.get(ControlPlaneState, continuity_id, with_for_update=True)
                if state is None:
                    raise CoreError("CONTINUITY_UNKNOWN")
                state.current_epoch = authority_state.epoch
                state.state_version += 1
                state.owner_version = authority_state.owner_version
                state.owner_principal_id = target_principal_id
                state.owner_key_fingerprint = target_key_fingerprint
                state.lease_id = None
                metadata = session.get(CoreMetadata, 1)
                metadata.current_owner_principal_id = target_principal_id
                metadata.current_owner_key_fingerprint = target_key_fingerprint
                metadata.owner_version = state.owner_version
                audit = append_audit(
                    session,
                    trust_domain_id=metadata.trust_domain_id,
                    continuity_id=continuity_id,
                    continuity_epoch=state.current_epoch,
                    state_version=state.state_version,
                    operation_type="GOVERNANCE_OWNER_TRANSFER",
                    actor_principal_id=current_owner_principal_id,
                    capability="core_governance",
                    request_id=request_id,
                    mutation_id=None,
                    result_code="COMMITTED",
                    payload={
                        "previous_owner_principal_id": current_owner_principal_id,
                        "target_owner_principal_id": target_principal_id,
                        "owner_version": state.owner_version,
                    },
                )
                audit_seq = audit.audit_seq
                audit_head_hash = audit.record_hash
        except Exception:
            self._quarantine(reason="OWNER_TRANSFER_OUTCOME_UNKNOWN")
            raise
        finally:
            session.close()
        self.authority.sync_audit_checkpoint(
            continuity_id=continuity_id,
            audit_seq=audit_seq,
            audit_head_hash=audit_head_hash,
        )
        return self.identity_status()

    def governed_mutation(self, request: MutationRequest) -> MutationResult:
        continuity_id = self.require_canonical_continuity(request.continuity_id)
        session = self._session()
        permit: MutationPermit | None = None
        commit_attempted = False
        try:
            state = session.get(ControlPlaneState, continuity_id)
            if state is None:
                raise CoreError("CONTINUITY_UNKNOWN")
            if state.status != "READY":
                raise CoreError("RESTORE_FENCE_UNPROVEN")
            storage_generation_id = state.active_storage_generation_id
            expected_state_version = state.state_version
            # Read-only inspection opened an implicit transaction; the local
            # PREPARE transaction below must start from a clean boundary.
            session.rollback()
            permit = self.authority.prepare_mutation(
                continuity_id=continuity_id,
                epoch=request.continuity_epoch,
                lease_id=request.lease_id,
                mutation_id=request.mutation_id,
                payload=request.payload,
                actor_principal_id=request.actor_principal_id,
                capability=request.capability,
                storage_generation_id=storage_generation_id,
                expected_state_version=expected_state_version,
            )
            if permit.state.value == "COMMITTED":
                receipt = session.get(MutationReceipt, request.mutation_id)
                if receipt is None:
                    raise CoreError("MUTATION_OUTCOME_UNKNOWN")
                return MutationResult(
                    mutation_id=receipt.mutation_id,
                    status=receipt.status,
                    continuity_epoch=receipt.continuity_epoch,
                    state_version=receipt.assigned_state_version,
                    audit_seq=receipt.audit_seq,
                    audit_head_hash=session.get(CoreMetadata, 1).audit_head_hash,
                    local_commit_id=receipt.local_commit_id,
                )
            with session.begin():
                state = session.get(ControlPlaneState, continuity_id, with_for_update=True)
                if state is None:
                    raise CoreError("CONTINUITY_UNKNOWN")
                if state.current_epoch != permit.epoch:
                    raise CoreError("EPOCH_STALE")
                audit = append_audit(
                    session,
                    trust_domain_id=session.get(CoreMetadata, 1).trust_domain_id,
                    continuity_id=continuity_id,
                    continuity_epoch=permit.epoch,
                    state_version=permit.assigned_state_version,
                    operation_type="GOVERNED_MUTATION",
                    actor_principal_id=request.actor_principal_id,
                    capability=request.capability,
                    request_id=request.mutation_id,
                    mutation_id=request.mutation_id,
                    result_code="COMMITTED",
                    payload={"payload_hash": permit.payload_hash},
                )
                local_commit_id = uuid.uuid4().hex
                receipt = MutationReceipt(
                    mutation_id=request.mutation_id,
                    continuity_id=continuity_id,
                    continuity_epoch=permit.epoch,
                    storage_generation_id=permit.storage_generation_id,
                    payload_hash=permit.payload_hash,
                    expected_state_version=permit.expected_state_version,
                    assigned_state_version=permit.assigned_state_version,
                    audit_seq=audit.audit_seq,
                    local_commit_id=local_commit_id,
                    status="PREPARED",
                )
                session.add(receipt)
                audit_head_hash = audit.record_hash
            commit_attempted = True
            committed = self.authority.commit_mutation(
                mutation_id=request.mutation_id,
                local_commit_id=local_commit_id,
                audit_head_hash=audit_head_hash,
                audit_seq=audit.audit_seq,
            )
            with session.begin():
                state = session.get(ControlPlaneState, continuity_id, with_for_update=True)
                receipt = session.get(MutationReceipt, request.mutation_id)
                state.state_version = permit.assigned_state_version
                metadata = session.get(CoreMetadata, 1, with_for_update=True)
                metadata.current_state_version = permit.assigned_state_version
                receipt.status = committed.state.value
            return MutationResult(
                mutation_id=request.mutation_id,
                status=committed.state.value,
                continuity_epoch=permit.epoch,
                state_version=permit.assigned_state_version,
                audit_seq=receipt.audit_seq,
                audit_head_hash=audit_head_hash,
                local_commit_id=local_commit_id,
            )
        except CoreError:
            if permit is not None:
                try:
                    self.authority.abort_mutation(request.mutation_id)
                except CoreError:
                    pass
            if commit_attempted:
                session.rollback()
                cleanup = self._session()
                try:
                    with cleanup.begin():
                        metadata = cleanup.get(CoreMetadata, 1, with_for_update=True)
                        receipt = cleanup.get(MutationReceipt, request.mutation_id)
                        if receipt is not None and receipt.status == "PREPARED":
                            receipt.status = "ABORTED"
                        if metadata is not None:
                            metadata.status = "RESTORE_QUARANTINED"
                        state = cleanup.get(ControlPlaneState, continuity_id, with_for_update=True)
                        if state is not None:
                            state.status = "RESTORE_QUARANTINED"
                finally:
                    cleanup.close()
            raise
        finally:
            session.close()

    def verify_restore(self, request: RestoreRequest) -> RestoreVerification:
        session = self._session()
        audit_seq = 0
        audit_head_hash: str | None = None
        try:
            genesis = session.scalar(select(GenesisRecord).limit(1))
            metadata = session.get(CoreMetadata, 1)
            if genesis is None or metadata is None:
                raise CoreError("GENESIS_NOT_INITIALIZED")
            manifest = request.manifest
            if (
                genesis.trust_domain_id != manifest.trust_domain_id
                or genesis.qingyu_identity_id != manifest.qingyu_identity_id
                or genesis.continuity_id != manifest.continuity_id
                or genesis.fingerprint != manifest.genesis_fingerprint
                or genesis.initial_owner_fingerprint != manifest.initial_owner_fingerprint
                or genesis.manifest_hash != manifest.manifest_hash
                or genesis.witness_set_version != manifest.witness_set_version
                or metadata.active_storage_generation_id != manifest.storage_generation_id
                or metadata.control_plane_generation_id != manifest.control_plane_generation_id
            ):
                raise CoreError("RESTORE_IDENTITY_MISMATCH")
            if (
                genesis.initial_owner_fingerprint != manifest.initial_owner_fingerprint
            ):
                raise CoreError("RESTORE_INITIAL_OWNER_MISMATCH")
            audit = verify_audit_chain(session)
            checkpoint = self.authority.export_checkpoint(manifest.continuity_id)
            if (
                checkpoint["trust_domain_id"] != str(manifest.trust_domain_id)
                or checkpoint["continuity_id"] != str(manifest.continuity_id)
                or checkpoint["storage_generation_id"] != str(manifest.storage_generation_id)
                or checkpoint["control_plane_generation_id"] != str(manifest.control_plane_generation_id)
            ):
                raise CoreError("RESTORE_STATE_GAP")
            if checkpoint["audit_high_water"] != manifest.audit_high_water:
                raise CoreError("RESTORE_STATE_GAP")
            if checkpoint["audit_head_hash"] != manifest.audit_head_hash:
                raise CoreError("AUDIT_HIGH_WATER_UNPROVEN")
            state = session.get(ControlPlaneState, manifest.continuity_id, with_for_update=True)
            state.status = "RESTORE_QUARANTINED"
            state.lease_id = None
            metadata.status = "RESTORE_QUARANTINED"
            session.commit()
            self.authority.quarantine_recovery(manifest.continuity_id)
            return RestoreVerification(
                same_identity=True,
                read_only=True,
                reason="RESTORE_QUARANTINED_UNTIL_AUTHORITY_ACTIVATION",
                continuity_epoch=checkpoint["epoch"],
                audit=audit,
            )
        finally:
            session.close()

    def activate_restore(self, request: RestoreRequest) -> RestoreVerification:
        existing_session = self._session()
        try:
            existing = existing_session.get(RestoreRecord, request.request_id)
            if existing is not None:
                state = existing_session.get(ControlPlaneState, existing.continuity_id)
                if (
                    existing.manifest_hash != request.manifest.manifest_hash
                    or existing.trust_domain_id != request.manifest.trust_domain_id
                    or existing.continuity_id != request.manifest.continuity_id
                    or request.target_storage_generation_id != existing.target_storage_generation_id
                    or state is None
                    or state.active_storage_generation_id != existing.target_storage_generation_id
                    or state.control_plane_generation_id != request.manifest.control_plane_generation_id
                    or state.owner_principal_id != request.current_owner_principal_id
                    or request.current_owner_record_hash
                    != sha256_hex(
                        {
                            "owner_version": state.owner_version,
                            "owner_principal_id": state.owner_principal_id,
                            "owner_key_fingerprint": state.owner_key_fingerprint,
                        }
                    )
                ):
                    raise CoreError("RESTORE_REQUEST_CONFLICT")
                if existing.status == "ACTIVE" and state is not None:
                    return RestoreVerification(
                        same_identity=True,
                        read_only=False,
                        reason="RESTORE_ACTIVATED",
                        continuity_epoch=state.current_epoch,
                        audit=None,
                    )
        finally:
            existing_session.close()
        manifest = request.manifest
        claim = self.authority.recovery_status(request.request_id)
        if claim is not None and claim.get("status") == "ACTIVE":
            if (
                claim.get("restore_manifest_hash") != manifest.manifest_hash
                or claim.get("continuity_id") != str(manifest.continuity_id)
                or claim.get("target_storage_generation_id") != str(request.target_storage_generation_id)
            ):
                raise CoreError("RESTORE_REQUEST_CONFLICT")
            check = self._session()
            try:
                genesis = check.scalar(select(GenesisRecord).limit(1))
                if genesis is None or genesis.trust_domain_id != manifest.trust_domain_id or genesis.qingyu_identity_id != manifest.qingyu_identity_id or genesis.continuity_id != manifest.continuity_id or genesis.fingerprint != manifest.genesis_fingerprint or genesis.manifest_hash != manifest.manifest_hash:
                    raise CoreError("RESTORE_IDENTITY_MISMATCH")
                audit = verify_audit_chain(check)
                verification = RestoreVerification(
                    same_identity=True,
                    read_only=True,
                    reason="RESTORE_RECONCILIATION",
                    continuity_epoch=int(claim["target_epoch"]),
                    audit=audit,
                )
            finally:
                check.close()
        else:
            verification = self.verify_restore(request)
            claim = self.authority.claim_recovery(
                request_id=request.request_id,
                trust_domain_id=manifest.trust_domain_id,
                continuity_id=manifest.continuity_id,
                current_owner_principal_id=request.current_owner_principal_id,
                current_owner_record_hash=request.current_owner_record_hash,
                target_storage_generation_id=request.target_storage_generation_id,
                restore_manifest_hash=manifest.manifest_hash,
            )
            claim = self.authority.activate_recovery(request.request_id)
        session = self._session()
        try:
            with session.begin():
                state = session.get(ControlPlaneState, manifest.continuity_id, with_for_update=True)
                metadata = session.get(CoreMetadata, 1, with_for_update=True)
                state.current_epoch = int(claim["target_epoch"])
                state.state_version += 1
                state.active_storage_generation_id = uuid.UUID(claim["target_storage_generation_id"])
                state.lease_id = None
                state.status = "READY"
                metadata.status = "READY"
                metadata.active_storage_generation_id = state.active_storage_generation_id
                audit = append_audit(
                    session,
                    trust_domain_id=manifest.trust_domain_id,
                    continuity_id=manifest.continuity_id,
                    continuity_epoch=state.current_epoch,
                    state_version=state.state_version,
                    operation_type="CONTINUITY_REBASED",
                    actor_principal_id=request.current_owner_principal_id,
                    capability="core_governance",
                    request_id=request.request_id,
                    mutation_id=None,
                    result_code="COMMITTED",
                    payload={
                        "previous_epoch": claim["previous_epoch"],
                        "target_epoch": claim["target_epoch"],
                        "target_storage_generation_id": claim["target_storage_generation_id"],
                    },
                )
                audit_seq = audit.audit_seq
                audit_head_hash = audit.record_hash
                session.add(
                    RestoreRecord(
                        request_id=request.request_id,
                        trust_domain_id=manifest.trust_domain_id,
                        continuity_id=manifest.continuity_id,
                        manifest_hash=manifest.manifest_hash,
                        target_storage_generation_id=state.active_storage_generation_id,
                        status="ACTIVE",
                        reason_code=None,
                    )
                )
        except Exception:
            self._quarantine(reason="RESTORE_FENCE_UNPROVEN")
            raise
        finally:
            session.close()
        self.authority.sync_audit_checkpoint(
            continuity_id=manifest.continuity_id,
            audit_seq=audit_seq,
            audit_head_hash=audit_head_hash,
        )
        return RestoreVerification(
            same_identity=verification.same_identity,
            read_only=False,
            reason="RESTORE_ACTIVATED",
            continuity_epoch=int(claim["target_epoch"]),
            audit=None,
        )
