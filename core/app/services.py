from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from .audit import append_audit, verify_audit_chain, verify_audit_row
from .canonical import sha256_hex, uuid4_opaque
from .control_plane.authority import (
    InMemoryControlPlane,
    MutationPermit,
    UnavailableControlPlane,
)
from .errors import CoreError
from .models import (
    AuditLedger,
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
    CoreReadModel,
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
    def _manifest(request: GenesisRequest | GenesisRecord) -> dict[str, object]:
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
                for state in session.scalars(select(ControlPlaneState).with_for_update()):
                    state.status = "RESTORE_QUARANTINED"
                    state.lease_id = None
        finally:
            session.close()

    def _local_projection(
        self, session: Session, continuity_id: uuid.UUID, *, require_ready: bool = True,
    ) -> tuple[CoreMetadata, ControlPlaneState, GenesisRecord]:
        """Validate cloneable projections; none of these rows grants authority.

        Reload locked rows at every boundary: expire_on_commit=False must not
        let a pre-PREPARE identity-map value hide a newly persisted quarantine.
        """
        metadata = session.get(CoreMetadata, 1, with_for_update=True, populate_existing=True)
        state = session.get(ControlPlaneState, continuity_id, with_for_update=True, populate_existing=True)
        genesis = session.scalar(select(GenesisRecord).where(
            GenesisRecord.continuity_id == continuity_id,
        ).execution_options(populate_existing=True))
        if metadata is None or state is None or genesis is None:
            raise CoreError("GENESIS_NOT_INITIALIZED")
        if require_ready and (metadata.status != "READY" or state.status != "READY"):
            raise CoreError("RESTORE_FENCE_UNPROVEN")
        identity = session.get(IdentityRegistry, genesis.qingyu_identity_id, populate_existing=True)
        continuity = session.get(ContinuityRegistry, continuity_id, populate_existing=True)
        if (
            identity is None or identity.genesis_id != genesis.genesis_id or identity.retired_at is not None
            or continuity is None or continuity.qingyu_identity_id != genesis.qingyu_identity_id
            or continuity.retired_at is not None
            or metadata.trust_domain_id != genesis.trust_domain_id
            or metadata.genesis_fingerprint != genesis.fingerprint
            or metadata.initial_owner_fingerprint != genesis.initial_owner_fingerprint
            or metadata.witness_set_version != genesis.witness_set_version
            or genesis.protocol_version != "control-plane-v1"
            or genesis.id_scheme != "uuidv4"
            or genesis.initial_epoch != 0 or genesis.quorum_threshold != 2
            or genesis.witness_set_fingerprint != sha256_hex({
                "witness_set_version": genesis.witness_set_version, "threshold": genesis.quorum_threshold,
            })
            or sha256_hex(self._manifest(genesis)) != genesis.manifest_hash
        ):
            raise CoreError("RESTORE_IDENTITY_MISMATCH")
        if (
            metadata.active_storage_generation_id != state.active_storage_generation_id
            or metadata.control_plane_generation_id != state.control_plane_generation_id
            or metadata.current_state_version != state.state_version
            or metadata.owner_version != state.owner_version
            or metadata.current_owner_principal_id != state.owner_principal_id
            or metadata.current_owner_key_fingerprint != state.owner_key_fingerprint
        ):
            raise CoreError("RESTORE_STATE_GAP")
        reservation = self.authority.genesis_status(genesis.trust_domain_id)
        attempt = session.get(GenesisAttempt, reservation.request_id, populate_existing=True) if reservation else None
        if (
            reservation is None or reservation.state.value != "COMMITTED"
            or reservation.manifest_hash != genesis.manifest_hash
            or not reservation.anchor_hash or not reservation.local_commit_id
            or attempt is None or attempt.state != "COMMITTED" or attempt.outcome_code != "COMMITTED"
            or attempt.trust_domain_id != genesis.trust_domain_id
            or attempt.manifest_hash != genesis.manifest_hash
            or attempt.storage_generation_id != reservation.claimed_storage_generation_id
            or attempt.local_commit_id != reservation.local_commit_id
            or reservation.anchor_hash != sha256_hex({
                **self._manifest(genesis), "genesis_fingerprint": genesis.fingerprint,
                "storage_generation_id": str(attempt.storage_generation_id),
                "control_plane_generation_id": str(state.control_plane_generation_id),
            })
        ):
            raise CoreError("GENESIS_OUTCOME_UNKNOWN")
        return metadata, state, genesis

    def _checkpoint_matches(
        self, session: Session, metadata: CoreMetadata, state: ControlPlaneState,
        genesis: GenesisRecord, checkpoint: dict, *, state_version: int | None = None,
        require_active: bool = True,
    ) -> dict[str, object]:
        if (
            checkpoint.get("trust_domain_id") != str(genesis.trust_domain_id)
            or checkpoint.get("identity_id") != str(genesis.qingyu_identity_id)
            or checkpoint.get("continuity_id") != str(genesis.continuity_id)
            or checkpoint.get("initial_owner_fingerprint") != genesis.initial_owner_fingerprint
            or checkpoint.get("witness_set_version") != genesis.witness_set_version
        ):
            raise CoreError("RESTORE_IDENTITY_MISMATCH")
        if require_active and checkpoint.get("recovery_state") != "ACTIVE":
            raise CoreError("RESTORE_FENCE_UNPROVEN")
        expected_version = state.state_version if state_version is None else state_version
        if (
            checkpoint.get("storage_generation_id") != str(state.active_storage_generation_id)
            or checkpoint.get("control_plane_generation_id") != str(state.control_plane_generation_id)
            or checkpoint.get("epoch") != state.current_epoch
            or checkpoint.get("state_version") != expected_version
            or checkpoint.get("owner_version") != state.owner_version
            or checkpoint.get("owner_principal_id") != state.owner_principal_id
            or checkpoint.get("owner_key_fingerprint") != state.owner_key_fingerprint
        ):
            raise CoreError("RESTORE_STATE_GAP")
        audit = verify_audit_chain(session, refresh=True)
        if audit["audit_seq"] != checkpoint.get("audit_high_water"):
            raise CoreError("RESTORE_STATE_GAP")
        if audit["audit_head_hash"] != checkpoint.get("audit_head_hash"):
            raise CoreError("AUDIT_HIGH_WATER_UNPROVEN")
        tip = verify_audit_row(session.get(
            AuditLedger, metadata.audit_seq, with_for_update=True, populate_existing=True,
        ))
        if (
            tip.trust_domain_id != genesis.trust_domain_id or tip.continuity_id != genesis.continuity_id
            or tip.continuity_epoch != state.current_epoch or tip.state_version != expected_version
        ):
            raise CoreError("RESTORE_STATE_GAP")
        return audit

    def _require_write_eligibility(
        self, session: Session, continuity_id: uuid.UUID, *, committed_permit: MutationPermit | None = None,
    ) -> tuple[CoreMetadata, ControlPlaneState, GenesisRecord]:
        projection = self._local_projection(session, continuity_id)
        metadata, state, genesis = projection
        checkpoint = self.authority.export_checkpoint(continuity_id)
        self._checkpoint_matches(
            session, metadata, state, genesis, checkpoint,
            state_version=committed_permit.assigned_state_version if committed_permit else None,
        )
        return projection

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
                try:
                    attempt = precheck.get(GenesisAttempt, request.genesis_request_id, with_for_update=True)
                    if attempt is not None and attempt.state == "CORE_COMMITTED" and attempt.outcome_code == "PENDING_AUTHORITY":
                        # Reconcile only the exact unfinished bootstrap. A
                        # terminal local receipt never clears later quarantine.
                        attempt.state = "COMMITTED"
                        attempt.outcome_code = "COMMITTED"
                        precheck.flush()
                        metadata, state, genesis = self._local_projection(precheck, existing.continuity_id, require_ready=False)
                        if (
                            metadata.audit_seq != 1 or state.state_version != 0 or state.current_epoch != 0
                            or state.active_storage_generation_id != attempt.storage_generation_id
                        ):
                            raise CoreError("GENESIS_OUTCOME_UNKNOWN")
                        self._checkpoint_matches(
                            precheck, metadata, state, genesis, self.authority.export_checkpoint(existing.continuity_id),
                        )
                        metadata.status = "READY"
                        state.status = "READY"
                        precheck.commit()
                    else:
                        metadata, _, _ = self._require_write_eligibility(precheck, existing.continuity_id)
                except CoreError:
                    precheck.rollback()
                    self._quarantine(reason="GENESIS_OUTCOME_UNKNOWN")
                    raise
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
                        metadata, _, _ = self._require_write_eligibility(session, existing.continuity_id)
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
                        status="RESTORE_QUARANTINED",
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
                metadata.status = "RESTORE_QUARANTINED"
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
        except Exception:
            self._quarantine(reason="GENESIS_OUTCOME_UNKNOWN")
            raise

        session = self._session()
        try:
            with session.begin():
                attempt = session.get(GenesisAttempt, request.genesis_request_id)
                if attempt:
                    attempt.state = "COMMITTED"
                    attempt.outcome_code = "COMMITTED"
                session.flush()
                metadata, state, genesis = self._local_projection(session, request.continuity_id, require_ready=False)
                self._checkpoint_matches(
                    session, metadata, state, genesis, self.authority.export_checkpoint(request.continuity_id),
                )
                metadata.status = "READY"
                state.status = "READY"
        except Exception:
            session.rollback()
            self._quarantine(reason="GENESIS_OUTCOME_UNKNOWN")
            raise
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

    def core_read_model(self) -> CoreReadModel:
        session = self._session()
        try:
            continuity = session.scalar(select(ContinuityRegistry).limit(1))
            if continuity is None:
                raise CoreError("GENESIS_NOT_INITIALIZED")
            metadata, state, genesis = self._local_projection(session, continuity.continuity_id)
            checkpoint = self.authority.export_checkpoint(continuity.continuity_id)
            audit = self._checkpoint_matches(session, metadata, state, genesis, checkpoint)
            payload = {
                "schema_version": "core-read-model-v1",
                "status": metadata.status,
                "identity_reference": {
                    "trust_domain_id": str(genesis.trust_domain_id),
                    "qingyu_identity_id": str(genesis.qingyu_identity_id),
                    "continuity_id": str(genesis.continuity_id),
                    "continuity_alias": genesis.continuity_alias,
                    "genesis_id": str(genesis.genesis_id),
                    "genesis_fingerprint": genesis.fingerprint,
                    "manifest_hash": genesis.manifest_hash,
                },
                "generation": {
                    "storage_generation_id": str(state.active_storage_generation_id),
                    "control_plane_generation_id": str(state.control_plane_generation_id),
                    "continuity_epoch": state.current_epoch,
                    "state_version": state.state_version,
                    "owner_version": state.owner_version,
                },
                "governed_state": {
                    "status": state.status,
                    "owner_principal_id": state.owner_principal_id,
                    "owner_key_fingerprint": state.owner_key_fingerprint,
                    "lease_generation": state.lease_generation,
                    "audit_high_water": audit["audit_seq"],
                    "audit_head_hash": audit["audit_head_hash"],
                    "recovery_state": checkpoint["recovery_state"],
                },
                "lineage": {
                    "initial_epoch": genesis.initial_epoch,
                    "witness_set_version": genesis.witness_set_version,
                    "witness_set_fingerprint": genesis.witness_set_fingerprint,
                    "protocol_version": genesis.protocol_version,
                    "constitution_genesis_ref": genesis.constitution_genesis_ref,
                    "constitution_genesis_hash": genesis.constitution_genesis_hash,
                },
                "provenance": {
                    "source": "core-foundation-service",
                    "checkpoint": checkpoint,
                    "checkpoint_hash": sha256_hex(checkpoint),
                    "audit": audit,
                    "governance_provenance": genesis.governance_provenance,
                },
                "read_only": True,
            }
            return CoreReadModel(**payload, read_model_hash=sha256_hex(payload))
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
                metadata, state, _ = self._require_write_eligibility(session, continuity_id)
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
        except Exception:
            session.rollback()
            self._quarantine(reason="LEASE_OUTCOME_UNKNOWN")
            raise
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
        session = self._session()
        audit_seq = 0
        audit_head_hash: str | None = None
        try:
            with session.begin():
                metadata, state, _ = self._require_write_eligibility(session, continuity_id)
                authority_state = self.authority.transfer_owner(
                    continuity_id=continuity_id,
                    expected_owner_version=expected_owner_version,
                    current_owner_principal_id=current_owner_principal_id,
                    target_principal_id=target_principal_id,
                    target_key_fingerprint=target_key_fingerprint,
                )
                state.current_epoch = authority_state.epoch
                state.state_version = authority_state.state_version
                state.owner_version = authority_state.owner_version
                state.owner_principal_id = target_principal_id
                state.owner_key_fingerprint = target_key_fingerprint
                state.lease_id = None
                metadata = session.get(CoreMetadata, 1)
                metadata.current_owner_principal_id = target_principal_id
                metadata.current_owner_key_fingerprint = target_key_fingerprint
                metadata.owner_version = state.owner_version
                metadata.current_state_version = state.state_version
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
            self.authority.sync_audit_checkpoint(
                continuity_id=continuity_id, audit_seq=audit_seq, audit_head_hash=audit_head_hash,
            )
        except Exception:
            session.rollback()
            self._quarantine(reason="OWNER_TRANSFER_OUTCOME_UNKNOWN")
            raise
        finally:
            session.close()
        return self.identity_status()

    def _committed_mutation_receipt(
        self, session: Session, request: MutationRequest, permit: MutationPermit,
        trust_domain_id: uuid.UUID, *, local_status: str,
    ) -> tuple[MutationReceipt, AuditLedger]:
        """Validate fresh local evidence for both first completion and replay."""
        receipt = session.get(
            MutationReceipt, request.mutation_id, with_for_update=True, populate_existing=True,
        )
        if (
            receipt is None or receipt.status != local_status or permit.state.value != "COMMITTED"
            or receipt.mutation_id != permit.mutation_id or permit.mutation_id != request.mutation_id
            or receipt.continuity_id != permit.continuity_id or permit.continuity_id != request.continuity_id
            or receipt.continuity_epoch != permit.epoch or permit.epoch != request.continuity_epoch
            or permit.lease_id != request.lease_id
            or permit.actor_principal_id != request.actor_principal_id or permit.capability != request.capability
            or receipt.storage_generation_id != permit.storage_generation_id
            or receipt.payload_hash != permit.payload_hash or permit.payload_hash != sha256_hex(request.payload)
            or receipt.expected_state_version != permit.expected_state_version
            or receipt.assigned_state_version != permit.assigned_state_version
            or receipt.local_commit_id != permit.local_commit_id
            or receipt.audit_seq != permit.audit_seq
        ):
            raise CoreError("MUTATION_OUTCOME_UNKNOWN")
        audit_row = verify_audit_row(session.get(
            AuditLedger, receipt.audit_seq, with_for_update=True, populate_existing=True,
        ))
        if (
            audit_row.record_hash != permit.audit_head_hash
            or audit_row.trust_domain_id != trust_domain_id
            or audit_row.mutation_id != receipt.mutation_id or audit_row.request_id != receipt.mutation_id
            or audit_row.continuity_id != receipt.continuity_id
            or audit_row.continuity_epoch != receipt.continuity_epoch
            or audit_row.state_version != receipt.assigned_state_version
            or audit_row.operation_type != "GOVERNED_MUTATION" or audit_row.result_code != "COMMITTED"
            or audit_row.actor_principal_id != request.actor_principal_id
            or audit_row.capability != request.capability
            or audit_row.payload_hash != sha256_hex({"payload_hash": permit.payload_hash})
        ):
            raise CoreError("MUTATION_OUTCOME_UNKNOWN")
        return receipt, audit_row

    def governed_mutation(self, request: MutationRequest) -> MutationResult:
        continuity_id = self.require_canonical_continuity(request.continuity_id)
        session = self._session()
        permit: MutationPermit | None = None
        local_prepared = False
        try:
            _, state, _ = self._require_write_eligibility(session, continuity_id)
            storage_generation_id = state.active_storage_generation_id
            expected_state_version = state.state_version
            previous_receipt = session.get(MutationReceipt, request.mutation_id)
            local_commit_id = previous_receipt.local_commit_id if previous_receipt else uuid.uuid4().hex
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
                local_commit_id=local_commit_id,
            )
            if permit.state.value == "COMMITTED":
                metadata, _, _ = self._require_write_eligibility(session, continuity_id)
                receipt, audit_row = self._committed_mutation_receipt(
                    session, request, permit, metadata.trust_domain_id, local_status="COMMITTED",
                )
                return MutationResult(
                    mutation_id=receipt.mutation_id,
                    status=receipt.status,
                    continuity_epoch=receipt.continuity_epoch,
                    state_version=receipt.assigned_state_version,
                    audit_seq=receipt.audit_seq,
                    audit_head_hash=audit_row.record_hash,
                    local_commit_id=receipt.local_commit_id,
                )
            with session.begin():
                _, state, _ = self._require_write_eligibility(session, continuity_id)
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
            local_prepared = True
            with session.begin():
                self._local_projection(session, continuity_id)
                committed = self.authority.commit_mutation(
                    mutation_id=request.mutation_id,
                    local_commit_id=local_commit_id,
                    audit_head_hash=audit_head_hash,
                    audit_seq=audit.audit_seq,
                    permit=permit,
                    payload=request.payload,
                )
                metadata, state, _ = self._require_write_eligibility(
                    session, continuity_id, committed_permit=committed,
                )
                receipt, audit_row = self._committed_mutation_receipt(
                    session, request, committed, metadata.trust_domain_id, local_status="PREPARED",
                )
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
                audit_head_hash=audit_row.record_hash,
                local_commit_id=local_commit_id,
            )
        except Exception:
            session.rollback()
            if permit is not None:
                try:
                    self.authority.abort_mutation(request.mutation_id)
                except CoreError:
                    pass
            if local_prepared:
                # A lost response may already be committed externally. Keep
                # the pending receipt unchanged as reconciliation evidence.
                self._quarantine(reason="MUTATION_OUTCOME_UNKNOWN")
            raise
        finally:
            session.close()

    @staticmethod
    def _manifest_checkpoint_matches(request: RestoreRequest, genesis: GenesisRecord, checkpoint: dict) -> None:
        manifest = request.manifest
        if (
            genesis.trust_domain_id != manifest.trust_domain_id
            or genesis.qingyu_identity_id != manifest.qingyu_identity_id
            or genesis.continuity_id != manifest.continuity_id
            or genesis.fingerprint != manifest.genesis_fingerprint
            or genesis.initial_owner_fingerprint != manifest.initial_owner_fingerprint
            or genesis.manifest_hash != manifest.manifest_hash
            or genesis.witness_set_version != manifest.witness_set_version
            or checkpoint.get("trust_domain_id") != str(manifest.trust_domain_id)
            or checkpoint.get("identity_id") != str(manifest.qingyu_identity_id)
            or checkpoint.get("continuity_id") != str(manifest.continuity_id)
            or checkpoint.get("initial_owner_fingerprint") != manifest.initial_owner_fingerprint
            or checkpoint.get("witness_set_version") != manifest.witness_set_version
        ):
            raise CoreError("RESTORE_IDENTITY_MISMATCH")
        if (
            checkpoint.get("storage_generation_id") != str(manifest.storage_generation_id)
            or checkpoint.get("control_plane_generation_id") != str(manifest.control_plane_generation_id)
            or checkpoint.get("audit_high_water") != manifest.audit_high_water
        ):
            raise CoreError("RESTORE_STATE_GAP")
        if checkpoint.get("audit_head_hash") != manifest.audit_head_hash:
            raise CoreError("AUDIT_HIGH_WATER_UNPROVEN")
        owner_hash = sha256_hex({
            "owner_version": checkpoint["owner_version"],
            "owner_principal_id": checkpoint["owner_principal_id"],
            "owner_key_fingerprint": checkpoint["owner_key_fingerprint"],
        })
        if request.current_owner_principal_id != checkpoint["owner_principal_id"] or request.current_owner_record_hash != owner_hash:
            raise CoreError("RESTORE_OWNER_UNPROVEN")

    def _verify_restore_source(self, session: Session, request: RestoreRequest, checkpoint: dict) -> dict[str, object]:
        metadata, state, genesis = self._local_projection(session, request.manifest.continuity_id, require_ready=False)
        self._manifest_checkpoint_matches(request, genesis, checkpoint)
        # The hash-bound audit tip supplies the version absent from the legacy
        # manifest model. Local chain consistency alone never proves currency.
        return self._checkpoint_matches(session, metadata, state, genesis, checkpoint, require_active=False)

    def verify_restore(self, request: RestoreRequest) -> RestoreVerification:
        self._quarantine(reason="RESTORE_VERIFICATION")
        session = self._session()
        try:
            checkpoint = self.authority.export_checkpoint(request.manifest.continuity_id)
            audit = self._verify_restore_source(session, request, checkpoint)
            self.authority.quarantine_recovery(request.manifest.continuity_id)
            return RestoreVerification(
                same_identity=True, read_only=True,
                reason="RESTORE_QUARANTINED_UNTIL_AUTHORITY_ACTIVATION",
                continuity_epoch=checkpoint["epoch"], audit=audit,
            )
        finally:
            session.close()

    @staticmethod
    def _restore_payload(request: RestoreRequest, claim: dict) -> dict:
        return {
            "previous_epoch": claim["previous_epoch"],
            "target_epoch": claim["target_epoch"],
            "target_storage_generation_id": claim["target_storage_generation_id"],
            "source_manifest_hash": sha256_hex(request.manifest.model_dump(mode="json")),
        }

    def _restore_record_audit(
        self, session: Session, request: RestoreRequest, claim: dict, *, local_status: str,
    ) -> tuple[RestoreRecord, AuditLedger]:
        record = session.get(
            RestoreRecord, request.request_id, with_for_update=True, populate_existing=True,
        )
        if (
            record is None or record.status != local_status
            or record.trust_domain_id != request.manifest.trust_domain_id
            or record.continuity_id != request.manifest.continuity_id
            or record.manifest_hash != request.manifest.manifest_hash
            or record.target_storage_generation_id != request.target_storage_generation_id
        ):
            raise CoreError("RESTORE_REQUEST_CONFLICT")
        row = verify_audit_row(session.scalar(select(AuditLedger).where(
            AuditLedger.request_id == request.request_id,
            AuditLedger.operation_type == "CONTINUITY_REBASED",
        ).with_for_update().execution_options(populate_existing=True)))
        if (
            row.trust_domain_id != record.trust_domain_id or row.continuity_id != record.continuity_id
            or row.continuity_epoch != claim["target_epoch"]
            or row.state_version != claim["target_state_version"]
            or row.audit_seq != claim["source_checkpoint"]["audit_high_water"] + 1
            or row.previous_record_hash != claim["source_checkpoint"]["audit_head_hash"]
            or row.actor_principal_id != request.current_owner_principal_id
            or row.capability != "core_governance" or row.mutation_id is not None
            or row.payload_hash != sha256_hex(self._restore_payload(request, claim))
            or row.result_code != "COMMITTED"
        ):
            raise CoreError("RESTORE_REQUEST_CONFLICT")
        return record, row

    def activate_restore(self, request: RestoreRequest) -> RestoreVerification:
        manifest = request.manifest
        claim = self.authority.recovery_status(request.request_id)
        if claim is None:
            self.verify_restore(request)
            claim = self.authority.claim_recovery(
                request_id=request.request_id,
                trust_domain_id=manifest.trust_domain_id,
                continuity_id=manifest.continuity_id,
                current_owner_principal_id=request.current_owner_principal_id,
                current_owner_record_hash=request.current_owner_record_hash,
                target_storage_generation_id=request.target_storage_generation_id,
                restore_manifest_hash=manifest.manifest_hash,
            )
        if (
            claim.get("trust_domain_id") != str(manifest.trust_domain_id)
            or claim.get("continuity_id") != str(manifest.continuity_id)
            or claim.get("restore_manifest_hash") != manifest.manifest_hash
            or claim.get("target_storage_generation_id") != str(request.target_storage_generation_id)
        ):
            raise CoreError("RESTORE_REQUEST_CONFLICT")

        session = self._session()
        try:
            genesis = session.scalar(select(GenesisRecord).where(GenesisRecord.continuity_id == manifest.continuity_id))
            if genesis is None:
                raise CoreError("GENESIS_NOT_INITIALIZED")
            self._manifest_checkpoint_matches(request, genesis, claim["source_checkpoint"])
            existing = session.get(RestoreRecord, request.request_id)
            if existing is not None and existing.status == "ACTIVE":
                _, state, _ = self._require_write_eligibility(session, manifest.continuity_id)
                existing, row = self._restore_record_audit(session, request, claim, local_status="ACTIVE")
                if claim["status"] != "ACTIVE" or claim.get("audit_seq") != row.audit_seq or claim.get("audit_head_hash") != row.record_hash:
                    raise CoreError("RESTORE_FENCE_UNPROVEN")
                if state.active_storage_generation_id != request.target_storage_generation_id:
                    raise CoreError("RESTORE_REQUEST_CONFLICT")
                return RestoreVerification(
                    same_identity=True, read_only=False, reason="RESTORE_ACTIVATED",
                    continuity_epoch=state.current_epoch, audit=None,
                )
            if existing is None:
                if claim["status"] == "ACTIVE":
                    # A terminal authority claim cannot recreate a lost local
                    # hash-bound receipt with a freshly timestamped audit row.
                    raise CoreError("RESTORE_STATE_GAP")
                self._verify_restore_source(session, request, claim["source_checkpoint"])
                session.rollback()
                claim = self.authority.activate_recovery(request.request_id)
                checkpoint = self.authority.export_checkpoint(manifest.continuity_id)
                source = claim["source_checkpoint"]
                expected = {
                    **source, "epoch": claim["target_epoch"],
                    "state_version": claim["target_state_version"],
                    "storage_generation_id": claim["target_storage_generation_id"],
                    "recovery_state": "RECOVERY_PREPARED",
                    "recovery_claim_request_id": request.request_id,
                }
                if checkpoint != expected:
                    raise CoreError("RESTORE_STATE_GAP")
                with session.begin():
                    metadata, state, genesis = self._local_projection(session, manifest.continuity_id, require_ready=False)
                    self._checkpoint_matches(session, metadata, state, genesis, source, require_active=False)
                    state.current_epoch = claim["target_epoch"]
                    state.state_version = claim["target_state_version"]
                    state.active_storage_generation_id = request.target_storage_generation_id
                    state.lease_id = None
                    state.status = "RESTORE_QUARANTINED"
                    metadata.status = "RESTORE_QUARANTINED"
                    metadata.current_state_version = state.state_version
                    metadata.active_storage_generation_id = state.active_storage_generation_id
                    append_audit(
                        session, trust_domain_id=manifest.trust_domain_id,
                        continuity_id=manifest.continuity_id, continuity_epoch=state.current_epoch,
                        state_version=state.state_version, operation_type="CONTINUITY_REBASED",
                        actor_principal_id=request.current_owner_principal_id,
                        capability="core_governance", request_id=request.request_id, mutation_id=None,
                        result_code="COMMITTED", payload=self._restore_payload(request, claim),
                    )
                    session.add(RestoreRecord(
                        request_id=request.request_id, trust_domain_id=manifest.trust_domain_id,
                        continuity_id=manifest.continuity_id, manifest_hash=manifest.manifest_hash,
                        target_storage_generation_id=request.target_storage_generation_id,
                        status="PREPARED", reason_code="AWAITING_AUTHORITY_CHECKPOINT",
                    ))
            else:
                session.rollback()

            with session.begin():
                metadata, state, genesis = self._local_projection(session, manifest.continuity_id, require_ready=False)
                record, row = self._restore_record_audit(session, request, claim, local_status="PREPARED")
                if (
                    metadata.audit_seq != row.audit_seq or metadata.audit_head_hash != row.record_hash
                    or state.state_version != claim["target_state_version"]
                    or state.current_epoch != claim["target_epoch"]
                    or state.active_storage_generation_id != request.target_storage_generation_id
                ):
                    raise CoreError("RESTORE_STATE_GAP")
                verify_audit_chain(session, refresh=True)
                completed = self.authority.complete_recovery(
                    request.request_id, audit_seq=row.audit_seq, audit_head_hash=row.record_hash,
                )
                metadata, state, genesis = self._local_projection(session, manifest.continuity_id, require_ready=False)
                self._checkpoint_matches(
                    session, metadata, state, genesis, self.authority.export_checkpoint(manifest.continuity_id),
                )
                record, row = self._restore_record_audit(session, request, claim, local_status="PREPARED")
                if completed.get("status") != "ACTIVE" or completed.get("audit_seq") != row.audit_seq or completed.get("audit_head_hash") != row.record_hash:
                    raise CoreError("RESTORE_FENCE_UNPROVEN")
                record.status = "ACTIVE"
                record.reason_code = None
                state.status = "READY"
                metadata.status = "READY"
            return RestoreVerification(
                same_identity=True, read_only=False, reason="RESTORE_ACTIVATED",
                continuity_epoch=claim["target_epoch"], audit=None,
            )
        except Exception:
            session.rollback()
            self._quarantine(reason="RESTORE_FENCE_UNPROVEN")
            raise
        finally:
            session.close()
