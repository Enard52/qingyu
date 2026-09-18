"""Durable R1 Core consumer; frozen legacy service remains a separate test path."""
from __future__ import annotations

from uuid import UUID
import hashlib

from .control_plane.r1_client import AuthorityClient, VerifiedPhase
from .control_plane.r1_commands import AbortAuthorization, CommitAuthorization
from .control_plane.r1_protocol import decode_canonical_wire
from .canonical import sha256_hex
from .errors import CoreError
from .r1_local_store import R1LocalStore
from .schemas import CoreReadModel, IdentityStatus, MutationResult


class R1CoreConsumer:
    def __init__(self, *, local_store: R1LocalStore, client: AuthorityClient):
        self.local, self.client = local_store, client

    def _complete(self, local, phase):
        record, intent = self.local.finalize(local.intent.operation_id, phase)
        return MutationResult(mutation_id=intent.payload["mutation_id"], status=phase.message["result_state"],
            continuity_epoch=record["continuity_epoch"], state_version=record["state_version"], audit_seq=record["audit_seq"],
            audit_head_hash=hashlib.sha256(local.commit_audit_wire if phase.state == "COMMITTED" else local.abort_audit_wire).hexdigest(),
            local_commit_id=intent.payload["local_commit_id"])

    def _drive(self, local):
        operation_id = local.intent.operation_id
        decision = local.requested_decision
        try:
            if local.terminal_wire is not None:
                message = decode_canonical_wire(local.terminal_wire)
                return self._complete(local, VerifiedPhase(message["result_state"], message))
            if local.ack_wire is None:
                phase = self.client.prepare(local.attempt, cursor=local.cursor)
            else:
                phase = self.client.query(local.attempt, cursor=local.cursor)
            if phase.state == "PREPARED":
                if local.authorization_wire is not None:
                    decision = decode_canonical_wire(local.authorization_wire)["decision"]
                local = self.local.stage(operation_id, phase, decision=decision)
                kind = CommitAuthorization if decision == "COMMIT" else AbortAuthorization
                authorization = kind.from_wire(local.authorization_wire)
                action = self.client.commit if decision == "COMMIT" else self.client.abort
                phase = action(local.attempt, authorization, cursor=local.cursor)
            if phase.state not in ("COMMITTED", "ABORTED"):
                raise CoreError("R1_RECONCILIATION_REQUIRED")
            return self._complete(local, phase)
        except Exception:
            self.local.uncertain(operation_id)
            raise

    def governed_mutation(self, request):
        # Existing ID replay must be possible while its own operation is pending.
        local = self.local.begin_intent(request)
        return self._drive(local)

    def abort_mutation(self, request):
        """Explicit caller decision only; never called by error handling."""
        return self._drive(self.local.begin_intent(request, decision="ABORT"))

    def reconcile_pending(self):
        for operation_id in self.local.pending():
            self._drive(self.local.load(operation_id))

    def identity_status(self):
        state, scope = self.local.inspect(), self.local.scope
        return IdentityStatus(status=state["status"], trust_domain_id=UUID(scope.trust_domain_id),
            qingyu_identity_id=UUID(scope.qingyu_identity_id), continuity_id=UUID(scope.continuity_id), continuity_alias=None,
            continuity_epoch=scope.continuity_epoch, state_version=state["state_version"], owner_version=scope.owner_version,
            active_storage_generation_id=UUID(scope.storage_generation_id), audit_seq=state["audit_sequence"],
            audit_head_hash=state["audit_head_hash"])

    def core_read_model(self):
        state, scope = self.local.inspect(), self.local.scope
        payload = {
            "schema_version": "core-read-model-v1",
            "status": state["status"],
            "identity_reference": {
                "trust_domain_id": scope.trust_domain_id,
                "qingyu_identity_id": scope.qingyu_identity_id,
                "continuity_id": scope.continuity_id,
                "continuity_alias": None,
                "genesis_operation_id": scope.genesis_operation_id,
                "origin_digest": self.local.admission.origin.signed_provisioning_origin_digest,
            },
            "generation": {
                "storage_generation_id": scope.storage_generation_id,
                "control_plane_generation_id": scope.control_plane_generation_id,
                "continuity_epoch": scope.continuity_epoch,
                "state_version": state["state_version"],
                "owner_version": scope.owner_version,
            },
            "governed_state": {
                "status": state["status"],
                "owner_principal_id": scope.owner_identity,
                "audit_high_water": state["audit_sequence"],
                "audit_head_hash": state["audit_head_hash"],
                "next_authority_sequence": state["next_authority_sequence"],
                "authority_head_hash": state["authority_head_hash"],
            },
            "lineage": {
                "genesis_operation_id": scope.genesis_operation_id,
                "continuity_epoch": scope.continuity_epoch,
                "owner_version": scope.owner_version,
            },
            "provenance": {
                "source": "r1-local-store",
                "admission_origin_digest": self.local.admission.origin.signed_provisioning_origin_digest,
                "authority_pin": {
                    "authority_domain_id": self.local.admission.pin.authority_domain_id,
                    "authority_instance_id": self.local.admission.pin.authority_instance_id,
                    "authority_generation": self.local.admission.pin.authority_generation,
                    "receipt_key_id": self.local.admission.pin.receipt_key_id,
                },
                "checkpoint": state,
            },
            "read_only": True,
        }
        return CoreReadModel(**payload, read_model_hash=sha256_hex(payload))

    def _unsupported(self, *args, **kwargs):
        raise CoreError("R1_LIFECYCLE_NOT_IMPLEMENTED")

    bootstrap_genesis = acquire_owner_lease = transfer_owner = verify_restore = activate_restore = _unsupported
def create_scoped_core_finisher(store, *, trust, deployments, runtime_principal,
                               source=None, checkpoint_hook=None):
    """Explicit V2 local-only integration. No default route or V1 alteration."""
    from .r1_atomic_finish import ScopedCoreFinisher
    return ScopedCoreFinisher(store, trust=trust, deployments=deployments,
                             runtime_principal=runtime_principal, source=source,
                             checkpoint_hook=checkpoint_hook)


def create_scoped_core_coordinator(*, journal, finisher, client, source, checkpoint_hook=None):
    """Explicit ordinary V2 service; production defaults gain no new route."""
    from .r1_scoped_coordinator import ScopedCoreCoordinator
    return ScopedCoreCoordinator(journal=journal, finisher=finisher, client=client,
                                 source=source, checkpoint_hook=checkpoint_hook)
