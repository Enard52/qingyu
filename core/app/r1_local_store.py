"""Core-only durable R1 projections. No Authority SQL, credentials or signer.

The separate candidate metadata is installed by explicit migration/test setup,
never by a constructor. Audit rows retain the Core canonical record format;
they are isolated from legacy CoreMetadata/AuditLedger and validated together.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from uuid import UUID, uuid4

from sqlalchemy import BigInteger, JSON, LargeBinary, String, UniqueConstraint, Index, select, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from .canonical import canonical_json, sha256_hex as core_hash
from .control_plane.r1_admission import VerifiedCoreAdmission, verify_genesis_evidence
from .control_plane.r1_client import ChainCursor, OperationAttempt, VerifiedPhase
from .control_plane.r1_commands import AbortAuthorization, CommitAuthorization, MutationIntent
from .control_plane.r1_protocol import canonical_bytes, decode_canonical_wire, sha256_hex, verify_prepare_ack, verify_terminal_receipt
from .errors import CoreError
from .schemas import MutationRequest


class R1LocalBase(DeclarativeBase):
    pass


class R1Checkpoint(R1LocalBase):
    __tablename__ = "r1_core_checkpoint"
    continuity_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scope_wire: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    origin_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    state_version: Mapped[int] = mapped_column(BigInteger, nullable=False)
    audit_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    audit_head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    next_authority_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    authority_head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)  # No READY default.


class R1LocalOperation(R1LocalBase):
    __tablename__ = "r1_core_operations"
    operation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    continuity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    mutation_id: Mapped[str] = mapped_column(String(256), nullable=False)
    request_wire: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    source_request_wire: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    commit_audit_wire: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    abort_audit_wire: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    cursor_sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    cursor_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    requested_decision: Mapped[str] = mapped_column(String(6), nullable=False)
    ack_wire: Mapped[bytes | None] = mapped_column(LargeBinary)
    authorization_wire: Mapped[bytes | None] = mapped_column(LargeBinary)
    terminal_wire: Mapped[bytes | None] = mapped_column(LargeBinary)
    receipt_hash: Mapped[str | None] = mapped_column(String(64))
    terminal_sequence: Mapped[int | None] = mapped_column(BigInteger)
    __table_args__ = (UniqueConstraint("continuity_id", "mutation_id"),
                     UniqueConstraint("terminal_sequence"),
                     Index("uq_r1_core_unresolved", "continuity_id", unique=True,
                           postgresql_where=text("terminal_wire IS NULL"), sqlite_where=text("terminal_wire IS NULL")))


class R1AuditRow(R1LocalBase):
    __tablename__ = "r1_core_audit"
    audit_sequence: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    operation_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False)
    canonical_record: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    projection: Mapped[dict] = mapped_column(JSON, nullable=False)
    record_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)


@dataclass(frozen=True, slots=True)
class CoreRuntimeScope:
    """Independently supplied immutable runtime identity; not a response projection."""
    trust_domain_id: str
    qingyu_identity_id: str
    continuity_id: str
    genesis_operation_id: str
    continuity_epoch: int
    owner_version: int
    owner_identity: str
    storage_generation_id: str
    control_plane_generation_id: str
    lease_id: str
    lease_generation: int
    caller_runtime_id: str
    session_id: str

    def __post_init__(self):
        for name in ("trust_domain_id", "qingyu_identity_id", "continuity_id", "genesis_operation_id",
                     "storage_generation_id", "control_plane_generation_id", "lease_id", "caller_runtime_id", "session_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or str(UUID(value)) != value:
                raise CoreError("R1_LOCAL_SCOPE_INVALID")
        if any(type(getattr(self, name)) is not int or getattr(self, name) < 1
               for name in ("continuity_epoch", "owner_version", "lease_generation")) or not self.owner_identity:
            raise CoreError("R1_LOCAL_SCOPE_INVALID")

    @property
    def wire(self) -> bytes:
        return canonical_bytes({name: getattr(self, name) for name in self.__dataclass_fields__})


@dataclass(frozen=True, slots=True)
class LocalAttempt:
    intent: MutationIntent
    cursor: ChainCursor
    status: str
    requested_decision: str
    ack_wire: bytes | None
    authorization_wire: bytes | None
    terminal_wire: bytes | None
    commit_audit_wire: bytes
    abort_audit_wire: bytes

    @property
    def attempt(self) -> OperationAttempt:
        return OperationAttempt.from_durable_intent(self.intent.envelope, self.intent.expected_intent)


class R1LocalStore:
    def __init__(self, session_factory, *, admission: VerifiedCoreAdmission, scope: CoreRuntimeScope,
                 genesis_evidence_wire: bytes):
        if not isinstance(admission, VerifiedCoreAdmission) or not isinstance(scope, CoreRuntimeScope):
            raise CoreError("R1_LOCAL_ADMISSION_REQUIRED")
        self.sessions, self.admission, self.scope = session_factory, admission, scope
        genesis = decode_canonical_wire(genesis_evidence_wire)
        verify_genesis_evidence(admission, genesis, continuity_id=scope.continuity_id,
                               identity_id=scope.qingyu_identity_id, operation_id=scope.genesis_operation_id)
        self._genesis_audit_hash = genesis["core_audit_candidate_hash"]
        self._genesis_receipt_hash = genesis["receipt_hash"]
        self.inspect()  # Read existing state only; never bootstrap tables/identity.

    def _checkpoint(self, session, *, allow_pending=False):
        row = session.get(R1Checkpoint, self.scope.continuity_id, with_for_update=True, populate_existing=True)
        if row is None or row.scope_wire != self.scope.wire or row.origin_digest != self.admission.origin.signed_provisioning_origin_digest:
            raise CoreError("R1_LOCAL_IDENTITY_MISMATCH")
        if row.status not in (("READY", "RECONCILIATION_REQUIRED") if allow_pending else ("READY",)):
            raise CoreError("R1_RECONCILIATION_REQUIRED")
        self._audit(session, row)
        return row

    def _audit(self, session, checkpoint):
        rows = list(session.scalars(select(R1AuditRow).order_by(R1AuditRow.audit_sequence)
                                   .with_for_update().execution_options(populate_existing=True)))
        previous = None
        authority_head, next_sequence = self._genesis_receipt_hash, 2
        prior_state = None
        for seq, row in enumerate(rows, 1):
            try:
                record = json.loads(row.canonical_record)
            except (ValueError, TypeError):
                raise CoreError("R1_AUDIT_INVALID") from None
            if (canonical_json(record) != row.canonical_record or row.projection != record
                    or row.audit_sequence != seq or record.get("audit_seq") != seq
                    or record.get("previous_record_hash") != previous
                    or core_hash(row.canonical_record) != row.record_hash
                    or record.get("request_id") != row.operation_id
                    or record.get("trust_domain_id") != self.scope.trust_domain_id
                    or record.get("continuity_id") != self.scope.continuity_id
                    or record.get("continuity_epoch") != self.scope.continuity_epoch):
                raise CoreError("R1_AUDIT_INVALID")
            previous = row.record_hash
            if seq == 1:
                if row.record_hash != self._genesis_audit_hash or row.operation_id != self.scope.genesis_operation_id:
                    raise CoreError("R1_GENESIS_AUDIT_MISMATCH")
            else:
                operation = session.get(R1LocalOperation, row.operation_id, populate_existing=True)
                if operation is None or operation.terminal_wire is None:
                    raise CoreError("R1_AUDIT_RECEIPT_MISSING")
                intent = self._validate_operation(operation)
                self._validate_staged(operation, intent)
                if (operation.cursor_sequence != next_sequence or operation.cursor_hash != authority_head
                        or intent.envelope["expected_state_version"] != prior_state):
                    raise CoreError("R1_AUTHORITY_CHAIN_MISMATCH")
                receipt = decode_canonical_wire(operation.terminal_wire)
                digest = verify_terminal_receipt(receipt, intent.envelope, self.admission.pin, intent.expected_intent,
                    expected_sequence=operation.cursor_sequence, expected_previous_hash=operation.cursor_hash)
                selected = operation.commit_audit_wire if receipt["result_state"] == "COMMITTED" else operation.abort_audit_wire
                if (selected != row.canonical_record or operation.receipt_hash != digest
                        or operation.terminal_sequence != next_sequence
                        or receipt["result_payload_hash"] != intent.result_hash(receipt["result_state"])):
                    raise CoreError("R1_AUDIT_RECEIPT_MISMATCH")
                authority_head, next_sequence = digest, next_sequence + 1
            prior_state = record["state_version"]
        if (not rows or checkpoint.audit_sequence != len(rows) or checkpoint.audit_head_hash != previous
                or rows[-1].projection["state_version"] != checkpoint.state_version
                or checkpoint.next_authority_sequence != next_sequence
                or checkpoint.authority_head_hash != authority_head):
            raise CoreError("R1_AUDIT_CHECKPOINT_MISMATCH")

    def inspect(self):
        with self.sessions.begin() as session:
            row = self._checkpoint(session, allow_pending=True)
            return {name: getattr(row, name) for name in ("state_version", "audit_sequence", "audit_head_hash",
                    "status", "next_authority_sequence", "authority_head_hash")}

    @staticmethod
    def _snapshot(row) -> LocalAttempt:
        return LocalAttempt(MutationIntent.from_wire(row.request_wire), ChainCursor(row.cursor_sequence, row.cursor_hash),
            row.status, row.requested_decision, row.ack_wire, row.authorization_wire, row.terminal_wire, row.commit_audit_wire, row.abort_audit_wire)

    @staticmethod
    def _pending_cursor(row, checkpoint):
        if row.terminal_wire is None and (row.cursor_sequence != checkpoint.next_authority_sequence
                or row.cursor_hash != checkpoint.authority_head_hash):
            raise CoreError("R1_PENDING_CURSOR_MISMATCH")

    def _validate_operation(self, row):
        intent = MutationIntent.from_wire(row.request_wire)
        source = decode_canonical_wire(row.source_request_wire)
        if row.operation_id != intent.operation_id or row.mutation_id != intent.payload["mutation_id"]:
            raise CoreError("R1_INTENT_MISMATCH")
        pin, scope = self.admission.pin, self.scope
        expected = {"authority_domain_id": pin.authority_domain_id, "authority_instance_id": pin.authority_instance_id,
            "authority_generation": pin.authority_generation, "qingyu_identity_id": scope.qingyu_identity_id,
            "continuity_id": scope.continuity_id, "expected_continuity_epoch": scope.continuity_epoch,
            "expected_owner_version": scope.owner_version, "actor_or_owner_identity": scope.owner_identity,
            "caller_runtime_id": scope.caller_runtime_id, "storage_generation_id": scope.storage_generation_id}
        expected_payload = {name: getattr(scope, name) for name in ("lease_id", "lease_generation", "session_id",
                             "control_plane_generation_id", "genesis_operation_id")}
        if (row.continuity_id != scope.continuity_id
                or any(intent.envelope[name] != value for name, value in expected.items())
                or any(intent.payload[name] != value for name, value in expected_payload.items())):
            raise CoreError("R1_INTENT_SCOPE_MISMATCH")
        bound = {"continuity_id": intent.envelope["continuity_id"],
            "continuity_epoch": intent.envelope["expected_continuity_epoch"], "lease_id": intent.payload["lease_id"],
            "mutation_id": intent.payload["mutation_id"], "actor_principal_id": intent.envelope["actor_or_owner_identity"],
            "capability": intent.payload["staged_result"]["value"]["capability"],
            "payload": intent.payload["staged_result"]["value"]["payload"],
            "_r1_decision": intent.payload["staged_result"]["value"]["requested_decision"]}
        if source != bound or row.requested_decision not in ("COMMIT", "ABORT") or row.requested_decision != bound["_r1_decision"]:
            raise CoreError("R1_SOURCE_REQUEST_MISMATCH")
        for wire, expected_hash, outcome in ((row.commit_audit_wire, intent.payload["core_audit_candidate_hash"], "COMMITTED"),
                (row.abort_audit_wire, intent.payload["abort_result"]["core_audit_candidate_hash"], "ABORTED")):
            record = json.loads(wire)
            if (canonical_json(record) != wire or core_hash(wire) != expected_hash
                    or record["previous_record_hash"] != intent.payload["core_audit_predecessor_hash"]
                    or record["request_id"] != intent.operation_id or record["mutation_id"] != row.mutation_id
                    or record["state_version"] != intent.result_payload(outcome)["state_version"]
                    or record["payload_hash"] != core_hash({"mutation_id": row.mutation_id,
                                                           "value": source["payload"], "decision": outcome})
                    or record["result_code"] != outcome):
                raise CoreError("R1_INTENT_AUDIT_MISMATCH")
        return intent

    def _validate_staged(self, row, intent):
        if row.ack_wire is None or row.authorization_wire is None:
            raise CoreError("R1_STAGED_PROOF_MISSING")
        ack = decode_canonical_wire(row.ack_wire)
        verify_prepare_ack(ack, intent.envelope, self.admission.pin, intent.expected_intent)
        value = decode_canonical_wire(row.authorization_wire)
        kind = CommitAuthorization if value.get("decision") == "COMMIT" else AbortAuthorization
        authorization = kind.from_wire(row.authorization_wire)
        authorization.validate_for(intent)
        if authorization.decision != row.requested_decision:
            raise CoreError("R1_STAGED_DECISION_MISMATCH")
        evidence = sha256_hex(b"QINGYU-R1-CORE-STAGED-EVIDENCE-V1\x00" + intent.request_wire + row.ack_wire
                              + row.commit_audit_wire + row.abort_audit_wire)
        evidence_field = "transaction_evidence_hash" if authorization.decision == "COMMIT" else "abort_evidence_hash"
        if value[evidence_field] != evidence:
            raise CoreError("R1_STAGED_EVIDENCE_MISMATCH")
        return authorization

    def begin_intent(self, request, *, decision="COMMIT") -> LocalAttempt:
        if decision not in ("COMMIT", "ABORT"):
            raise CoreError("R1_UNSUPPORTED_DECISION")
        source = canonical_bytes({**request.model_dump(mode="json"), "_r1_decision": decision})
        frozen_input = decode_canonical_wire(source)
        frozen_input.pop("_r1_decision")
        # All later derivation uses this detached canonical snapshot, including
        # across database waits; the caller still owns its mutable request.
        request = MutationRequest.model_validate(frozen_input)
        with self.sessions.begin() as session:
            cp = self._checkpoint(session, allow_pending=True)
            old = session.scalar(select(R1LocalOperation).where(R1LocalOperation.continuity_id == self.scope.continuity_id,
                 R1LocalOperation.mutation_id == request.mutation_id).with_for_update())
            if old is not None:
                if old.source_request_wire != source:
                    raise CoreError("R1_MUTATION_ID_CONFLICT")
                self._validate_operation(old)
                self._pending_cursor(old, cp)
                if old.ack_wire is not None or old.authorization_wire is not None:
                    self._validate_staged(old, MutationIntent.from_wire(old.request_wire))
                return self._snapshot(old)
            if cp.status != "READY" or session.scalar(select(R1LocalOperation.operation_id).where(
                    R1LocalOperation.continuity_id == self.scope.continuity_id,
                    R1LocalOperation.terminal_wire.is_(None)).limit(1)):
                raise CoreError("R1_RECONCILIATION_REQUIRED")
            s, pin = self.scope, self.admission.pin
            if (str(request.continuity_id) != s.continuity_id or request.continuity_epoch != s.continuity_epoch
                    or str(request.lease_id) != s.lease_id or request.actor_principal_id != s.owner_identity
                    or request.capability != "core_governance"):
                raise CoreError("R1_REQUEST_SCOPE_MISMATCH")
            operation_id, local_commit_id = str(uuid4()), str(uuid4())
            records = {}
            for outcome in ("COMMITTED", "ABORTED"):
                record = {"audit_seq": cp.audit_sequence + 1, "trust_domain_id": s.trust_domain_id,
                    "continuity_id": s.continuity_id, "continuity_epoch": s.continuity_epoch,
                    "state_version": cp.state_version + (outcome == "COMMITTED"), "operation_type": "GOVERNED_MUTATION",
                    "actor_principal_id": s.owner_identity, "capability": request.capability,
                    "request_id": operation_id, "mutation_id": request.mutation_id, "result_code": outcome,
                    "payload_hash": core_hash({"mutation_id": request.mutation_id, "value": request.payload, "decision": outcome}),
                    "previous_record_hash": cp.audit_head_hash, "created_at": datetime.now(timezone.utc).isoformat()}
                records[outcome] = canonical_json(record)
            staged = {"mutation_id": request.mutation_id, "state_version": cp.state_version + 1,
                      "value": {"payload": request.payload, "capability": request.capability, "requested_decision": decision}}
            aborted = {"mutation_id": request.mutation_id, "state_version": cp.state_version, "result_state": "ABORTED",
                       "core_audit_candidate_hash": core_hash(records["ABORTED"])}
            envelope = {"schema_version": 1, "authority_domain_id": pin.authority_domain_id,
                "authority_instance_id": pin.authority_instance_id, "authority_generation": pin.authority_generation,
                "qingyu_identity_id": s.qingyu_identity_id, "continuity_id": s.continuity_id, "operation_id": operation_id,
                "operation_type": "MUTATION", "expected_continuity_epoch": s.continuity_epoch,
                "expected_state_version": cp.state_version, "expected_owner_version": s.owner_version,
                "actor_or_owner_identity": s.owner_identity, "caller_runtime_id": s.caller_runtime_id,
                "storage_generation_id": s.storage_generation_id, "reason": "Core governed mutation",
                "payload": {"payload_version": 1, "mutation_id": request.mutation_id, "local_commit_id": local_commit_id,
                    "lease_id": s.lease_id, "lease_generation": s.lease_generation, "session_id": s.session_id,
                    "control_plane_generation_id": s.control_plane_generation_id, "genesis_operation_id": s.genesis_operation_id,
                    "staged_result": staged, "staged_result_hash": sha256_hex(canonical_bytes(staged)),
                    "core_audit_predecessor_hash": cp.audit_head_hash, "core_audit_candidate_hash": core_hash(records["COMMITTED"]),
                    "abort_result": aborted, "abort_result_hash": sha256_hex(canonical_bytes(aborted))}}
            intent = MutationIntent.from_envelope(envelope)
            row = R1LocalOperation(operation_id=operation_id, continuity_id=s.continuity_id, mutation_id=request.mutation_id,
                request_wire=intent.request_wire, source_request_wire=source, commit_audit_wire=records["COMMITTED"],
                abort_audit_wire=records["ABORTED"], cursor_sequence=cp.next_authority_sequence,
                cursor_hash=cp.authority_head_hash, status="INTENT", requested_decision=decision)
            session.add(row)
            cp.status = "RECONCILIATION_REQUIRED"
            return self._snapshot(row)

    def load(self, operation_id) -> LocalAttempt:
        with self.sessions.begin() as session:
            cp = self._checkpoint(session, allow_pending=True)
            row = session.get(R1LocalOperation, operation_id, with_for_update=True)
            if row is None:
                raise CoreError("R1_INTENT_MISSING")
            self._validate_operation(row)
            self._pending_cursor(row, cp)
            if row.ack_wire is not None or row.authorization_wire is not None:
                self._validate_staged(row, MutationIntent.from_wire(row.request_wire))
            return self._snapshot(row)

    def pending(self) -> list[str]:
        with self.sessions.begin() as session:
            self._checkpoint(session, allow_pending=True)
            return list(session.scalars(select(R1LocalOperation.operation_id).where(
                R1LocalOperation.continuity_id == self.scope.continuity_id, R1LocalOperation.terminal_wire.is_(None))))

    def stage(self, operation_id, phase: VerifiedPhase, *, decision="COMMIT") -> LocalAttempt:
        with self.sessions.begin() as session:
            cp = self._checkpoint(session, allow_pending=True)
            row = session.get(R1LocalOperation, operation_id, with_for_update=True)
            intent = self._validate_operation(row)
            if decision != row.requested_decision:
                raise CoreError("R1_DECISION_CONFLICT")
            verify_prepare_ack(phase.message, intent.envelope, self.admission.pin, intent.expected_intent)
            wire = canonical_bytes(phase.message)
            if row.ack_wire is not None and row.ack_wire != wire:
                raise CoreError("R1_ACK_CONFLICT")
            if cp.state_version != intent.envelope["expected_state_version"] or cp.audit_head_hash != intent.payload["core_audit_predecessor_hash"]:
                raise CoreError("R1_LOCAL_STATE_STALE")
            authorization = {"authorization_version": 1, "decision": decision, "operation_id": intent.operation_id,
                "request_envelope_hash": intent.request_hash, **{name: intent.payload[name] for name in (
                    "local_commit_id", "staged_result_hash", "core_audit_predecessor_hash", "core_audit_candidate_hash")}}
            evidence = sha256_hex(b"QINGYU-R1-CORE-STAGED-EVIDENCE-V1\x00" + intent.request_wire + wire
                                  + row.commit_audit_wire + row.abort_audit_wire)
            if decision == "COMMIT":
                authorization["transaction_evidence_hash"] = evidence
                auth = CommitAuthorization.from_mapping(authorization)
            elif decision == "ABORT":
                authorization.update(no_local_business_commit=True, abort_evidence_hash=evidence)
                auth = AbortAuthorization.from_mapping(authorization)
            else:
                raise CoreError("R1_UNSUPPORTED_DECISION")
            if row.authorization_wire is not None and row.authorization_wire != auth.wire:
                raise CoreError("R1_AUTHORIZATION_CONFLICT")
            row.ack_wire, row.authorization_wire, row.status = wire, auth.wire, "PREPARED"
            return self._snapshot(row)

    def uncertain(self, operation_id) -> None:
        invalid_terminal = None
        with self.sessions.begin() as session:
            cp = session.get(R1Checkpoint, self.scope.continuity_id, with_for_update=True, populate_existing=True)
            row = session.get(R1LocalOperation, operation_id, with_for_update=True, populate_existing=True)
            if row is not None and row.terminal_wire is not None:
                try:
                    # A sibling retry may already have finalized this operation.
                    # Ignore its late failure only after proving this terminal is
                    # in the verified local chain; a status/receipt flag alone is
                    # not evidence. Never reset another pending operation's gate.
                    self._checkpoint(session, allow_pending=True)
                    intent = self._validate_operation(row)
                    authorization = self._validate_staged(row, intent)
                    receipt = decode_canonical_wire(row.terminal_wire)
                    outcome = "COMMITTED" if authorization.decision == "COMMIT" else "ABORTED"
                    selected = row.commit_audit_wire if outcome == "COMMITTED" else row.abort_audit_wire
                    audit = session.get(R1AuditRow, json.loads(selected)["audit_seq"], populate_existing=True)
                    if (receipt["result_state"] != outcome or row.status != "FINALIZED_" + outcome
                            or audit is None or audit.operation_id != operation_id or audit.canonical_record != selected):
                        raise CoreError("R1_HISTORICAL_RECEIPT_MISMATCH")
                except Exception as exc:
                    invalid_terminal = exc
                else:
                    return
            if cp is not None:
                cp.status = "RECONCILIATION_REQUIRED"
            if row is not None and row.terminal_wire is None:
                row.status = "RECONCILIATION_REQUIRED"
        if invalid_terminal is not None:
            # Preserve the fail-closed barrier even when malformed terminal
            # history has no unresolved row for startup to reconcile.
            raise invalid_terminal

    def finalize(self, operation_id, phase: VerifiedPhase):
        with self.sessions.begin() as session:
            cp = self._checkpoint(session, allow_pending=True)
            row = session.get(R1LocalOperation, operation_id, with_for_update=True)
            intent = self._validate_operation(row)
            message = phase.message
            digest = verify_terminal_receipt(message, intent.envelope, self.admission.pin, intent.expected_intent,
                expected_sequence=row.cursor_sequence, expected_previous_hash=row.cursor_hash,
                prepared_ack=decode_canonical_wire(row.ack_wire) if row.ack_wire else None)
            outcome = message["result_state"]
            authorization = self._validate_staged(row, intent)
            if phase.state != outcome or outcome != ("COMMITTED" if authorization.decision == "COMMIT" else "ABORTED"):
                raise CoreError("R1_TERMINAL_DECISION_MISMATCH")
            if (message["result_payload_hash"] != intent.result_hash(outcome)
                    or message["continuity_epoch"] != self.scope.continuity_epoch
                    or message["owner_version"] != self.scope.owner_version
                    or message["control_plane_generation_id"] != self.scope.control_plane_generation_id
                    or message["lease_generation"] != self.scope.lease_generation):
                raise CoreError("R1_TERMINAL_RESULT_MISMATCH")
            wire = canonical_bytes(message)
            selected = row.commit_audit_wire if outcome == "COMMITTED" else row.abort_audit_wire
            record = json.loads(selected)
            if row.terminal_wire is not None:
                old_audit = session.get(R1AuditRow, record["audit_seq"])
                if (row.terminal_wire != wire or row.receipt_hash != digest or old_audit is None
                        or old_audit.canonical_record != selected or old_audit.operation_id != operation_id):
                    raise CoreError("R1_HISTORICAL_RECEIPT_MISMATCH")
                return record, intent
            if row.ack_wire is None or row.authorization_wire is None:
                raise CoreError("R1_STAGED_PROOF_MISSING")
            if (cp.state_version != intent.envelope["expected_state_version"]
                    or cp.audit_head_hash != intent.payload["core_audit_predecessor_hash"]
                    or cp.audit_sequence + 1 != record["audit_seq"]
                    or cp.next_authority_sequence != row.cursor_sequence or cp.authority_head_hash != row.cursor_hash):
                raise CoreError("R1_LOCAL_STATE_STALE")
            session.add(R1AuditRow(audit_sequence=record["audit_seq"], operation_id=operation_id,
                canonical_record=selected, projection=record, record_hash=core_hash(selected)))
            row.terminal_wire, row.receipt_hash, row.terminal_sequence = wire, digest, message["authority_sequence"]
            row.status = "FINALIZED_" + outcome
            cp.state_version = intent.result_payload(outcome)["state_version"]
            cp.audit_sequence, cp.audit_head_hash = record["audit_seq"], core_hash(selected)
            cp.next_authority_sequence, cp.authority_head_hash = message["authority_sequence"] + 1, digest
            cp.status = "READY"
            return record, intent
