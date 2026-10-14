"""The sole current-R1 mutation coordinator; no Root signing or memory fallback."""
from __future__ import annotations

from typing import Protocol
from datetime import datetime

from .r1_admission import AdmissionError, AuthorityAdmission
from .r1_commands import AbortAuthorization, AuthenticatedCaller, CommitAuthorization, MutationIntent
from .r1_postgres_store import R1PostgresStore, StoreError
from .r1_protocol import (PREPARE_FIELDS, PREPARE_PREFIX, RECEIPT_FIELDS, RECEIPT_PREFIX,
    ProtocolError, canonical_bytes, decode_canonical_wire, verify_prepare_ack, verify_terminal_receipt,
    _validate_prepare, _validate_receipt)


class ReceiptSigner(Protocol):
    @property
    def key_id(self) -> str: ...
    def sign(self, message: bytes) -> bytes: ...


class R1Coordinator:
    def __init__(self, *, store: R1PostgresStore, admission: AuthorityAdmission, receipt_signer: ReceiptSigner):
        if not isinstance(admission, AuthorityAdmission):
            raise AdmissionError("verified independent Authority admission required")
        admission.verify()  # Refuse absent evidence before acquiring any DB connection.
        if receipt_signer is None or receipt_signer.key_id != admission.public.pin.receipt_key_id:
            raise AdmissionError("preprovisioned receipt signer binding required")
        admission.check_store(store.describe())
        self.store, self.admission, self.signer = store, admission, receipt_signer

    def _gate(self, caller: AuthenticatedCaller, intent: MutationIntent | None = None) -> None:
        if not isinstance(caller, AuthenticatedCaller):
            raise ProtocolError("authenticated server scope required")
        self.admission.verify()
        self.admission.check_store(self.store.describe())
        if caller.authority_domain_id != self.admission.public.pin.authority_domain_id:
            raise ProtocolError("authenticated Authority domain differs")
        if intent is not None:
            caller.validate_for(intent)
            self.admission.verify_genesis(self.store.genesis_evidence(caller),
                continuity_id=caller.continuity_id, identity_id=intent.envelope["qingyu_identity_id"],
                operation_id=intent.payload["genesis_operation_id"])

    def _verify(self, wire: bytes, intent: MutationIntent) -> None:
        message, pin = decode_canonical_wire(wire), self.admission.public.pin
        if message.get("state") == "PREPARED":
            verify_prepare_ack(message, intent.envelope, pin, intent.expected_intent)
            return
        # Store owns global sequencing. Core independently validates its saved
        # cursor; service validation here does NOT grant Core a cursor.
        verify_terminal_receipt(message, intent.envelope, pin, intent.expected_intent,
            expected_sequence=message["authority_sequence"], expected_previous_hash=message["previous_receipt_hash"])
        expected = {"result_payload_hash": intent.result_hash(message["result_state"]),
                    "continuity_epoch": intent.envelope["expected_continuity_epoch"],
                    "owner_version": intent.envelope["expected_owner_version"],
                    "control_plane_generation_id": intent.payload["control_plane_generation_id"],
                    "lease_generation": intent.payload["lease_generation"]}
        if any(message[name] != value for name, value in expected.items()):
            raise ProtocolError("terminal proposal result/context differs from frozen intent")

    def _finish(self, transaction, intent: MutationIntent, target: str) -> bytes:
        proposal = transaction.proposal
        if proposal.operation_id != intent.operation_id:
            raise ProtocolError("proposal operation mismatch")
        if proposal.historical:
            self._verify(proposal.wire, intent)
            return proposal.wire
        if proposal.state != target:
            raise ProtocolError("proposal changed authenticated decision")
        message = decode_canonical_wire(proposal.wire)
        prepared = proposal.state == "PREPARED"
        field, prefix, fields = (("ack_signature", PREPARE_PREFIX, PREPARE_FIELDS) if prepared
                                  else ("receipt_signature", RECEIPT_PREFIX, RECEIPT_FIELDS))
        if set(message) != fields - {field}:
            raise ProtocolError("proposal canonical fields mismatch")
        (_validate_prepare if prepared else _validate_receipt)({**message, field: "0" * 128})
        if message.get("state" if prepared else "result_state") != proposal.state:
            raise ProtocolError("proposal state mismatch")
        # Validate full unsigned semantics before accessing the signer. Signature
        # verification below independently checks the actual returned signature.
        envelope, payload = intent.envelope, intent.payload
        expected = {name: envelope[name] for name in ("authority_domain_id", "authority_instance_id",
                    "authority_generation", "qingyu_identity_id", "continuity_id", "operation_id", "operation_type")}
        expected.update(receipt_key_id=self.admission.public.pin.receipt_key_id,
                        request_envelope_hash=intent.request_hash)
        expected.update({name: payload[name] for name in ("staged_result_hash", "core_audit_predecessor_hash", "core_audit_candidate_hash")})
        if prepared:
            expected.update({name: envelope[name] for name in ("caller_runtime_id", "storage_generation_id",
                "expected_continuity_epoch", "expected_owner_version", "expected_state_version")})
        else:
            expected.update(actor_or_owner_identity=envelope["actor_or_owner_identity"],
                storage_generation_id=envelope["storage_generation_id"],
                continuity_epoch=envelope["expected_continuity_epoch"], owner_version=envelope["expected_owner_version"],
                lease_generation=payload["lease_generation"], control_plane_generation_id=payload["control_plane_generation_id"],
                result_code=target)
        stamp = message["prepared_at" if prepared else "decided_at"]
        try:
            parsed = datetime.fromisoformat(stamp)
            if not stamp.endswith("Z") or parsed.utcoffset().total_seconds() != 0:
                raise ValueError
        except (ValueError, TypeError, AttributeError):
            raise ProtocolError("proposal timestamp is not canonical UTC") from None
        if any(message.get(name) != value for name, value in expected.items()):
            raise ProtocolError("proposal scope differs from immutable intent")
        if not prepared and message["result_payload_hash"] != intent.result_hash(proposal.state):
            raise ProtocolError("proposal selected result differs")
        signature = self.signer.sign(prefix + proposal.wire)
        self.admission.public.pin.receipt_public_key.verify(signature, prefix + proposal.wire)
        candidate = canonical_bytes({**message, field: signature.hex()})
        self._verify(candidate, intent)
        result = transaction.finalize(intent.operation_id, signature)
        if result != candidate:
            raise ProtocolError("finalize replaced the signed proposal")
        self._verify(result, intent)
        return result

    def prepare(self, wire: bytes, caller: AuthenticatedCaller) -> bytes:
        intent = MutationIntent.from_wire(wire)
        self._gate(caller, intent)
        with self.store.prepare(intent, caller) as tx:
            result = self._finish(tx, intent, "PREPARED")
        return result

    def decide(self, operation_id: str, authorization: CommitAuthorization | AbortAuthorization,
               caller: AuthenticatedCaller) -> bytes:
        self._gate(caller)
        intent = self.store.lookup_intent(operation_id, caller)
        if intent is None:
            raise StoreError("OPERATION_UNKNOWN")
        authorization.validate_for(intent)
        self._gate(caller, intent)
        with self.store.terminal(intent, caller, authorization) as tx:
            result = self._finish(tx, intent, "COMMITTED" if authorization.decision == "COMMIT" else "ABORTED")
        return result

    def query(self, operation_id: str, caller: AuthenticatedCaller) -> bytes | None:
        self._gate(caller)
        intent = self.store.lookup_intent(operation_id, caller)
        if intent is None:
            return None
        value = self.store.query(operation_id, caller, intent.request_hash)
        if value is None:
            return None
        self._verify(value.wire, intent)
        return value.wire
