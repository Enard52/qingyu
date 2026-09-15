"""Immutable, versioned F3 mutation commands; no transport or persistence authority."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping
from uuid import UUID

from .r1_protocol import (
    ExpectedIntent, ProtocolError, canonical_bytes, decode_canonical_wire,
    request_envelope_hash, sha256_hex,
)


MAX_SAFE_INTEGER = 9_007_199_254_740_991
PAYLOAD_FIELDS = frozenset({
    "payload_version", "mutation_id", "local_commit_id", "lease_id",
    "lease_generation", "session_id", "control_plane_generation_id",
    "genesis_operation_id", "staged_result", "staged_result_hash",
    "core_audit_predecessor_hash", "core_audit_candidate_hash", "abort_result", "abort_result_hash",
})
AUTHORIZATION_FIELDS = frozenset({
    "authorization_version", "decision", "operation_id", "request_envelope_hash",
    "local_commit_id", "staged_result_hash", "core_audit_predecessor_hash",
    "core_audit_candidate_hash",
})


def _uuid(value: Any) -> None:
    try:
        valid = isinstance(value, str) and str(UUID(value)) == value
    except (ValueError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise ProtocolError("non-canonical command UUID")


def _hash(value: Any) -> None:
    if (not isinstance(value, str) or len(value) != 64
            or any(c not in "0123456789abcdef" for c in value)):
        raise ProtocolError("invalid command SHA-256")


def _text(value: Any, maximum: int = 256) -> None:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise ProtocolError("invalid command text")


def _integer(value: Any, *, minimum: int = 1) -> None:
    if type(value) is not int or not minimum <= value <= MAX_SAFE_INTEGER:
        raise ProtocolError("command integer outside JCS safe range")


@dataclass(frozen=True, slots=True)
class AuthenticatedCaller:
    """Server-established scope; constructing this object does not authenticate HTTP."""

    authority_domain_id: str
    continuity_id: str
    caller_runtime_id: str
    session_id: str
    storage_generation_id: str
    actor_identity: str

    def __post_init__(self) -> None:
        for value in (self.authority_domain_id, self.continuity_id,
                      self.caller_runtime_id, self.session_id, self.storage_generation_id):
            _uuid(value)
        _text(self.actor_identity)

    def as_mapping(self) -> dict[str, str]:
        return {field: getattr(self, field) for field in self.__dataclass_fields__}

    def validate_for(self, intent: "MutationIntent") -> None:
        envelope = intent.envelope
        for field in ("authority_domain_id", "continuity_id", "caller_runtime_id",
                      "storage_generation_id"):
            if getattr(self, field) != envelope[field]:
                raise ProtocolError("authenticated caller scope mismatch")
        if (self.session_id != envelope["payload"]["session_id"]
                or self.actor_identity != envelope["actor_or_owner_identity"]):
            raise ProtocolError("authenticated caller session/actor mismatch")


@dataclass(frozen=True, slots=True)
class MutationIntent:
    """Canonical bytes are the only stored representation; properties are detached."""

    request_wire: bytes

    def __post_init__(self) -> None:
        envelope = decode_canonical_wire(self.request_wire)
        request_envelope_hash(envelope)
        if envelope["operation_type"] != "MUTATION":
            raise ProtocolError("unsupported F3 operation type")
        for field in ("authority_generation", "expected_continuity_epoch",
                      "expected_owner_version"):
            _integer(envelope[field])
        _integer(envelope["expected_state_version"], minimum=0)
        _text(envelope["actor_or_owner_identity"])
        if "\x00" in envelope["reason"]:
            raise ProtocolError("NUL cannot be persisted in PostgreSQL JSON")
        payload = envelope["payload"]
        if set(payload) != PAYLOAD_FIELDS or type(payload["payload_version"]) is not int or payload["payload_version"] != 1:
            raise ProtocolError("unknown mutation payload fields/version")
        for field in ("local_commit_id", "lease_id", "session_id",
                      "control_plane_generation_id", "genesis_operation_id"):
            _uuid(payload[field])
        _integer(payload["lease_generation"])
        _text(payload["mutation_id"])
        for field in ("staged_result_hash", "core_audit_predecessor_hash",
                      "core_audit_candidate_hash"):
            _hash(payload[field])
        result = payload["staged_result"]
        if not isinstance(result, Mapping) or set(result) != {"mutation_id", "state_version", "value"}:
            raise ProtocolError("invalid staged mutation result")
        _integer(result["state_version"])
        if (result["mutation_id"] != payload["mutation_id"]
                or result["state_version"] != envelope["expected_state_version"] + 1
                or sha256_hex(canonical_bytes(result)) != payload["staged_result_hash"]):
            raise ProtocolError("staged result/version/hash mismatch")
        abort = payload["abort_result"]
        if (not isinstance(abort, Mapping) or set(abort) != {
                "mutation_id", "state_version", "result_state", "core_audit_candidate_hash"}
                or abort["mutation_id"] != payload["mutation_id"]
                or type(abort["state_version"]) is not int
                or abort["state_version"] != envelope["expected_state_version"]
                or abort["result_state"] != "ABORTED"):
            raise ProtocolError("invalid frozen abort result")
        _hash(abort["core_audit_candidate_hash"])
        _hash(payload["abort_result_hash"])
        if sha256_hex(canonical_bytes(abort)) != payload["abort_result_hash"]:
            raise ProtocolError("abort result hash mismatch")
        # PostgreSQL JSONB cannot represent NUL; reject it anywhere in nested JSON.
        def check_json(value: Any) -> None:
            if isinstance(value, str) and "\x00" in value:
                raise ProtocolError("NUL cannot be persisted in PostgreSQL JSON")
            if isinstance(value, Mapping):
                for key, child in value.items():
                    check_json(key)
                    check_json(child)
            elif isinstance(value, list):
                for child in value:
                    check_json(child)
        check_json(envelope)

    @classmethod
    def from_envelope(cls, envelope: Mapping[str, Any]) -> "MutationIntent":
        return cls(canonical_bytes(envelope))

    @classmethod
    def from_wire(cls, wire: bytes) -> "MutationIntent":
        return cls(wire)

    @property
    def envelope(self) -> dict[str, Any]:
        return decode_canonical_wire(self.request_wire)

    @property
    def payload(self) -> dict[str, Any]:
        return self.envelope["payload"]

    @property
    def operation_id(self) -> str:
        return self.envelope["operation_id"]

    @property
    def request_hash(self) -> str:
        return sha256_hex(self.request_wire)

    @property
    def expected_intent(self) -> ExpectedIntent:
        payload = self.payload
        return ExpectedIntent(self.request_hash, payload["staged_result_hash"],
                              payload["core_audit_predecessor_hash"],
                              payload["core_audit_candidate_hash"])

    def result_payload(self, target_state: str) -> dict[str, Any]:
        if target_state == "COMMITTED":
            return self.payload["staged_result"]
        if target_state == "ABORTED":
            return self.payload["abort_result"]
        raise ProtocolError("invalid terminal result state")

    def result_hash(self, target_state: str) -> str:
        return sha256_hex(canonical_bytes(self.result_payload(target_state)))


def _validate_authorization(wire: bytes, decision: str) -> dict[str, Any]:
    value = decode_canonical_wire(wire)
    extra = ({"transaction_evidence_hash"} if decision == "COMMIT"
             else {"no_local_business_commit", "abort_evidence_hash"})
    if (not isinstance(value, Mapping) or set(value) != AUTHORIZATION_FIELDS | extra
            or type(value["authorization_version"]) is not int
            or value["authorization_version"] != 1 or value["decision"] != decision):
        raise ProtocolError("unknown authorization fields/version/decision")
    for field in ("operation_id", "local_commit_id"):
        _uuid(value[field])
    for field in ("request_envelope_hash", "staged_result_hash", "core_audit_predecessor_hash",
                  "core_audit_candidate_hash", "transaction_evidence_hash" if decision == "COMMIT" else "abort_evidence_hash"):
        _hash(value[field])
    if decision == "ABORT" and value["no_local_business_commit"] is not True:
        raise ProtocolError("abort requires explicit no-local-commit assertion")
    return dict(value)


def _authorization_for(wire: bytes, decision: str, intent: MutationIntent) -> None:
    value = _validate_authorization(wire, decision)
    expected = {"operation_id": intent.operation_id, "request_envelope_hash": intent.request_hash,
                **{name: intent.payload[name] for name in ("local_commit_id", "staged_result_hash",
                   "core_audit_predecessor_hash", "core_audit_candidate_hash")}}
    if any(value[name] != data for name, data in expected.items()):
        raise ProtocolError("authorization differs from immutable intent")


@dataclass(frozen=True, slots=True)
class CommitAuthorization:
    wire: bytes

    def __post_init__(self) -> None:
        _validate_authorization(self.wire, self.decision)

    @property
    def decision(self) -> str:
        return "COMMIT"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "CommitAuthorization":
        return cls(canonical_bytes(value))

    @classmethod
    def from_wire(cls, wire: bytes) -> "CommitAuthorization":
        return cls(wire)

    def validate_for(self, intent: MutationIntent) -> None:
        _authorization_for(self.wire, self.decision, intent)


@dataclass(frozen=True, slots=True)
class AbortAuthorization:
    wire: bytes

    def __post_init__(self) -> None:
        _validate_authorization(self.wire, self.decision)

    @property
    def decision(self) -> str:
        return "ABORT"

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AbortAuthorization":
        return cls(canonical_bytes(value))

    @classmethod
    def from_wire(cls, wire: bytes) -> "AbortAuthorization":
        return cls(wire)

    def validate_for(self, intent: MutationIntent) -> None:
        _authorization_for(self.wire, self.decision, intent)
