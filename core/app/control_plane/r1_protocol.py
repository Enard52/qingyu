"""Canonical, fail-closed R1 Authority wire primitives.

This module handles bytes, signatures and chain verification only. It does not
issue authority, validate TLS, persist a ledger, or manage private keys.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Any, Mapping
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
import rfc8785


RECEIPT_PREFIX = b"QINGYU-CP-R1-AUTHORITY-RECEIPT\x00"
PREPARE_PREFIX = b"QINGYU-CP-R1-PREPARE-ACK\x00"
GENESIS_PREFIX = b"QINGYU-CP-R1-GENESIS-HEAD\x00"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX128 = re.compile(r"[0-9a-f]{128}\Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")

REQUEST_FIELDS = frozenset({
    "schema_version", "authority_domain_id", "authority_instance_id",
    "authority_generation", "qingyu_identity_id", "continuity_id",
    "operation_id", "operation_type", "expected_continuity_epoch",
    "expected_state_version", "expected_owner_version", "actor_or_owner_identity",
    "caller_runtime_id", "storage_generation_id", "payload", "reason",
})
PREPARE_FIELDS = frozenset({
    "ack_version", "authority_domain_id", "authority_instance_id",
    "authority_generation", "qingyu_identity_id", "continuity_id",
    "operation_id", "operation_type", "request_envelope_hash",
    "caller_runtime_id", "storage_generation_id", "expected_continuity_epoch",
    "expected_owner_version", "expected_state_version", "staged_result_hash",
    "core_audit_predecessor_hash", "core_audit_candidate_hash", "state",
    "prepared_at", "receipt_key_id", "ack_signature",
})
RECEIPT_FIELDS = frozenset({
    "receipt_version", "schema_version", "authority_domain_id",
    "authority_instance_id", "authority_generation", "qingyu_identity_id",
    "continuity_id", "operation_id", "operation_type",
    "request_envelope_hash", "result_state", "result_code",
    "actor_or_owner_identity", "continuity_epoch", "storage_generation_id",
    "control_plane_generation_id", "owner_version", "lease_generation",
    "authority_sequence", "previous_receipt_hash", "result_payload_hash",
    "staged_result_hash", "core_audit_predecessor_hash",
    "core_audit_candidate_hash", "decided_at", "receipt_key_id",
    "signed_provisioning_origin_digest", "previous_generation",
    "previous_generation_sequence", "previous_generation_head_hash",
    "signed_dr_artifact_digest", "receipt_signature",
})


class ProtocolError(ValueError):
    """Untrusted protocol input failed closed."""


def _exact(value: Mapping[str, Any], fields: frozenset[str]) -> None:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProtocolError("unknown or missing protocol fields")


def _uuid(value: Any) -> None:
    try:
        valid = isinstance(value, str) and str(UUID(value)) == value
    except ValueError:
        valid = False
    if not valid:
        raise ProtocolError("non-canonical UUID")


def _hash(value: Any) -> None:
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ProtocolError("invalid SHA-256 digest")


def _positive(value: Any) -> None:
    if type(value) is not int or value < 1:
        raise ProtocolError("invalid positive integer")


def _nonnegative(value: Any) -> None:
    if type(value) is not int or value < 0:
        raise ProtocolError("invalid nonnegative integer")


def canonical_bytes(value: Any) -> bytes:
    """RFC 8785 JCS UTF-8, never Python's sorted JSON approximation."""
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, TypeError, ValueError) as exc:
        raise ProtocolError("non-canonical JSON value") from exc


def decode_canonical_wire(raw: bytes) -> Any:
    """Decode an API body without losing duplicate keys or non-JCS wire bytes."""
    if not isinstance(raw, bytes):
        raise ProtocolError("wire body must be bytes")

    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for name, item in pairs:
            if name in value:
                raise ProtocolError("duplicate JSON key")
            value[name] = item
        return value

    try:
        value = json.loads(raw.decode("utf-8", errors="strict"),
                           object_pairs_hook=reject_duplicates,
                           parse_constant=lambda _name: (_ for _ in ()).throw(
                               ProtocolError("non-JSON number")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid UTF-8 JSON wire body") from exc
    if canonical_bytes(value) != raw:
        raise ProtocolError("non-canonical JSON wire body")
    return value


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return sha256_hex(raw)


@dataclass(frozen=True, slots=True)
class AuthorityPin:
    authority_domain_id: str
    authority_instance_id: str
    authority_generation: int
    receipt_public_key: Ed25519PublicKey
    receipt_key_id: str
    api_version: int
    https_origin: str
    server_spki_sha256: str
    operator_root_key_id: str

    def validate(self) -> None:
        _uuid(self.authority_domain_id)
        _uuid(self.authority_instance_id)
        _positive(self.authority_generation)
        _positive(self.api_version)
        _hash(self.receipt_key_id)
        _hash(self.server_spki_sha256)
        _hash(self.operator_root_key_id)
        if self.receipt_key_id != key_id(self.receipt_public_key):
            raise ProtocolError("receipt key pin mismatch")
        try:
            origin = urlsplit(self.https_origin)
            host = origin.hostname
            port = origin.port  # urllib raises on nonnumeric/out-of-range ports.
        except (ValueError, TypeError) as exc:
            raise ProtocolError("invalid HTTPS origin") from exc
        if (origin.scheme != "https" or not host or origin.username
                or origin.password or origin.path or origin.query or origin.fragment
                or origin.netloc.endswith(":")
                or self.https_origin != f"https://{origin.netloc}"):
            raise ProtocolError("invalid HTTPS origin")
        if host.count(":"):
            if "%" in host:
                raise ProtocolError("scoped IPv6 origin is unsupported")
            try:
                if str(ipaddress.IPv6Address(host)) != host:
                    raise ProtocolError("non-canonical IPv6 origin")
            except ValueError as exc:
                raise ProtocolError("invalid IPv6 origin") from exc
            expected_netloc = f"[{host}]" + (f":{port}" if port is not None else "")
        else:
            labels = host.split(".")
            if not all(_DNS_LABEL.fullmatch(label) for label in labels):
                raise ProtocolError("invalid DNS origin")
            expected_netloc = host + (f":{port}" if port is not None else "")
        if (port is not None and not 1 <= port <= 65535) or origin.netloc != expected_netloc:
            raise ProtocolError("non-canonical HTTPS origin authority")


@dataclass(frozen=True, slots=True)
class ExpectedIntent:
    """Frozen local INTENT values, loaded from durable Core state, never Ack input."""

    request_envelope_hash: str
    staged_result_hash: str
    core_audit_predecessor_hash: str
    core_audit_candidate_hash: str

    def validate(self, envelope: Mapping[str, Any]) -> None:
        for field in ("request_envelope_hash", "staged_result_hash",
                      "core_audit_predecessor_hash", "core_audit_candidate_hash"):
            _hash(getattr(self, field))
        if self.request_envelope_hash != request_envelope_hash(envelope):
            raise ProtocolError("local INTENT request digest mismatch")

    def check(self, signed_value: Mapping[str, Any], envelope: Mapping[str, Any]) -> None:
        self.validate(envelope)
        for field in ("request_envelope_hash", "staged_result_hash",
                      "core_audit_predecessor_hash", "core_audit_candidate_hash"):
            if signed_value[field] != getattr(self, field):
                raise ProtocolError("signed value differs from durable local INTENT")


def _identity(value: Mapping[str, Any], pin: AuthorityPin) -> None:
    pin.validate()
    if (
        value["authority_domain_id"] != pin.authority_domain_id
        or value["authority_instance_id"] != pin.authority_instance_id
        or value["authority_generation"] != pin.authority_generation
        or value["receipt_key_id"] != pin.receipt_key_id
    ):
        raise ProtocolError("Authority tuple mismatch")
    _uuid(value["qingyu_identity_id"])
    _uuid(value["continuity_id"])
    _uuid(value["operation_id"])


def _validate_common_identity(value: Mapping[str, Any]) -> None:
    for field in ("authority_domain_id", "authority_instance_id",
                  "qingyu_identity_id", "continuity_id", "operation_id"):
        _uuid(value[field])
    _positive(value["authority_generation"])
    _hash(value["receipt_key_id"])
    if not isinstance(value["operation_type"], str) or not value["operation_type"]:
        raise ProtocolError("missing operation type")


def request_envelope_hash(envelope: Mapping[str, Any]) -> str:
    _exact(envelope, REQUEST_FIELDS)
    if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1:
        raise ProtocolError("unsupported request schema")
    for field in ("authority_domain_id", "authority_instance_id",
                  "qingyu_identity_id", "continuity_id", "operation_id",
                  "caller_runtime_id", "storage_generation_id"):
        _uuid(envelope[field])
    for field in ("authority_generation", "expected_continuity_epoch",
                  "expected_state_version", "expected_owner_version"):
        (_positive if field == "authority_generation" else _nonnegative)(envelope[field])
    if not isinstance(envelope["operation_type"], str) or not envelope["operation_type"]:
        raise ProtocolError("empty operation type")
    if not isinstance(envelope["actor_or_owner_identity"], str) or not envelope["actor_or_owner_identity"]:
        raise ProtocolError("empty actor identity")
    if not isinstance(envelope["reason"], str) or not isinstance(envelope["payload"], Mapping):
        raise ProtocolError("invalid request payload")
    return sha256_hex(canonical_bytes(envelope))


def same_operation_envelope(stored_operation_id: str, stored_hash: str,
                            envelope: Mapping[str, Any]) -> bool:
    """Reject an operation-ID collision; never interpret it as a retry."""
    digest = request_envelope_hash(envelope)
    _hash(stored_hash)
    if envelope["operation_id"] != stored_operation_id or digest != stored_hash:
        raise ProtocolError("operation ID reused with a different envelope")
    return True


def _signed_payload(value: Mapping[str, Any], signature_field: str) -> dict[str, Any]:
    return {k: v for k, v in value.items() if k != signature_field}


def _verify_signature(value: Mapping[str, Any], field: str, prefix: bytes,
                      public_key: Ed25519PublicKey) -> None:
    signature = value[field]
    if not isinstance(signature, str) or not _HEX128.fullmatch(signature):
        raise ProtocolError("invalid signature encoding")
    try:
        public_key.verify(bytes.fromhex(signature),
                          prefix + canonical_bytes(_signed_payload(value, field)))
    except InvalidSignature as exc:
        raise ProtocolError("invalid Authority signature") from exc


def _sign(value: Mapping[str, Any], field: str, prefix: bytes,
          private_key: Ed25519PrivateKey) -> dict[str, Any]:
    result = dict(value)
    result["receipt_key_id"] = key_id(private_key.public_key())
    result[field] = private_key.sign(
        prefix + canonical_bytes(_signed_payload(result, field))
    ).hex()
    return result


def _matching_request(value: Mapping[str, Any], envelope: Mapping[str, Any]) -> None:
    if value["request_envelope_hash"] != request_envelope_hash(envelope):
        raise ProtocolError("request digest mismatch")
    for field in ("authority_domain_id", "authority_instance_id",
                  "authority_generation", "qingyu_identity_id", "continuity_id",
                  "operation_id", "operation_type"):
        if value[field] != envelope[field]:
            raise ProtocolError("request scope mismatch")


def sign_prepare_ack(unsigned: Mapping[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    if set(unsigned) != PREPARE_FIELDS - {"receipt_key_id", "ack_signature"}:
        raise ProtocolError("invalid PrepareAck fields")
    result = _sign(unsigned, "ack_signature", PREPARE_PREFIX, private_key)
    _validate_prepare(result)
    return result


def _validate_prepare(ack: Mapping[str, Any]) -> None:
    _exact(ack, PREPARE_FIELDS)
    _validate_common_identity(ack)
    if type(ack["ack_version"]) is not int or ack["ack_version"] != 1 or ack["state"] != "PREPARED":
        raise ProtocolError("unsupported PrepareAck")
    for field in ("request_envelope_hash", "staged_result_hash",
                  "core_audit_predecessor_hash", "core_audit_candidate_hash"):
        _hash(ack[field])
    for field in ("caller_runtime_id", "storage_generation_id"):
        _uuid(ack[field])
    for field in ("expected_continuity_epoch", "expected_owner_version",
                  "expected_state_version"):
        _nonnegative(ack[field])
    if not isinstance(ack["prepared_at"], str) or not ack["prepared_at"]:
        raise ProtocolError("missing prepare timestamp")


def verify_prepare_ack(ack: Mapping[str, Any], envelope: Mapping[str, Any],
                       pin: AuthorityPin, expected_intent: ExpectedIntent) -> None:
    _validate_prepare(ack)
    _identity(ack, pin)
    _matching_request(ack, envelope)
    expected_intent.check(ack, envelope)
    for source, target in (("caller_runtime_id", "caller_runtime_id"),
                           ("storage_generation_id", "storage_generation_id"),
                           ("expected_continuity_epoch", "expected_continuity_epoch"),
                           ("expected_owner_version", "expected_owner_version"),
                           ("expected_state_version", "expected_state_version")):
        if ack[source] != envelope[target]:
            raise ProtocolError("PrepareAck request mismatch")
    _verify_signature(ack, "ack_signature", PREPARE_PREFIX, pin.receipt_public_key)


def verify_prepare_ack_wire(raw: bytes, envelope: Mapping[str, Any],
                            pin: AuthorityPin, expected_intent: ExpectedIntent) -> Mapping[str, Any]:
    ack = decode_canonical_wire(raw)
    verify_prepare_ack(ack, envelope, pin, expected_intent)
    return ack


def sign_terminal_receipt(unsigned: Mapping[str, Any],
                          private_key: Ed25519PrivateKey) -> dict[str, Any]:
    if set(unsigned) != RECEIPT_FIELDS - {"receipt_key_id", "receipt_signature"}:
        raise ProtocolError("invalid terminal receipt fields")
    result = _sign(unsigned, "receipt_signature", RECEIPT_PREFIX, private_key)
    _validate_receipt(result)
    return result


def _validate_receipt(receipt: Mapping[str, Any]) -> None:
    _exact(receipt, RECEIPT_FIELDS)
    _validate_common_identity(receipt)
    if (type(receipt["receipt_version"]) is not int or receipt["receipt_version"] != 1
            or type(receipt["schema_version"]) is not int or receipt["schema_version"] != 1):
        raise ProtocolError("unsupported receipt version")
    if receipt["result_state"] not in ("COMMITTED", "ABORTED"):
        raise ProtocolError("non-terminal receipt")
    for field in ("request_envelope_hash", "previous_receipt_hash",
                  "result_payload_hash", "staged_result_hash",
                  "core_audit_predecessor_hash", "core_audit_candidate_hash"):
        _hash(receipt[field])
    for field in ("storage_generation_id", "control_plane_generation_id"):
        _uuid(receipt[field])
    for field in ("continuity_epoch", "owner_version", "authority_sequence"):
        _positive(receipt[field])
    if receipt["lease_generation"] is not None:
        _positive(receipt["lease_generation"])
    for field in ("result_code", "actor_or_owner_identity", "decided_at"):
        if not isinstance(receipt[field], str) or not receipt[field]:
            raise ProtocolError("missing receipt value")
    for field in ("signed_provisioning_origin_digest", "previous_generation_head_hash",
                  "signed_dr_artifact_digest"):
        if receipt[field] is not None:
            _hash(receipt[field])
    if receipt["previous_generation"] is not None:
        _positive(receipt["previous_generation"])
    if receipt["previous_generation_sequence"] is not None:
        _positive(receipt["previous_generation_sequence"])
    opening = receipt["authority_sequence"] == 1
    if not opening and any(receipt[field] is not None for field in (
            "signed_provisioning_origin_digest", "previous_generation",
            "previous_generation_sequence", "previous_generation_head_hash",
            "signed_dr_artifact_digest")):
        raise ProtocolError("non-opening receipt carries generation transition")
    if opening and receipt["authority_generation"] == 1:
        if (receipt["operation_type"] != "AUTHORITY_GENESIS_ACTIVATION"
                or receipt["result_state"] != "COMMITTED"
                or receipt["result_code"] != "ACTIVATED"
                or receipt["signed_provisioning_origin_digest"] is None
                or any(receipt[field] is not None for field in (
                    "previous_generation", "previous_generation_sequence",
                    "previous_generation_head_hash", "signed_dr_artifact_digest"))):
            raise ProtocolError("invalid genesis opening")
    if opening and receipt["authority_generation"] > 1:
        if (receipt["operation_type"] != "AUTHORITY_DR_ACTIVATION"
                or receipt["result_state"] != "COMMITTED"
                or receipt["result_code"] != "ACTIVATED"
                or receipt["signed_provisioning_origin_digest"] is not None
                or receipt["previous_generation"] != receipt["authority_generation"] - 1
                or any(receipt[field] is None for field in (
                    "previous_generation_sequence", "previous_generation_head_hash",
                    "signed_dr_artifact_digest"))):
            raise ProtocolError("invalid DR opening")


def receipt_hash(receipt: Mapping[str, Any]) -> str:
    _validate_receipt(receipt)
    return sha256_hex(RECEIPT_PREFIX + canonical_bytes(receipt))


def verify_terminal_receipt(receipt: Mapping[str, Any], envelope: Mapping[str, Any],
                            pin: AuthorityPin, expected_intent: ExpectedIntent, *, expected_sequence: int,
                            expected_previous_hash: str,
                            prepared_ack: Mapping[str, Any] | None = None) -> str:
    _validate_receipt(receipt)
    _identity(receipt, pin)
    _matching_request(receipt, envelope)
    expected_intent.check(receipt, envelope)
    _positive(expected_sequence)
    _hash(expected_previous_hash)
    if (receipt["authority_sequence"] != expected_sequence
            or receipt["previous_receipt_hash"] != expected_previous_hash):
        raise ProtocolError("Authority chain gap, fork or rollback")
    if receipt["actor_or_owner_identity"] != envelope["actor_or_owner_identity"]:
        raise ProtocolError("actor mismatch")
    if receipt["storage_generation_id"] != envelope["storage_generation_id"]:
        raise ProtocolError("storage generation scope mismatch")
    if prepared_ack is not None:
        verify_prepare_ack(prepared_ack, envelope, pin, expected_intent)
        for field in ("staged_result_hash", "core_audit_predecessor_hash",
                      "core_audit_candidate_hash"):
            if receipt[field] != prepared_ack[field]:
                raise ProtocolError("terminal receipt changed frozen prepared value")
    _verify_signature(receipt, "receipt_signature", RECEIPT_PREFIX, pin.receipt_public_key)
    return receipt_hash(receipt)


def verify_terminal_receipt_wire(raw: bytes, envelope: Mapping[str, Any],
                                 pin: AuthorityPin, expected_intent: ExpectedIntent, *,
                                 expected_sequence: int, expected_previous_hash: str,
                                 prepared_ack: Mapping[str, Any] | None = None) -> str:
    receipt = decode_canonical_wire(raw)
    return verify_terminal_receipt(receipt, envelope, pin, expected_intent,
                                   expected_sequence=expected_sequence,
                                   expected_previous_hash=expected_previous_hash,
                                   prepared_ack=prepared_ack)


def genesis_head_seed(*, authority_domain_id: str, authority_instance_id: str,
                      provisioning_uuid: str, signed_provisioning_origin_digest: str,
                      receipt_key_id: str, operator_root_key_id: str) -> str:
    """Hash an already verified signed origin; this is not provenance proof.

    R1-2 must verify both signed envelopes against the pinned operator
    root before supplying their digest. This module intentionally provides no
    raw-envelope-to-origin-digest shortcut.
    """
    for value in (authority_domain_id, authority_instance_id, provisioning_uuid):
        _uuid(value)
    for value in (signed_provisioning_origin_digest, receipt_key_id, operator_root_key_id):
        _hash(value)
    return sha256_hex(GENESIS_PREFIX + canonical_bytes({
        "authority_domain_id": authority_domain_id,
        "authority_instance_id": authority_instance_id,
        "authority_generation": 1,
        "provisioning_uuid": provisioning_uuid,
        "signed_provisioning_origin_digest": signed_provisioning_origin_digest,
        "receipt_key_id": receipt_key_id,
        "operator_root_key_id": operator_root_key_id,
    }))


def verify_generation_opening(receipt: Mapping[str, Any], envelope: Mapping[str, Any],
                              pin: AuthorityPin, expected_intent: ExpectedIntent, *,
                              provisioning_uuid: str | None = None,
                              signed_origin_hash: str | None = None,
                              prior_generation: int | None = None,
                              prior_sequence: int | None = None,
                              prior_head_hash: str | None = None,
                              signed_dr_artifact_digest: str | None = None) -> str:
    """Verify sequence-1 activation and its explicit genesis/DR predecessor."""
    _validate_receipt(receipt)
    if pin.authority_generation == 1:
        if provisioning_uuid is None or signed_origin_hash is None:
            raise ProtocolError("missing signed genesis origin")
        if receipt["operation_type"] != "AUTHORITY_GENESIS_ACTIVATION":
            raise ProtocolError("wrong genesis operation")
        if (receipt["signed_provisioning_origin_digest"] != signed_origin_hash
                or any(receipt[field] is not None for field in (
                    "previous_generation", "previous_generation_sequence",
                    "previous_generation_head_hash", "signed_dr_artifact_digest"))):
            raise ProtocolError("genesis opening mismatch")
        predecessor = genesis_head_seed(
            authority_domain_id=pin.authority_domain_id,
            authority_instance_id=pin.authority_instance_id,
            provisioning_uuid=provisioning_uuid,
            signed_provisioning_origin_digest=signed_origin_hash,
            receipt_key_id=pin.receipt_key_id,
            operator_root_key_id=pin.operator_root_key_id,
        )
    else:
        if (prior_generation is None or prior_sequence is None or prior_head_hash is None
                or signed_dr_artifact_digest is None):
            raise ProtocolError("missing verified DR predecessor")
        _positive(prior_generation)
        _positive(prior_sequence)
        _hash(prior_head_hash)
        _hash(signed_dr_artifact_digest)
        if (prior_generation != pin.authority_generation - 1
                or receipt["operation_type"] != "AUTHORITY_DR_ACTIVATION"
                or receipt["signed_provisioning_origin_digest"] is not None
                or receipt["previous_generation"] != prior_generation
                or receipt["previous_generation_sequence"] != prior_sequence
                or receipt["previous_generation_head_hash"] != prior_head_hash
                or receipt["signed_dr_artifact_digest"] != signed_dr_artifact_digest):
            raise ProtocolError("DR opening mismatch")
        predecessor = prior_head_hash
    return verify_terminal_receipt(receipt, envelope, pin, expected_intent, expected_sequence=1,
                                   expected_previous_hash=predecessor)
