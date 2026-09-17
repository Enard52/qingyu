"""V2 Ed25519 verification against explicitly supplied fixed trust.

This module performs no provisioning, trust discovery, signing, I/O, or current
authorization.  A successful signature does not establish the object's semantic
bindings, complete trustworthy history, or an actor's right to execute an action.
The caller must obtain FixedTrust from its protected configuration boundary,
never from the evidence being verified.  V1 retains its original verifier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .r1_validation_codec import ContractError, c2, decode, h2, s2, sha, validate


# A type's signer is contractual, never selected by a body's key ID or fields.
_SIGNERS = MappingProxyType({
    "abort_override": "ROOT",
    "opening_authorization": "ROOT",
    "recovery_policy": "ROOT",
    "restoration_context": "ROOT",
    "execution_grant": "RECEIPT",
    "local_finish_permit": "RECEIPT",
    "opening_prepare": "RECEIPT",
    "opening_receipt": "RECEIPT",
    "prepare_ack": "RECEIPT",
    "terminal_receipt": "RECEIPT",
})


@dataclass(frozen=True, slots=True)
class FixedTrust:
    """Public material injected by an independently trusted configuration owner.

    Construction verifies internal consistency, not the provenance or continuing
    trustworthiness of this configuration.  Pin/public-key rotation and live
    trust admission are deliberately absent.  The canonical pin is stored as
    immutable bytes; ``pin`` returns a new object on each access.
    """

    pin_wire: bytes = field(repr=False)
    root_public_key: bytes = field(repr=False)
    receipt_key_id: str = field(init=False)
    operator_root_key_id: str = field(init=False)
    pin_digest: str = field(init=False)
    _receipt_key: Ed25519PublicKey = field(init=False, repr=False, compare=False)
    _root_key: Ed25519PublicKey = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if type(self.pin_wire) is not bytes:
            raise ContractError("fixed pin must be original canonical V2 bytes")
        if type(self.root_public_key) is not bytes or len(self.root_public_key) != 32:
            raise ContractError("fixed Root public key must be raw32 bytes")
        pin = decode(self.pin_wire)
        validate(pin)
        if pin["type"] != "authority_pin":
            raise ContractError("fixed trust requires an authority_pin")
        receipt_public = bytes.fromhex(pin["receipt_public_key"])
        if sha(receipt_public) != pin["receipt_key_id"]:
            raise ContractError("fixed receipt public key does not match its key ID")
        if sha(self.root_public_key) != pin["operator_root_key_id"]:
            raise ContractError("fixed Root public key does not match its key ID")
        object.__setattr__(self, "receipt_key_id", pin["receipt_key_id"])
        object.__setattr__(self, "operator_root_key_id", pin["operator_root_key_id"])
        object.__setattr__(self, "pin_digest", h2(pin))
        object.__setattr__(self, "_receipt_key", Ed25519PublicKey.from_public_bytes(receipt_public))
        object.__setattr__(self, "_root_key", Ed25519PublicKey.from_public_bytes(self.root_public_key))

    @property
    def pin(self) -> dict:
        return decode(self.pin_wire)


@dataclass(frozen=True, slots=True)
class VerifiedSignature:
    """Signature-only evidence bound to the complete signed object's digest.

    This is a descriptive return value, not an admission/authorization token and
    must not substitute for semantic verification at another entry point.
    """

    object_type: str
    signer_role: Literal["ROOT", "RECEIPT"]
    key_id: str
    object_digest: str
    signing_input_digest: str


def verify_signed(value: dict | bytes, trust: FixedTrust) -> VerifiedSignature:
    """Verify exactly one supported V2 signed body using its fixed signer role.

    Bytes must already be canonical C2; dictionaries are snapshotted through C2
    before verification.  Only the single contractual signature field is omitted
    from S2.  No timestamp is compared to wall time: historical validity and
    current execution qualification are separate callers' responsibilities.
    """
    if type(trust) is not FixedTrust:
        raise ContractError("an explicit FixedTrust configuration is required")
    if type(value) is bytes:
        body = decode(value)
    elif type(value) is dict:
        body = decode(c2(value))
    else:
        raise ContractError("signed evidence must be a V2 object or original C2 bytes")
    validate(body)
    role = _SIGNERS.get(body["type"])
    if role is None:
        raise ContractError("unsupported signed V2 type")
    if role == "ROOT":
        signature_field, id_field = "root_signature", "operator_root_key_id"
        key, expected_id = trust._root_key, trust.operator_root_key_id
    else:
        signature_field, id_field = "receipt_signature", "receipt_key_id"
        key, expected_id = trust._receipt_key, trust.receipt_key_id
    if body[id_field] != expected_id:
        raise ContractError("signed key ID does not match its fixed signer role")
    signing_input = s2(body)
    try:
        key.verify(bytes.fromhex(body[signature_field]), signing_input)
    except InvalidSignature as exc:
        raise ContractError("invalid V2 Ed25519 signature") from exc
    return VerifiedSignature(
        object_type=body["type"],
        signer_role=role,
        key_id=expected_id,
        object_digest=h2(body),
        signing_input_digest=sha(signing_input),
    )
