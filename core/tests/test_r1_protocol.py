from __future__ import annotations

from copy import deepcopy
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from app.control_plane.r1_protocol import (
    AuthorityPin,
    ExpectedIntent,
    PREPARE_PREFIX,
    ProtocolError,
    RECEIPT_PREFIX,
    canonical_bytes,
    decode_canonical_wire,
    genesis_head_seed,
    key_id,
    receipt_hash,
    request_envelope_hash,
    same_operation_envelope,
    sha256_hex,
    sign_prepare_ack,
    sign_terminal_receipt,
    verify_generation_opening,
    verify_prepare_ack,
    verify_prepare_ack_wire,
    verify_terminal_receipt,
    verify_terminal_receipt_wire,
)


def u(number: int) -> str:
    return str(UUID(int=number))


# RFC 8032 test vector 1; the seed is public test material, not a service key.
@pytest.fixture
def signer() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc4"
                                                           "4449c5697b326919703bac031cae7f60"))


@pytest.fixture
def pin(signer: Ed25519PrivateKey) -> AuthorityPin:
    return AuthorityPin(u(1), u(2), 1, signer.public_key(), key_id(signer.public_key()),
                        1, "https://authority.example", "a" * 64, "b" * 64)


@pytest.fixture
def envelope(pin: AuthorityPin) -> dict:
    return {
        "schema_version": 1,
        "authority_domain_id": pin.authority_domain_id,
        "authority_instance_id": pin.authority_instance_id,
        "authority_generation": 1,
        "qingyu_identity_id": u(3),
        "continuity_id": u(4),
        "operation_id": u(5),
        "operation_type": "AUTHORITY_GENESIS_ACTIVATION",
        "expected_continuity_epoch": 0,
        "expected_state_version": 0,
        "expected_owner_version": 0,
        "actor_or_owner_identity": "operator-root",
        "caller_runtime_id": u(6),
        "storage_generation_id": u(7),
        "payload": {"origin": "approved"},
        "reason": "genesis",
    }


def ack_unsigned(envelope: dict) -> dict:
    return {
        "ack_version": 1,
        **{field: envelope[field] for field in (
            "authority_domain_id", "authority_instance_id", "authority_generation",
            "qingyu_identity_id", "continuity_id", "operation_id", "operation_type",
            "caller_runtime_id", "storage_generation_id", "expected_continuity_epoch",
            "expected_owner_version", "expected_state_version")},
        "request_envelope_hash": request_envelope_hash(envelope),
        "staged_result_hash": "1" * 64,
        "core_audit_predecessor_hash": "2" * 64,
        "core_audit_candidate_hash": "3" * 64,
        "state": "PREPARED",
        "prepared_at": "2026-09-13T00:00:00Z",
    }


def local_intent(envelope: dict) -> ExpectedIntent:
    return ExpectedIntent(request_envelope_hash(envelope), "1" * 64, "2" * 64,
                          "3" * 64)


def receipt_unsigned(envelope: dict, predecessor: str, origin: str | None) -> dict:
    return {
        "receipt_version": 1,
        "schema_version": 1,
        **{field: envelope[field] for field in (
            "authority_domain_id", "authority_instance_id", "authority_generation",
            "qingyu_identity_id", "continuity_id", "operation_id", "operation_type",
            "actor_or_owner_identity", "storage_generation_id")},
        "request_envelope_hash": request_envelope_hash(envelope),
        "result_state": "COMMITTED",
        "result_code": "ACTIVATED",
        "continuity_epoch": 1,
        "control_plane_generation_id": u(8),
        "owner_version": 1,
        "lease_generation": None,
        "authority_sequence": 1,
        "previous_receipt_hash": predecessor,
        "result_payload_hash": "4" * 64,
        "staged_result_hash": "1" * 64,
        "core_audit_predecessor_hash": "2" * 64,
        "core_audit_candidate_hash": "3" * 64,
        "decided_at": "2026-09-13T00:00:01Z",
        "signed_provisioning_origin_digest": origin,
        "previous_generation": None,
        "previous_generation_sequence": None,
        "previous_generation_head_hash": None,
        "signed_dr_artifact_digest": None,
    }


def test_rfc8785_jcs_not_sorted_json() -> None:
    # RFC 8785 Appendix B number rendering and UTF-8 serialization behavior.
    assert canonical_bytes({"z": 1.0, "a": 1e-7, "ü": "é"}) == (
        b'{"a":1e-7,"z":1,"\xc3\xbc":"\xc3\xa9"}'
    )
    with pytest.raises(ProtocolError):
        canonical_bytes({"bad": float("nan")})


def test_rfc8032_vector(signer: Ed25519PrivateKey) -> None:
    expected = ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    signature = signer.sign(b"")
    assert signature.hex() == expected
    signer.public_key().verify(signature, b"")


def test_prepare_roundtrip_and_domain_separation(signer, pin, envelope) -> None:
    ack = sign_prepare_ack(ack_unsigned(envelope), signer)
    verify_prepare_ack(ack, envelope, pin, local_intent(envelope))
    with pytest.raises(InvalidSignature):
        signer.public_key().verify(bytes.fromhex(ack["ack_signature"]),
                                   RECEIPT_PREFIX + canonical_bytes({
                                       k: v for k, v in ack.items() if k != "ack_signature"}))
    tampered = deepcopy(ack)
    tampered["staged_result_hash"] = "f" * 64
    with pytest.raises(ProtocolError):
        verify_prepare_ack(tampered, envelope, pin, local_intent(envelope))
    tampered = deepcopy(ack)
    tampered["authority_generation"] = 2
    with pytest.raises(ProtocolError):
        verify_prepare_ack(tampered, envelope, pin, local_intent(envelope))
    tampered = deepcopy(ack)
    tampered["authority_sequence"] = 1
    with pytest.raises(ProtocolError):
        verify_prepare_ack(tampered, envelope, pin, local_intent(envelope))
    assert PREPARE_PREFIX != RECEIPT_PREFIX


def test_genesis_opening_and_chain(signer, pin, envelope) -> None:
    origin = "c" * 64
    seed = genesis_head_seed(authority_domain_id=pin.authority_domain_id,
                            authority_instance_id=pin.authority_instance_id,
                            provisioning_uuid=u(9), signed_provisioning_origin_digest=origin,
                            receipt_key_id=pin.receipt_key_id,
                            operator_root_key_id=pin.operator_root_key_id)
    receipt = sign_terminal_receipt(receipt_unsigned(envelope, seed, origin), signer)
    ack = sign_prepare_ack(ack_unsigned(envelope), signer)
    digest = verify_generation_opening(receipt, envelope, pin, local_intent(envelope),
                                       provisioning_uuid=u(9), signed_origin_hash=origin)
    assert digest == receipt_hash(receipt)
    assert len(digest) == 64
    verify_terminal_receipt(receipt, envelope, pin, local_intent(envelope), expected_sequence=1,
                            expected_previous_hash=seed, prepared_ack=ack)
    with pytest.raises(InvalidSignature):
        signer.public_key().verify(bytes.fromhex(receipt["receipt_signature"]),
                                   PREPARE_PREFIX + canonical_bytes({
                                       k: v for k, v in receipt.items()
                                       if k != "receipt_signature"}))
    with pytest.raises(ProtocolError):
        verify_terminal_receipt(receipt, envelope, pin, local_intent(envelope), expected_sequence=2,
                                expected_previous_hash=seed)
    with pytest.raises(ProtocolError):
        verify_generation_opening(receipt, envelope, pin, local_intent(envelope),
                                  provisioning_uuid=u(10), signed_origin_hash=origin)
    tampered = deepcopy(receipt)
    tampered["result_state"] = "ABORTED"
    with pytest.raises(ProtocolError):
        verify_generation_opening(tampered, envelope, pin, local_intent(envelope),
                                  provisioning_uuid=u(9), signed_origin_hash=origin)
    changed_ack = sign_prepare_ack(dict(ack_unsigned(envelope), staged_result_hash="f" * 64),
                                   signer)
    with pytest.raises(ProtocolError):
        verify_terminal_receipt(receipt, envelope, pin, local_intent(envelope), expected_sequence=1,
                                expected_previous_hash=seed, prepared_ack=changed_ack)
    with pytest.raises(ProtocolError):
        verify_terminal_receipt(dict(receipt, receipt_version=2), envelope, pin, local_intent(envelope),
                                expected_sequence=1, expected_previous_hash=seed)


def test_dr_opening_fences_generation_and_head(signer, pin, envelope) -> None:
    dr_pin = AuthorityPin(pin.authority_domain_id, u(12), 2, pin.receipt_public_key,
                          pin.receipt_key_id, 1, pin.https_origin,
                          pin.server_spki_sha256, pin.operator_root_key_id)
    dr_envelope = dict(envelope, authority_instance_id=u(12), authority_generation=2,
                       operation_type="AUTHORITY_DR_ACTIVATION")
    prior_head = "e" * 64
    unsigned = receipt_unsigned(dr_envelope, prior_head, None)
    unsigned.update(previous_generation=1, previous_generation_sequence=13,
                    previous_generation_head_hash=prior_head,
                    signed_dr_artifact_digest="d" * 64)
    receipt = sign_terminal_receipt(unsigned, signer)
    verify_generation_opening(receipt, dr_envelope, dr_pin, local_intent(dr_envelope), prior_generation=1,
                              prior_sequence=13, prior_head_hash=prior_head,
                              signed_dr_artifact_digest="d" * 64)
    with pytest.raises(ProtocolError):
        verify_generation_opening(receipt, dr_envelope, dr_pin, local_intent(dr_envelope), prior_generation=1,
                                  prior_sequence=12, prior_head_hash=prior_head,
                                  signed_dr_artifact_digest="d" * 64)
    with pytest.raises(ProtocolError):
        verify_generation_opening(receipt, dr_envelope, pin, local_intent(dr_envelope), prior_generation=1,
                                  prior_sequence=13, prior_head_hash=prior_head,
                                  signed_dr_artifact_digest="d" * 64)


def test_operation_id_envelope_binding(pin, envelope) -> None:
    digest = request_envelope_hash(envelope)
    assert same_operation_envelope(envelope["operation_id"], digest, envelope)
    changed = deepcopy(envelope)
    changed["payload"]["origin"] = "other"
    with pytest.raises(ProtocolError):
        same_operation_envelope(envelope["operation_id"], digest, changed)
    with pytest.raises(ProtocolError):
        request_envelope_hash(dict(envelope, unexpected=True))
    assert digest == sha256_hex(canonical_bytes(envelope))


def test_unknown_versions_and_wrong_key(signer, pin, envelope) -> None:
    ack = sign_prepare_ack(ack_unsigned(envelope), signer)
    with pytest.raises(ProtocolError):
        verify_prepare_ack(dict(ack, ack_version=2), envelope, pin, local_intent(envelope))
    wrong = Ed25519PrivateKey.generate()
    wrong_pin = AuthorityPin(pin.authority_domain_id, pin.authority_instance_id,
                             pin.authority_generation, wrong.public_key(),
                             key_id(wrong.public_key()), 1, pin.https_origin,
                             pin.server_spki_sha256, pin.operator_root_key_id)
    with pytest.raises(ProtocolError):
        verify_prepare_ack(ack, envelope, wrong_pin, local_intent(envelope))


def test_durable_intent_is_mandatory_and_not_ack_derived(signer, pin, envelope) -> None:
    ack = sign_prepare_ack(ack_unsigned(envelope), signer)
    wrong_intent = ExpectedIntent(request_envelope_hash(envelope), "f" * 64,
                                  "2" * 64, "3" * 64)
    with pytest.raises(ProtocolError):
        verify_prepare_ack(ack, envelope, pin, wrong_intent)
    with pytest.raises(TypeError):
        verify_prepare_ack(ack, envelope, pin)
    seed = genesis_head_seed(authority_domain_id=pin.authority_domain_id,
                            authority_instance_id=pin.authority_instance_id,
                            provisioning_uuid=u(9), signed_provisioning_origin_digest="c" * 64,
                            receipt_key_id=pin.receipt_key_id,
                            operator_root_key_id=pin.operator_root_key_id)
    receipt = sign_terminal_receipt(receipt_unsigned(envelope, seed, "c" * 64), signer)
    with pytest.raises(ProtocolError):
        verify_terminal_receipt(receipt, envelope, pin, wrong_intent,
                                expected_sequence=1, expected_previous_hash=seed)
    with pytest.raises(TypeError):
        verify_terminal_receipt(receipt, envelope, pin,
                                expected_sequence=1, expected_previous_hash=seed)


def test_terminal_storage_scope_and_opening_result(signer, pin, envelope) -> None:
    seed = genesis_head_seed(authority_domain_id=pin.authority_domain_id,
                            authority_instance_id=pin.authority_instance_id,
                            provisioning_uuid=u(9), signed_provisioning_origin_digest="c" * 64,
                            receipt_key_id=pin.receipt_key_id,
                            operator_root_key_id=pin.operator_root_key_id)
    unsigned = receipt_unsigned(envelope, seed, "c" * 64)
    wrong_storage = sign_terminal_receipt(dict(unsigned, storage_generation_id=u(55)), signer)
    with pytest.raises(ProtocolError):
        verify_terminal_receipt(wrong_storage, envelope, pin, local_intent(envelope),
                                expected_sequence=1, expected_previous_hash=seed)
    for changes in ({"result_state": "ABORTED"}, {"result_code": "DENIED"}):
        with pytest.raises(ProtocolError):
            sign_terminal_receipt(dict(unsigned, **changes), signer)


def test_strict_versions_and_canonical_wire(signer, pin, envelope) -> None:
    for bad in (True, 1.0, "1"):
        with pytest.raises(ProtocolError):
            request_envelope_hash(dict(envelope, schema_version=bad))
        with pytest.raises(ProtocolError):
            sign_prepare_ack(dict(ack_unsigned(envelope), ack_version=bad), signer)
    ack = sign_prepare_ack(ack_unsigned(envelope), signer)
    wire = canonical_bytes(ack)
    assert verify_prepare_ack_wire(wire, envelope, pin, local_intent(envelope)) == ack
    with pytest.raises(ProtocolError):
        decode_canonical_wire(b'{"a":1,"a":2}')
    with pytest.raises(ProtocolError):
        decode_canonical_wire(b'{"b":1,"a":2}')
    with pytest.raises(ProtocolError):
        decode_canonical_wire(b'{"a":NaN}')
    with pytest.raises(ProtocolError):
        decode_canonical_wire(b'\xff')
    with pytest.raises(ProtocolError):
        verify_prepare_ack_wire(b" " + wire, envelope, pin, local_intent(envelope))
    seed = genesis_head_seed(authority_domain_id=pin.authority_domain_id,
                            authority_instance_id=pin.authority_instance_id,
                            provisioning_uuid=u(9), signed_provisioning_origin_digest="c" * 64,
                            receipt_key_id=pin.receipt_key_id,
                            operator_root_key_id=pin.operator_root_key_id)
    receipt = sign_terminal_receipt(receipt_unsigned(envelope, seed, "c" * 64), signer)
    assert verify_terminal_receipt_wire(canonical_bytes(receipt), envelope, pin,
                                        local_intent(envelope), expected_sequence=1,
                                        expected_previous_hash=seed) == receipt_hash(receipt)
    for bad in (True, 1.0, "1"):
        with pytest.raises(ProtocolError):
            sign_terminal_receipt(dict(receipt_unsigned(envelope, seed, "c" * 64),
                                       receipt_version=bad), signer)


def test_https_origin_authority_is_canonical(pin) -> None:
    from dataclasses import replace

    for origin in (
        "https://authority.example:bad", "https://authority.example:",
        "https://authority.example:0", "https://authority.example:65536",
        "https://authority.example:443:444", "https://authority.example/path",
        "https://user@authority.example", "https://authority.example?x=1",
        "https://authority.example.", "https://AUTHORITY.example",
        "https://authority example", "https://[::1]:bad", "https://[::1",
        "https://[fe80::1%25eth0]",
        "http://authority.example", " https://authority.example",
    ):
        with pytest.raises(ProtocolError):
            replace(pin, https_origin=origin).validate()
    for origin in ("https://authority.example", "https://authority.example:443",
                   "https://[::1]", "https://[::1]:8443"):
        replace(pin, https_origin=origin).validate()
