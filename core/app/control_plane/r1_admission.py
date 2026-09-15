"""Public verification and independent deployment admission; never Root signing.

Inspectors are trusted deployment components, not HTTP inputs. No default
inspector, synthetic origin, secret provider or permissive readiness flag exists.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from cryptography.hazmat.primitives import serialization

from .r1_candidate_schema import F3_CONTRACT_VERSION, F3_SCHEMA_DIGEST
from .r1_protocol import AuthorityPin, ExpectedIntent, ProtocolError, canonical_bytes, decode_canonical_wire, key_id, verify_generation_opening, verify_prepare_ack
from .r1_provisioning import (ObservedInitialState, VerifiedOrigin, verify_initial_migration_attestation,
    verify_signed_origin_wire, _verify_envelope, _exact, _timestamp, _ATTESTATION,
    INITIAL_ATTESTATION_PREFIX, INITIAL_REVISION)
from .r1_root_pin import OperatorRootPin, RootTrustSource, load_operator_root_pin, PRODUCTION, ACCEPTANCE_TEST_ONLY, RootPinError


class AdmissionError(RuntimeError):
    pass


def verify_canonical_root(public: "VerifiedCoreAdmission", *, profile: str, source: RootTrustSource | None = None) -> None:
    """Supported factory gate. Source is deployment code/test injection, never wire/config imports."""
    try:
        root = load_operator_root_pin(profile, source=source)
    except RootPinError:
        raise AdmissionError("canonical machine Root public pin unavailable") from None
    expected = public.root
    if (root.profile != expected.profile or root.test_only != expected.test_only
            or root.key_id != expected.key_id or key_id(root.public_key) != key_id(expected.public_key)):
        raise AdmissionError("admission Root differs from canonical machine public pin")


def verify_public_attestation(origin: VerifiedOrigin, wire: bytes, root: OperatorRootPin) -> None:
    """Verify signed claims only. Never construct an independently observed type."""
    p = _exact(_verify_envelope(decode_canonical_wire(wire), root.public_key,
                               INITIAL_ATTESTATION_PREFIX)["payload"], _ATTESTATION)
    expected = {
        "provisioning_uuid": origin.intent["provisioning_uuid"],
        "signed_provisioning_origin_digest": origin.signed_provisioning_origin_digest,
        "canonical_initial_revision": INITIAL_REVISION,
        "fingerprint_version": origin.intent["expected_fingerprint_version"],
        "schema_fingerprint": origin.intent["expected_schema_fingerprint"],
        "initial_migration_artifact_digest": origin.intent["initial_migration_artifact_digest"],
        "database_name": origin.intent["database_name"],
        "server_system_identifier": origin.completion["server_system_identifier"],
        "cluster_binding_fingerprint": origin.completion["cluster_binding_fingerprint"],
        "authority_domain_id": origin.intent["authority_domain_id"],
        "authority_instance_id": origin.intent["authority_instance_id"],
        "authority_generation": 1, "receipt_key_id": origin.completion["receipt_key_id"],
        "test_only": origin.intent["test_only"],
    }
    _timestamp(p["observed_at"])
    from datetime import datetime
    if (any(p[name] != value for name, value in expected.items())
            or datetime.fromisoformat(p["observed_at"]) < datetime.fromisoformat(origin.completion["creation_event_timestamp"])):
        raise AdmissionError("public attestation differs from signed origin")


class DeploymentInspector(Protocol):
    def observe_initial_state(self) -> ObservedInitialState: ...
    def verify_runtime_prerequisites(self, origin: VerifiedOrigin, pin: AuthorityPin) -> None:
        """Check actual catalog/ACL, frozen release/dependencies, TLS and secret custody.

        Raise if any required observation is absent. This is an independent
        inspection contract, not an assertion supplied by a signed manifest.
        """
        ...


@dataclass(frozen=True, slots=True)
class VerifiedCoreAdmission:
    """Only public trust evidence; Core has no Authority inspector or secret."""
    pin: AuthorityPin
    root: OperatorRootPin
    intent_wire: bytes
    completion_wire: bytes
    attestation_wire: bytes

    def __post_init__(self) -> None:
        self.pin.validate()
        if (self.root.key_id != key_id(self.root.public_key)
                or self.root.profile not in (PRODUCTION, ACCEPTANCE_TEST_ONLY)
                or type(self.root.test_only) is not bool
                or self.root.test_only != (self.root.profile == ACCEPTANCE_TEST_ONLY)):
            raise AdmissionError("invalid public Root identity/profile")
        origin = self.origin
        p, c = origin.intent, origin.completion
        if (self.root.key_id != self.pin.operator_root_key_id
                or self.root.test_only != p["test_only"]
                or self.pin.authority_domain_id != p["authority_domain_id"]
                or self.pin.authority_instance_id != p["authority_instance_id"]
                or self.pin.authority_generation != p["authority_generation"]
                or self.pin.https_origin != c["observed_tls_origin"]
                or self.pin.receipt_key_id != c["receipt_key_id"]
                or self.pin.receipt_key_id == self.root.key_id):
            raise AdmissionError("public deployment trust binding mismatch")
        verify_public_attestation(origin, self.attestation_wire, self.root)

    @property
    def origin(self) -> VerifiedOrigin:
        return verify_signed_origin_wire(self.intent_wire, self.completion_wire, self.root.public_key)


@dataclass(frozen=True, slots=True)
class AuthorityAdmission:
    public: VerifiedCoreAdmission
    inspector: DeploymentInspector

    def __post_init__(self) -> None:
        if not isinstance(self.public, VerifiedCoreAdmission) or self.inspector is None:
            raise AdmissionError("independent deployment admission required")
        self.verify()

    def verify(self) -> None:
        origin = self.public.origin
        observed = self.inspector.observe_initial_state()
        verify_initial_migration_attestation(origin, decode_canonical_wire(self.public.attestation_wire),
                                             self.public.root.public_key, observed)
        self.inspector.verify_runtime_prerequisites(origin, self.public.pin)

    def check_store(self, description: Mapping[str, Any]) -> None:
        self.verify()
        pin, origin = self.public.pin, self.public.origin
        expected = {
            "f3_contract_digest": F3_SCHEMA_DIGEST, "f3_contract_version": F3_CONTRACT_VERSION,
            "authority_domain_id": pin.authority_domain_id,
            "authority_instance_id": pin.authority_instance_id,
            "authority_generation": pin.authority_generation,
            "receipt_key_id": pin.receipt_key_id, "generation_status": "ACTIVE",
            "receipt_key_revoked_at": None, "operator_root_key_id": pin.operator_root_key_id,
            "provisioning_uuid": origin.intent["provisioning_uuid"],
            "signed_provisioning_origin_digest": origin.signed_provisioning_origin_digest,
            "database_name": origin.intent["database_name"],
            "cluster_system_identifier": origin.completion["server_system_identifier"],
            "cluster_binding_fingerprint": origin.completion["cluster_binding_fingerprint"],
        }
        for name, value in expected.items():
            actual = description.get(name)
            if isinstance(value, str):
                actual = str(actual)
            if actual != value:
                raise AdmissionError("Authority runtime description differs from admitted deployment")
        public = pin.receipt_public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        if bytes(description.get("receipt_public_key", b"")) != public:
            raise AdmissionError("Authority receipt public key differs")

    def verify_genesis(self, evidence: Mapping[str, Any], *, continuity_id: str,
                       identity_id: str | None = None, operation_id: str | None = None) -> None:
        verify_genesis_evidence(self.public, evidence, continuity_id=continuity_id,
                               identity_id=identity_id, operation_id=operation_id)


def verify_genesis_evidence(public: VerifiedCoreAdmission, evidence: Mapping[str, Any], *,
                           continuity_id: str, identity_id: str | None = None,
                           operation_id: str | None = None) -> None:
        # Work only from a detached snapshot, never mutable database driver values.
        e = decode_canonical_wire(canonical_bytes(evidence))
        envelope, ack, receipt = e["request_envelope"], e["prepare_ack"], e["receipt_payload"]
        if (str(e["continuity_id"]) != continuity_id or envelope["continuity_id"] != continuity_id
                or identity_id is not None and envelope["qingyu_identity_id"] != identity_id
                or operation_id is not None and envelope["operation_id"] != operation_id
                or e["genesis_operation_id"] != envelope["operation_id"]
                or e["operation_id"] != envelope["operation_id"]
                or e["qingyu_identity_id"] != envelope["qingyu_identity_id"]):
            raise AdmissionError("canonical GENESIS scope mismatch")
        intent = ExpectedIntent(*(e[field] for field in ("request_envelope_hash", "staged_result_hash",
                                  "core_audit_predecessor_hash", "core_audit_candidate_hash")))
        verify_prepare_ack(ack, envelope, public.pin, intent)
        digest = verify_generation_opening(receipt, envelope, public.pin, intent,
                    provisioning_uuid=public.origin.intent["provisioning_uuid"],
                    signed_origin_hash=public.origin.signed_provisioning_origin_digest)
        if digest != e["receipt_hash"]:
            raise ProtocolError("canonical GENESIS receipt digest differs")
