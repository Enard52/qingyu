from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from enum import StrEnum
import re
from typing import Any, Callable, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .control_plane.r1_protocol import canonical_bytes, key_id
from .errors import CoreError


SMI_SIGNATURE_DOMAIN_V1 = b"QINGYU:R1:SIGNED_MIGRATION_INTENT:v1\x00"
TRUST_RECORD_SCHEMA_VERSION = "qingyu-b2-production-trust-record-v1"
SIGNER_PROVIDER_CONTRACT_VERSION = "qingyu-b2-signer-provider-v1"
PRODUCTION_SIGNER_ADMISSION_SCHEMA_VERSION = "qingyu-b2-production-signer-admission-v1"
APPROVED_R1_PRODUCTION_PROVIDER_BACKEND = "encrypted-file-backed-ed25519"
IN_MEMORY_PROVIDER_BACKEND = "in-memory-ed25519"
PRODUCTION_STORAGE_POLICY = "D_BACKED_QINGYU_PROTECTED_STORAGE"
PRODUCTION_PERMISSION_POLICY = "OWNER_ONLY_POSIX_0600_EQUIVALENT"
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_HEX128 = re.compile(r"[0-9a-f]{128}\Z")


class SignerProviderClassification(StrEnum):
    TEST_ONLY = "TEST_ONLY"
    REHEARSAL_ONLY = "REHEARSAL_ONLY"
    SYNTHETIC_PRODUCTION_TEST_ONLY = "SYNTHETIC_PRODUCTION_TEST_ONLY"
    PRODUCTION_ELIGIBLE = "PRODUCTION_ELIGIBLE"


class AuthorityEnvironmentMode(StrEnum):
    SYNTHETIC_PRODUCTION_TEST = "SYNTHETIC_PRODUCTION_TEST"
    REAL_PRODUCTION = "REAL_PRODUCTION"


class TrustStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    RETIRED = "RETIRED"


class SignerProvider(Protocol):
    @property
    def provider_reference(self) -> str: ...

    @property
    def classification(self) -> SignerProviderClassification: ...

    @property
    def algorithm(self) -> str: ...

    @property
    def key_id(self) -> str: ...

    @property
    def backend_type(self) -> str: ...

    def public_key(self) -> Ed25519PublicKey: ...

    def sign(self, signing_bytes: bytes, *, domain: bytes) -> bytes: ...

    def readiness_metadata(self) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class InMemoryEd25519SignerProvider:
    """Synthetic/test provider. It never represents production custody."""

    provider_reference: str
    private_key: Ed25519PrivateKey
    classification: SignerProviderClassification = SignerProviderClassification.TEST_ONLY

    @property
    def algorithm(self) -> str:
        return "Ed25519"

    @property
    def key_id(self) -> str:
        return key_id(self.private_key.public_key())

    @property
    def backend_type(self) -> str:
        return IN_MEMORY_PROVIDER_BACKEND

    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def sign(self, signing_bytes: bytes, *, domain: bytes) -> bytes:
        return self.private_key.sign(domain + signing_bytes)

    def readiness_metadata(self) -> dict[str, Any]:
        return {
            "contract_version": SIGNER_PROVIDER_CONTRACT_VERSION,
            "provider_reference": self.provider_reference,
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "backend_type": self.backend_type,
            "classification": self.classification.value,
            "private_key_exposed": False,
        }


@dataclass(frozen=True, slots=True)
class EncryptedFileBackedEd25519SignerProvider:
    """R1 file-backed provider contract; production key material is not created here."""

    provider_reference: str
    encrypted_private_key_path: str
    passphrase_provider: Callable[[], bytes]
    classification: SignerProviderClassification

    @property
    def algorithm(self) -> str:
        return "Ed25519"

    def _private_key(self) -> Ed25519PrivateKey:
        key = serialization.load_pem_private_key(
            open(self.encrypted_private_key_path, "rb").read(),
            self.passphrase_provider(),
        )
        if not isinstance(key, Ed25519PrivateKey):
            raise CoreError("SIGNER_PROVIDER_KEY_TYPE_INVALID")
        return key

    @property
    def key_id(self) -> str:
        return key_id(self._private_key().public_key())

    @property
    def backend_type(self) -> str:
        return APPROVED_R1_PRODUCTION_PROVIDER_BACKEND

    def public_key(self) -> Ed25519PublicKey:
        return self._private_key().public_key()

    def sign(self, signing_bytes: bytes, *, domain: bytes) -> bytes:
        return self._private_key().sign(domain + signing_bytes)

    def readiness_metadata(self) -> dict[str, Any]:
        return {
            "contract_version": SIGNER_PROVIDER_CONTRACT_VERSION,
            "provider_reference": self.provider_reference,
            "algorithm": self.algorithm,
            "backend_type": self.backend_type,
            "classification": self.classification.value,
            "storage": "encrypted-file-backed",
            "private_key_exposed": False,
            "passphrase_exposed": False,
        }


def validate_file_backed_provider_policy(provider: EncryptedFileBackedEd25519SignerProvider) -> None:
    path = Path(provider.encrypted_private_key_path)
    if not str(path).lower().startswith("d:"):
        raise CoreError("SIGNER_PROVIDER_STORAGE_POLICY_INVALID")
    if "qingyu" not in str(path).lower():
        raise CoreError("SIGNER_PROVIDER_STORAGE_POLICY_INVALID")
    if not path.exists() or not path.is_file():
        raise CoreError("SIGNER_PROVIDER_KEY_FILE_MISSING")
    data = path.read_bytes()
    if b"BEGIN ENCRYPTED PRIVATE KEY" not in data:
        raise CoreError("SIGNER_PROVIDER_ENCRYPTION_FORMAT_INVALID")
    passphrase = provider.passphrase_provider()
    if not isinstance(passphrase, bytes) or len(passphrase) < 16:
        raise CoreError("SIGNER_PROVIDER_PASSPHRASE_POLICY_INVALID")
    return None


def provider_backend_type(provider: SignerProvider) -> str:
    return provider.backend_type


class TrustRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = TRUST_RECORD_SCHEMA_VERSION
    trust_reference: str = Field(min_length=1)
    algorithm: str
    key_id: str = Field(min_length=64, max_length=64)
    public_key: str = Field(min_length=64, max_length=64)
    public_key_fingerprint: str = Field(min_length=64, max_length=64)
    provider_reference: str = Field(min_length=1)
    provider_backend_type: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    target_reference: str = Field(min_length=1)
    generation: int = Field(ge=1)
    created_at: datetime
    status: TrustStatus = TrustStatus.ACTIVE
    provider_classification: SignerProviderClassification
    rotation_deferred: bool = True

    @field_validator("key_id", "public_key", "public_key_fingerprint")
    @classmethod
    def _hex64(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise CoreError("TRUST_RECORD_HEX_INVALID")
        return value

    @model_validator(mode="after")
    def validate_record(self) -> "TrustRecord":
        if self.schema_version != TRUST_RECORD_SCHEMA_VERSION:
            raise CoreError("TRUST_RECORD_SCHEMA_UNSUPPORTED")
        if self.algorithm != "Ed25519":
            raise CoreError("SMI_SIGNER_ALGORITHM_MISMATCH")
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key))
        derived = key_id(public)
        if self.key_id != derived or self.public_key_fingerprint != derived:
            raise CoreError("SMI_SIGNER_KEY_ID_MISMATCH")
        return self

    @classmethod
    def from_provider(
        cls,
        *,
        trust_reference: str,
        provider: SignerProvider,
        environment: str,
        target_reference: str,
        generation: int,
        created_at: datetime,
        status: TrustStatus = TrustStatus.ACTIVE,
    ) -> "TrustRecord":
        public_bytes = provider.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        kid = key_id(provider.public_key())
        return cls(
            trust_reference=trust_reference,
            algorithm=provider.algorithm,
            key_id=kid,
            public_key=public_bytes.hex(),
            public_key_fingerprint=kid,
            provider_reference=provider.provider_reference,
            provider_backend_type=provider.backend_type,
            environment=environment,
            target_reference=target_reference,
            generation=generation,
            created_at=created_at,
            status=status,
            provider_classification=provider.classification,
        )

    def public_key_obj(self) -> Ed25519PublicKey:
        return Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key))


class TrustStore:
    def __init__(self, records: Mapping[str, TrustRecord] | None = None):
        self._records = dict(records or {})

    def add(self, record: TrustRecord) -> None:
        self._records[record.trust_reference] = record

    def resolve(self, trust_reference: str) -> TrustRecord:
        record = self._records.get(trust_reference)
        if record is None:
            raise CoreError("SMI_SIGNER_TRUST_NOT_FOUND")
        return record


def smi_signing_bytes(payload: Mapping[str, Any]) -> bytes:
    return canonical_bytes(payload)


def sign_smi_payload(provider: SignerProvider, payload: Mapping[str, Any]) -> str:
    signature = provider.sign(smi_signing_bytes(payload), domain=SMI_SIGNATURE_DOMAIN_V1)
    if len(signature) != 64:
        raise CoreError("SMI_SIGNATURE_INVALID")
    return signature.hex()


def verify_smi_signature(
    *,
    canonical_payload: Mapping[str, Any],
    signature_hex: str | None,
    trust_record: TrustRecord,
) -> None:
    if not signature_hex:
        raise CoreError("SMI_SIGNATURE_REQUIRED")
    if type(signature_hex) is not str or _HEX128.fullmatch(signature_hex) is None:
        raise CoreError("SMI_SIGNATURE_FORMAT_INVALID")
    if trust_record.algorithm != "Ed25519":
        raise CoreError("SMI_SIGNER_ALGORITHM_MISMATCH")
    if trust_record.status == TrustStatus.REVOKED:
        raise CoreError("SMI_SIGNER_TRUST_REVOKED")
    if trust_record.status == TrustStatus.RETIRED:
        raise CoreError("SMI_SIGNER_TRUST_RETIRED")
    if trust_record.status != TrustStatus.ACTIVE:
        raise CoreError("SMI_SIGNER_TRUST_NOT_FOUND")
    try:
        trust_record.public_key_obj().verify(
            bytes.fromhex(signature_hex),
            SMI_SIGNATURE_DOMAIN_V1 + smi_signing_bytes(canonical_payload),
        )
    except InvalidSignature as exc:
        raise CoreError("SMI_SIGNATURE_INVALID") from exc


class ProductionSignerAdmissionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    RETIRED = "RETIRED"


class ProductionSignerAdmissionRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = PRODUCTION_SIGNER_ADMISSION_SCHEMA_VERSION
    admission_reference: str = Field(min_length=1)
    provider_reference: str = Field(min_length=1)
    provider_backend_type: str = Field(min_length=1)
    algorithm: str
    key_id: str = Field(min_length=64, max_length=64)
    public_key_fingerprint: str = Field(min_length=64, max_length=64)
    environment: str = Field(min_length=1)
    target_reference: str = Field(min_length=1)
    storage_policy: str = Field(min_length=1)
    permission_policy: str = Field(min_length=1)
    custody_policy_version: str = Field(min_length=1)
    provisioning_reference: str = Field(min_length=1)
    provisioning_generation: int = Field(ge=1)
    status: ProductionSignerAdmissionStatus = ProductionSignerAdmissionStatus.ACTIVE
    created_at: datetime

    @field_validator("key_id", "public_key_fingerprint")
    @classmethod
    def _admission_hex64(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_HEX_INVALID")
        return value

    @model_validator(mode="after")
    def validate_admission(self) -> "ProductionSignerAdmissionRecord":
        if self.schema_version != PRODUCTION_SIGNER_ADMISSION_SCHEMA_VERSION:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_SCHEMA_UNSUPPORTED")
        if self.algorithm != "Ed25519":
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_ALGORITHM_MISMATCH")
        return self

    @property
    def admission_hash(self) -> str:
        from .canonical import sha256_hex
        return sha256_hex(self.model_dump(mode="json"))


class ProductionSignerAdmissionStore:
    def __init__(self, records: Mapping[str, ProductionSignerAdmissionRecord] | None = None):
        self._records = dict(records or {})

    def add(self, record: ProductionSignerAdmissionRecord) -> None:
        self._records[record.admission_reference] = record

    def resolve_for_trust(self, trust_record: TrustRecord) -> ProductionSignerAdmissionRecord:
        matches = [
            record for record in self._records.values()
            if record.provider_reference == trust_record.provider_reference
        ]
        if len(matches) != 1:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_NOT_FOUND")
        return matches[0]


def verify_production_signer_admission(
    *,
    trust_record: TrustRecord,
    admission_store: ProductionSignerAdmissionStore | None,
    signer_provider: SignerProvider | None,
) -> None:
    if admission_store is None:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_NOT_FOUND")
    admission = admission_store.resolve_for_trust(trust_record)
    if admission.status != ProductionSignerAdmissionStatus.ACTIVE:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_NOT_ACTIVE")
    if admission.algorithm != trust_record.algorithm:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_ALGORITHM_MISMATCH")
    if admission.key_id != trust_record.key_id:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_KEY_ID_MISMATCH")
    if admission.public_key_fingerprint != trust_record.public_key_fingerprint:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_FINGERPRINT_MISMATCH")
    if admission.environment != trust_record.environment:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_ENVIRONMENT_MISMATCH")
    if admission.target_reference != trust_record.target_reference:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_TARGET_MISMATCH")
    if admission.provider_reference != trust_record.provider_reference:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_PROVIDER_MISMATCH")
    if admission.provider_backend_type != APPROVED_R1_PRODUCTION_PROVIDER_BACKEND:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_BACKEND_NOT_APPROVED")
    if trust_record.provider_backend_type != admission.provider_backend_type:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_BACKEND_MISMATCH")
    if signer_provider is None:
        raise CoreError("PRODUCTION_SIGNER_PROVIDER_REQUIRED")
    if signer_provider.provider_reference != admission.provider_reference:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_PROVIDER_MISMATCH")
    if signer_provider.backend_type != admission.provider_backend_type:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_BACKEND_MISMATCH")
    if not isinstance(signer_provider, EncryptedFileBackedEd25519SignerProvider):
        raise CoreError("PRODUCTION_SIGNER_PROVIDER_BACKEND_NOT_APPROVED")
    if admission.storage_policy != PRODUCTION_STORAGE_POLICY:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORAGE_POLICY_MISMATCH")
    if admission.permission_policy != PRODUCTION_PERMISSION_POLICY:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_PERMISSION_POLICY_MISMATCH")
    validate_file_backed_provider_policy(signer_provider)


def ensure_production_eligible(
    record: TrustRecord,
    *,
    mode: AuthorityEnvironmentMode,
    admission_store: ProductionSignerAdmissionStore | None = None,
    signer_provider: SignerProvider | None = None,
) -> None:
    if mode == AuthorityEnvironmentMode.REAL_PRODUCTION:
        verify_production_signer_admission(
            trust_record=record,
            admission_store=admission_store,
            signer_provider=signer_provider,
        )
    elif record.provider_classification not in (
        SignerProviderClassification.SYNTHETIC_PRODUCTION_TEST_ONLY,
        SignerProviderClassification.TEST_ONLY,
    ):
        raise CoreError("B2_SYNTHETIC_TRUST_CLASSIFICATION_INVALID")
