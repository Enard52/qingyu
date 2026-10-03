from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath
from enum import StrEnum
import re
import json
import subprocess
from typing import Any, Callable, Mapping, Protocol

from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError, ProgrammingError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .canonical import sha256_hex
from .control_plane.r1_protocol import canonical_bytes, key_id
from .errors import CoreError


SMI_SIGNATURE_DOMAIN_V1 = b"QINGYU:R1:SIGNED_MIGRATION_INTENT:v1\x00"
TRUST_RECORD_SCHEMA_VERSION = "qingyu-b2-production-trust-record-v1"
POSTGRES_PRODUCTION_TRUST_STORE_SCHEMA_VERSION = "qingyu-b2-postgres-production-trust-store-v1"
POSTGRES_PRODUCTION_TRUST_STORE_MIGRATION_ID = "b2_001_postgres_production_trust_store"
POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION = "qingyu-b2-postgres-production-signer-admission-store-v1"
POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID = "b2_002_postgres_production_signer_admission_store"
R1_PRODUCTION_CONTROL_DATABASE_NAME = "qingyu_control"
SIGNER_PROVIDER_CONTRACT_VERSION = "qingyu-b2-signer-provider-v1"
PRODUCTION_SIGNER_ADMISSION_SCHEMA_VERSION = "qingyu-b2-production-signer-admission-v1"
APPROVED_R1_PRODUCTION_PROVIDER_BACKEND = "encrypted-file-backed-ed25519"
IN_MEMORY_PROVIDER_BACKEND = "in-memory-ed25519"
PRODUCTION_STORAGE_POLICY = "D_BACKED_QINGYU_PROTECTED_STORAGE"
PRODUCTION_WSL_ROOTFS_STORAGE_POLICY = "D_BACKED_WSL_ROOTFS"
APPROVED_PRODUCTION_STORAGE_POLICIES = {PRODUCTION_STORAGE_POLICY, PRODUCTION_WSL_ROOTFS_STORAGE_POLICY}
PRODUCTION_PERMISSION_POLICY = "GUEST_OWNER_ONLY_0700_0600"
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


class ProductionSignerStorageClass(StrEnum):
    D_BACKED_HOST_PATH = "D_BACKED_HOST_PATH"
    D_BACKED_WSL_ROOTFS = "D_BACKED_WSL_ROOTFS"


PRODUCTION_SIGNER_STORAGE_ATTESTATION_SCHEMA_VERSION = "qingyu-b2-production-signer-storage-attestation-v1"
APPROVED_R1_PRODUCTION_WSL_DISTRO = "qingyu-prod-local-01"
APPROVED_R1_PRODUCTION_HOST_VOLUME = "D:"
GUEST_OWNER_ONLY_PERMISSION_POLICY = PRODUCTION_PERMISSION_POLICY
PRODUCTION_SIGNER_STORAGE_ATTESTATION_MAX_AGE = timedelta(minutes=5)
TRUSTED_STORAGE_INSPECTOR_ATTESTED_BY = "windows-wsl-storage-inspector"


def _host_path_is_within(path: str, root: str) -> bool:
    try:
        candidate = Path(path).resolve(strict=True)
        allowed = Path(root).resolve(strict=True)
        candidate.relative_to(allowed)
        return True
    except ValueError:
        return False
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise CoreError("PRODUCTION_SIGNER_STORAGE_PATH_INVALID") from exc


def _host_volume(path: str) -> str:
    drive = PureWindowsPath(str(path)).drive
    return drive.upper()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_fresh_observation(observed_at: datetime | None, *, now: datetime | None = None) -> None:
    if observed_at is None:
        raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_FRESHNESS_REQUIRED")
    observed = observed_at if observed_at.tzinfo is not None else observed_at.replace(tzinfo=timezone.utc)
    current = now or _utc_now()
    if current.tzinfo is None:
        current = current.replace(tzinfo=timezone.utc)
    if observed > current + timedelta(seconds=30):
        raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_NOT_YET_VALID")
    if current - observed > PRODUCTION_SIGNER_STORAGE_ATTESTATION_MAX_AGE:
        raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_STALE")

class ProductionSignerStorageAttestation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: str = PRODUCTION_SIGNER_STORAGE_ATTESTATION_SCHEMA_VERSION
    storage_class: str = Field(min_length=1)
    provider_reference: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    target_reference: str = Field(min_length=1)
    logical_secret_path_reference: str = Field(min_length=1)
    host_backing_volume: str = Field(min_length=1)
    host_backing_artifact_reference: str = Field(min_length=1)
    qingyu_storage_root_reference: str = Field(min_length=1)
    backing_verified: bool
    encrypted_private_key_format: str = "PKCS8_PEM_ENCRYPTED_PRIVATE_KEY"
    guest_secret_dir_mode: str = "0o700"
    guest_key_file_mode: str = "0o600"
    guest_passphrase_file_mode: str = "0o600"
    permission_boundary: str = GUEST_OWNER_ONLY_PERMISSION_POLICY
    host_admin_boundary_claimed: bool = False
    host_admin_trusted_computing_base: bool = True
    passphrase_separation_policy: str = "DEDICATED_SIGNER_PASSPHRASE_SEPARATE_CUSTODY"
    attested_by: str = "provisioning-storage-inspection-boundary"
    provider_self_attested: bool = False
    distro_reference: str | None = None
    wsl_version: int | None = None
    registered_base_path: str | None = None
    approved_qingyu_root: str | None = None
    encrypted_format_verified: bool = True
    passphrase_separation_verified: bool = True
    host_acl_state: str = "HOST_STORAGE_ACL_ACCEPTABLE"
    attestation_reference: str | None = None
    inspector_version: str = "qingyu-b2-production-signer-storage-inspector-v1"
    observed_at: datetime | None = None
    observation_generation: int = 1
    evidence_hash: str | None = None
    status: str = "VALID"
    created_at: datetime | None = None
    os_observed: bool = False

    @model_validator(mode="after")
    def validate_attestation_contract(self) -> "ProductionSignerStorageAttestation":
        if self.schema_version != PRODUCTION_SIGNER_STORAGE_ATTESTATION_SCHEMA_VERSION:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_SCHEMA_UNSUPPORTED")
        if self.storage_class not in {item.value for item in ProductionSignerStorageClass}:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_CLASS_UNSUPPORTED")
        if self.provider_self_attested or self.attested_by == "provider":
            raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_SELF_DECLARED")
        if self.storage_class == ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value:
            if self.attested_by != TRUSTED_STORAGE_INSPECTOR_ATTESTED_BY or not self.os_observed:
                raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_NOT_OS_OBSERVED")
            _ensure_fresh_observation(self.observed_at)
        if not self.backing_verified:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_BACKING_UNVERIFIED")
        if self.host_backing_volume.upper() != APPROVED_R1_PRODUCTION_HOST_VOLUME:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_HOST_VOLUME_UNAPPROVED")
        if self.approved_qingyu_root is not None and self.approved_qingyu_root != self.qingyu_storage_root_reference:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_ROOT_UNAPPROVED")
        if not _host_path_is_within(self.host_backing_artifact_reference, self.qingyu_storage_root_reference):
            raise CoreError("PRODUCTION_SIGNER_STORAGE_ROOT_UNAPPROVED")
        if _host_volume(self.host_backing_artifact_reference) != APPROVED_R1_PRODUCTION_HOST_VOLUME:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_HOST_VOLUME_UNAPPROVED")
        if self.encrypted_private_key_format != "PKCS8_PEM_ENCRYPTED_PRIVATE_KEY" or not self.encrypted_format_verified:
            raise CoreError("SIGNER_PROVIDER_ENCRYPTION_FORMAT_INVALID")
        if self.guest_secret_dir_mode != "0o700" or self.guest_key_file_mode != "0o600" or self.guest_passphrase_file_mode != "0o600":
            raise CoreError("PRODUCTION_SIGNER_GUEST_PERMISSION_POLICY_INVALID")
        if self.permission_boundary != GUEST_OWNER_ONLY_PERMISSION_POLICY:
            raise CoreError("PRODUCTION_SIGNER_PERMISSION_BOUNDARY_INVALID")
        if self.host_admin_boundary_claimed:
            raise CoreError("PRODUCTION_SIGNER_HOST_ADMIN_BOUNDARY_OVERCLAIMED")
        if not self.host_admin_trusted_computing_base:
            raise CoreError("PRODUCTION_SIGNER_HOST_ADMIN_TCB_REQUIRED")
        if not self.passphrase_separation_verified:
            raise CoreError("PRODUCTION_SIGNER_PASSPHRASE_SEPARATION_UNVERIFIED")
        if self.host_acl_state != "HOST_STORAGE_ACL_ACCEPTABLE":
            raise CoreError("PRODUCTION_SIGNER_HOST_ACL_UNSAFE")
        if self.status != "VALID":
            raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_INVALID")
        if self.storage_class == ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value:
            if self.distro_reference != APPROVED_R1_PRODUCTION_WSL_DISTRO:
                raise CoreError("PRODUCTION_SIGNER_WSL_DISTRO_UNAPPROVED")
            if self.wsl_version != 2:
                raise CoreError("PRODUCTION_SIGNER_WSL_VERSION_UNAPPROVED")
            if not self.logical_secret_path_reference.startswith("/etc/qingyu/secrets/production-signer/"):
                raise CoreError("PRODUCTION_SIGNER_WSL_LOGICAL_PATH_UNAPPROVED")
            if self.registered_base_path is None or not _host_path_is_within(self.host_backing_artifact_reference, self.registered_base_path):
                raise CoreError("PRODUCTION_SIGNER_WSL_BACKING_ARTIFACT_INVALID")
            if not self.host_backing_artifact_reference.lower().endswith(".vhdx"):
                raise CoreError("PRODUCTION_SIGNER_WSL_BACKING_ARTIFACT_INVALID")
            if not Path(self.host_backing_artifact_reference).is_file():
                raise CoreError("PRODUCTION_SIGNER_WSL_BACKING_ARTIFACT_INVALID")
        if self.storage_class == ProductionSignerStorageClass.D_BACKED_HOST_PATH.value:
            if not self.logical_secret_path_reference.lower().startswith("d:"):
                raise CoreError("SIGNER_PROVIDER_STORAGE_POLICY_INVALID")
        return self




class ProductionSignerStorageAttestationStore:
    """Trusted provisioning/inspection boundary for non-secret signer storage facts."""

    def __init__(self, records: Mapping[str, ProductionSignerStorageAttestation] | None = None):
        self._records: dict[str, ProductionSignerStorageAttestation] = {}
        for record in (records or {}).values():
            self.add(record)

    def add(self, record: ProductionSignerStorageAttestation) -> None:
        record.validate_attestation_contract()
        self._records[record.provider_reference] = record

    def resolve_for_provider(
        self,
        *,
        provider_reference: str,
        environment: str,
        target_reference: str,
    ) -> ProductionSignerStorageAttestation:
        record = self._records.get(provider_reference)
        if record is None:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_REQUIRED")
        if record.environment != environment:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_ENVIRONMENT_MISMATCH")
        if record.target_reference != target_reference:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_TARGET_MISMATCH")
        record.validate_attestation_contract()
        return record


@dataclass(frozen=True, slots=True)
class ProductionSignerStorageInspectionResult:
    signer_reference: str
    provider_reference: str
    environment: str
    target_reference: str
    storage_class: str
    distro_reference: str
    wsl_version: int
    registered_base_path: str
    host_backing_artifact_reference: str
    qingyu_storage_root_reference: str
    logical_secret_path_reference: str
    guest_secret_dir_mode: str
    guest_key_file_mode: str
    guest_passphrase_file_mode: str
    encrypted_format_verified: bool
    passphrase_separation_verified: bool
    host_acl_state: str
    observed_at: datetime
    observation_generation: int = 1


class ProductionSignerStorageInspector:
    """Base inspector contract. Test subclasses may provide controlled observations.

    Directly passing ProductionSignerStorageInspectionResult is intentionally not
    a production API; real production uses WindowsWslProductionSignerStorageInspector
    to observe WSL/Windows state before minting the attestation.
    """

    inspector_version = "qingyu-b2-production-signer-storage-inspector-v1"
    trusted_for_real_production = False

    def inspect(self, *, provider: EncryptedFileBackedEd25519SignerProvider, environment: str, target_reference: str) -> ProductionSignerStorageAttestation:
        raise CoreError("PRODUCTION_SIGNER_STORAGE_INSPECTOR_REQUIRED")

    def attest(self, observation: ProductionSignerStorageInspectionResult) -> ProductionSignerStorageAttestation:
        if observation.storage_class != ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_CLASS_UNSUPPORTED")
        if observation.distro_reference != APPROVED_R1_PRODUCTION_WSL_DISTRO:
            raise CoreError("PRODUCTION_SIGNER_WSL_DISTRO_UNAPPROVED")
        if observation.wsl_version != 2:
            raise CoreError("PRODUCTION_SIGNER_WSL_VERSION_UNAPPROVED")
        if not _host_path_is_within(observation.registered_base_path, observation.qingyu_storage_root_reference):
            raise CoreError("PRODUCTION_SIGNER_STORAGE_ROOT_UNAPPROVED")
        if not _host_path_is_within(observation.host_backing_artifact_reference, observation.registered_base_path):
            raise CoreError("PRODUCTION_SIGNER_WSL_BACKING_ARTIFACT_INVALID")
        if _host_volume(observation.host_backing_artifact_reference) != APPROVED_R1_PRODUCTION_HOST_VOLUME:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_HOST_VOLUME_UNAPPROVED")
        payload = {
            "provider_reference": observation.provider_reference,
            "environment": observation.environment,
            "target_reference": observation.target_reference,
            "storage_class": observation.storage_class,
            "distro_reference": observation.distro_reference,
            "registered_base_path": observation.registered_base_path,
            "host_backing_artifact_reference": observation.host_backing_artifact_reference,
            "logical_secret_path_reference": observation.logical_secret_path_reference,
            "observed_at": observation.observed_at.isoformat(),
            "generation": observation.observation_generation,
        }
        from .canonical import sha256_hex
        evidence_hash = sha256_hex(payload)
        record = ProductionSignerStorageAttestation(
            attestation_reference=f"storage-attestation:{observation.provider_reference}:{observation.observation_generation}",
            storage_class=observation.storage_class,
            distro_reference=observation.distro_reference,
            wsl_version=observation.wsl_version,
            registered_base_path=observation.registered_base_path,
            provider_reference=observation.provider_reference,
            environment=observation.environment,
            target_reference=observation.target_reference,
            logical_secret_path_reference=observation.logical_secret_path_reference,
            host_backing_volume=_host_volume(observation.host_backing_artifact_reference),
            host_backing_artifact_reference=observation.host_backing_artifact_reference,
            qingyu_storage_root_reference=observation.qingyu_storage_root_reference,
            approved_qingyu_root=observation.qingyu_storage_root_reference,
            backing_verified=True,
            attested_by=TRUSTED_STORAGE_INSPECTOR_ATTESTED_BY if self.trusted_for_real_production else "test-storage-inspection-boundary",
            os_observed=self.trusted_for_real_production,
            guest_secret_dir_mode=observation.guest_secret_dir_mode,
            guest_key_file_mode=observation.guest_key_file_mode,
            guest_passphrase_file_mode=observation.guest_passphrase_file_mode,
            encrypted_format_verified=observation.encrypted_format_verified,
            passphrase_separation_verified=observation.passphrase_separation_verified,
            host_acl_state=observation.host_acl_state,
            inspector_version=self.inspector_version,
            observed_at=observation.observed_at,
            observation_generation=observation.observation_generation,
            evidence_hash=evidence_hash,
            status="VALID",
        )
        record.validate_attestation_contract()
        return record


class WindowsWslProductionSignerStorageInspector(ProductionSignerStorageInspector):
    """Read-only Windows/WSL observer for the R1 production signer storage boundary."""

    inspector_version = "qingyu-b2-production-signer-storage-inspector-v2-windows-wsl"
    trusted_for_real_production = True

    def __init__(
        self,
        *,
        signer_reference: str = "qingyu-prod-signer-01",
        distro_reference: str = APPROVED_R1_PRODUCTION_WSL_DISTRO,
        qingyu_storage_root_reference: str = "<repo>/production/qingyu-prod-local-01",
        logical_secret_path_reference: str = "/etc/qingyu/secrets/production-signer/qingyu-prod-signer-01.pem",
        logical_passphrase_path_reference: str = "/etc/qingyu/secrets/production-signer/qingyu-prod-signer-01.passphrase",
    ):
        self.signer_reference = signer_reference
        self.distro_reference = distro_reference
        self.qingyu_storage_root_reference = qingyu_storage_root_reference
        self.logical_secret_path_reference = logical_secret_path_reference
        self.logical_passphrase_path_reference = logical_passphrase_path_reference

    def _run(self, args: list[str]) -> str:
        result = subprocess.run(args, check=False, capture_output=True, text=True, encoding="utf-8", errors="replace")
        if result.returncode != 0:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_OS_OBSERVATION_FAILED")
        return result.stdout.strip()

    def _registered_base_path(self) -> str:
        script = (
            "$d='" + self.distro_reference.replace("'", "''") + "';"
            "$k=Get-ChildItem HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss | "
            "Where-Object { $_.GetValue('DistributionName') -eq $d } | Select-Object -First 1;"
            "if (-not $k) { exit 2 }; $k.GetValue('BasePath')"
        )
        return self._run(["powershell", "-NoProfile", "-Command", script])

    def _wsl_version(self) -> int:
        out = self._run(["wsl.exe", "-l", "-v"])
        for raw in out.splitlines():
            line = raw.replace("\x00", "").replace("*", " ").strip()
            if line.startswith(self.distro_reference):
                parts = line.split()
                if parts and parts[-1].isdigit():
                    return int(parts[-1])
        raise CoreError("PRODUCTION_SIGNER_WSL_DISTRO_UNAPPROVED")

    def _mode(self, path: str) -> str:
        value = self._run(["wsl.exe", "-d", self.distro_reference, "--", "stat", "-c", "%a", path]).strip()
        return "0o" + value[-3:]

    def _encrypted_private_key_format_verified(self, provider: EncryptedFileBackedEd25519SignerProvider) -> bool:
        try:
            head = Path(provider.encrypted_private_key_path).read_bytes()[:128]
        except OSError:
            return False
        return b"BEGIN ENCRYPTED PRIVATE KEY" in head

    def _host_acl_state(self, artifact: Path) -> str:
        out = self._run(["icacls", str(artifact)])
        unsafe = ("Everyone", "Authenticated Users", "BUILTIN\\Users", "CodexSandboxUsers")
        return "HOST_STORAGE_ACL_UNSAFE" if any(item in out for item in unsafe) else "HOST_STORAGE_ACL_ACCEPTABLE"

    def inspect(self, *, provider: EncryptedFileBackedEd25519SignerProvider, environment: str, target_reference: str) -> ProductionSignerStorageAttestation:
        registered_base = self._registered_base_path()
        base = Path(registered_base).resolve(strict=True)
        candidates = sorted(base.glob("*.vhdx"))
        if not candidates:
            raise CoreError("PRODUCTION_SIGNER_WSL_BACKING_ARTIFACT_INVALID")
        artifact = candidates[0].resolve(strict=True)
        observation = ProductionSignerStorageInspectionResult(
            signer_reference=self.signer_reference,
            provider_reference=provider.provider_reference,
            environment=environment,
            target_reference=target_reference,
            storage_class=ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value,
            distro_reference=self.distro_reference,
            wsl_version=self._wsl_version(),
            registered_base_path=str(base),
            host_backing_artifact_reference=str(artifact),
            qingyu_storage_root_reference=str(Path(self.qingyu_storage_root_reference).resolve(strict=True)),
            logical_secret_path_reference=self.logical_secret_path_reference,
            guest_secret_dir_mode=self._mode("/etc/qingyu/secrets/production-signer"),
            guest_key_file_mode=self._mode(self.logical_secret_path_reference),
            guest_passphrase_file_mode=self._mode(self.logical_passphrase_path_reference),
            encrypted_format_verified=self._encrypted_private_key_format_verified(provider),
            passphrase_separation_verified=self.logical_secret_path_reference != self.logical_passphrase_path_reference,
            host_acl_state=self._host_acl_state(artifact),
            observed_at=_utc_now(),
        )
        return self.attest(observation)


def build_r1_production_signer_storage_inspector() -> WindowsWslProductionSignerStorageInspector:
    return WindowsWslProductionSignerStorageInspector()


def inspect_r1_production_signer_storage(
    provider: EncryptedFileBackedEd25519SignerProvider,
    *,
    environment: str,
    target_reference: str,
) -> ProductionSignerStorageAttestation:
    """Production-owned storage trust boundary for R1 real production.

    Callers do not provide the inspector, a store, or a precomputed attestation.
    The authority comes from this controlled call path constructing the concrete
    Windows/WSL inspector and using its fresh observation in the same validation.
    """

    inspector = build_r1_production_signer_storage_inspector()
    return inspector.inspect(provider=provider, environment=environment, target_reference=target_reference)


def _provider_key_path_matches_attestation(provider_path: str, attestation: ProductionSignerStorageAttestation) -> bool:
    normalized_provider_path = provider_path.replace("\\", "/")
    logical = attestation.logical_secret_path_reference.replace("\\", "/")
    if attestation.storage_class == ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value:
        unc_prefix = f"//wsl.localhost/{attestation.distro_reference}"
        return normalized_provider_path == logical or normalized_provider_path.endswith(unc_prefix + logical)
    return normalized_provider_path.lower() == logical.lower().replace("\\", "/")


def validate_file_backed_provider_policy(
    provider: EncryptedFileBackedEd25519SignerProvider,
    *,
    storage_attestation: ProductionSignerStorageAttestation | None = None,
    environment: str | None = None,
    target_reference: str | None = None,
) -> None:
    if storage_attestation is None:
        raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_REQUIRED")
    storage_attestation.validate_attestation_contract()
    if storage_attestation.provider_reference != provider.provider_reference:
        raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_PROVIDER_MISMATCH")
    if environment is not None and storage_attestation.environment != environment:
        raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_ENVIRONMENT_MISMATCH")
    if target_reference is not None and storage_attestation.target_reference != target_reference:
        raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_TARGET_MISMATCH")
    if not _provider_key_path_matches_attestation(provider.encrypted_private_key_path, storage_attestation):
        raise CoreError("PRODUCTION_SIGNER_STORAGE_ATTESTATION_PATH_MISMATCH")
    path = Path(provider.encrypted_private_key_path)
    if not path.exists() or not path.is_file():
        raise CoreError("SIGNER_PROVIDER_KEY_FILE_MISSING")
    data = path.read_bytes()
    if b"BEGIN ENCRYPTED PRIVATE KEY" not in data or b"BEGIN PRIVATE KEY" in data.replace(b"BEGIN ENCRYPTED PRIVATE KEY", b""):
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

    @field_validator("created_at")
    @classmethod
    def _created_at_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise CoreError("TRUST_RECORD_CREATED_AT_TIMEZONE_REQUIRED")
        return value.astimezone(timezone.utc)

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


def _trust_record_payload(record: TrustRecord) -> dict[str, Any]:
    return record.validate_record().model_dump(mode="json")


def _trust_record_hash(record: TrustRecord) -> str:
    return sha256_hex(_trust_record_payload(record))


def _assert_postgres_trust_store_database_identity(connection: Any, expected_database_name: str | None) -> str:
    if not expected_database_name:
        raise CoreError("DATABASE_SAFETY_VIOLATION")
    actual = str(connection.execute(text("SELECT current_database()")).scalar_one())
    if actual.lower() != expected_database_name.lower():
        raise CoreError("DATABASE_SAFETY_VIOLATION")
    if actual.lower() in {"postgres", "template0", "template1", "qingyu_prod"}:
        raise CoreError("DATABASE_SAFETY_VIOLATION")
    return actual


def apply_postgres_production_trust_store_migration(
    sqlalchemy_url: str,
    *,
    expected_database_name: str,
) -> None:
    """Explicit B2 control-plane migration for durable production trust records.

    This function is intentionally separate from PostgresProductionTrustStore
    construction. Normal reads/writes must not opportunistically create
    governance tables, and REAL production must provision the control database
    through an owner/migrator-controlled path.
    """

    engine = create_engine(sqlalchemy_url, pool_pre_ping=True)
    with engine.begin() as connection:
        _assert_postgres_trust_store_database_identity(connection, expected_database_name)
        connection.execute(text("CREATE SCHEMA IF NOT EXISTS governance"))
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS governance.schema_migrations (
                migration_id TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS governance.production_trust_records (
                trust_reference TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                key_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                public_key_fingerprint TEXT NOT NULL,
                provider_reference TEXT NOT NULL,
                provider_backend_type TEXT NOT NULL,
                environment TEXT NOT NULL,
                target_reference TEXT NOT NULL,
                generation INTEGER NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                status TEXT NOT NULL,
                provider_classification TEXT NOT NULL,
                rotation_deferred BOOLEAN NOT NULL,
                record_hash TEXT NOT NULL,
                durable_store_schema_version TEXT NOT NULL,
                provisioned_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                provenance JSONB NOT NULL DEFAULT '{}'::jsonb,
                CONSTRAINT production_trust_records_schema_version_ck
                    CHECK (schema_version = 'qingyu-b2-production-trust-record-v1'),
                CONSTRAINT production_trust_records_store_schema_version_ck
                    CHECK (durable_store_schema_version = 'qingyu-b2-postgres-production-trust-store-v1'),
                CONSTRAINT production_trust_records_algorithm_ck
                    CHECK (algorithm = 'Ed25519'),
                CONSTRAINT production_trust_records_status_ck
                    CHECK (status IN ('ACTIVE', 'REVOKED', 'RETIRED')),
                CONSTRAINT production_trust_records_generation_ck
                    CHECK (generation >= 1),
                CONSTRAINT production_trust_records_key_id_ck
                    CHECK (key_id ~ '^[0-9a-f]{64}$'),
                CONSTRAINT production_trust_records_public_key_ck
                    CHECK (public_key ~ '^[0-9a-f]{64}$'),
                CONSTRAINT production_trust_records_fingerprint_ck
                    CHECK (public_key_fingerprint ~ '^[0-9a-f]{64}$'),
                CONSTRAINT production_trust_records_record_hash_ck
                    CHECK (record_hash ~ '^[0-9a-f]{64}$')
            )
        """))
        connection.execute(text("""
            INSERT INTO governance.schema_migrations (migration_id, schema_version)
            VALUES (:migration_id, :schema_version)
            ON CONFLICT (migration_id) DO NOTHING
        """), {
            "migration_id": POSTGRES_PRODUCTION_TRUST_STORE_MIGRATION_ID,
            "schema_version": POSTGRES_PRODUCTION_TRUST_STORE_SCHEMA_VERSION,
        })


def apply_r1_production_trust_store_migration(sqlalchemy_url: str) -> None:
    apply_postgres_production_trust_store_migration(
        sqlalchemy_url,
        expected_database_name=R1_PRODUCTION_CONTROL_DATABASE_NAME,
    )


class PostgresProductionTrustStore:
    """Durable PostgreSQL TrustStore-compatible implementation for B2 control plane.

    Construction does not create tables. Call
    apply_postgres_production_trust_store_migration through an explicit
    migration/provisioning path before using this store.
    """

    def __init__(self, sqlalchemy_url: str, *, expected_database_name: str):
        if not expected_database_name:
            raise CoreError("DATABASE_SAFETY_VIOLATION")
        self.sqlalchemy_url = sqlalchemy_url
        self.expected_database_name = expected_database_name
        self.engine = create_engine(sqlalchemy_url, pool_pre_ping=True)

    def create_if_absent_exact(self, record: TrustRecord, *, provenance: Mapping[str, Any] | None = None) -> str:
        record.validate_record()
        payload = _trust_record_payload(record)
        record_hash = _trust_record_hash(record)
        try:
            with self.engine.begin() as connection:
                _assert_postgres_trust_store_database_identity(connection, self.expected_database_name)
                result = connection.execute(text("""
                    INSERT INTO governance.production_trust_records (
                        trust_reference, schema_version, algorithm, key_id, public_key,
                        public_key_fingerprint, provider_reference, provider_backend_type,
                        environment, target_reference, generation, created_at, status,
                        provider_classification, rotation_deferred, record_hash,
                        durable_store_schema_version, provenance
                    )
                    VALUES (
                        :trust_reference, :schema_version, :algorithm, :key_id, :public_key,
                        :public_key_fingerprint, :provider_reference, :provider_backend_type,
                        :environment, :target_reference, :generation, :created_at, :status,
                        :provider_classification, :rotation_deferred, :record_hash,
                        :durable_store_schema_version, CAST(:provenance AS jsonb)
                    )
                    ON CONFLICT (trust_reference) DO NOTHING
                """), {
                    **payload,
                    "status": record.status.value,
                    "provider_classification": record.provider_classification.value,
                    "record_hash": record_hash,
                    "durable_store_schema_version": POSTGRES_PRODUCTION_TRUST_STORE_SCHEMA_VERSION,
                    "provenance": canonical_bytes(provenance or {}).decode("utf-8"),
                })
                if result.rowcount == 1:
                    return "CREATED"
                existing = self._get_for_update(connection, record.trust_reference)
                if existing is None:
                    raise CoreError("PRODUCTION_TRUST_CREATE_RACE_UNRESOLVED")
                if _trust_record_hash(existing) != record_hash or _trust_record_payload(existing) != payload:
                    raise CoreError("PRODUCTION_TRUST_IDENTITY_CONFLICT")
                return "IDEMPOTENT_EXISTING"
        except ProgrammingError as exc:
            raise CoreError("PRODUCTION_TRUST_STORE_SCHEMA_REQUIRED") from exc
        except IntegrityError as exc:
            raise CoreError("PRODUCTION_TRUST_IDENTITY_CONFLICT") from exc

    def add(self, record: TrustRecord) -> None:
        self.create_if_absent_exact(record)

    def get(self, trust_reference: str) -> TrustRecord | None:
        try:
            with self.engine.begin() as connection:
                _assert_postgres_trust_store_database_identity(connection, self.expected_database_name)
                return self._get_for_update(connection, trust_reference, lock=False)
        except ProgrammingError as exc:
            raise CoreError("PRODUCTION_TRUST_STORE_SCHEMA_REQUIRED") from exc

    def resolve(self, trust_reference: str) -> TrustRecord:
        record = self.get(trust_reference)
        if record is None:
            raise CoreError("SMI_SIGNER_TRUST_NOT_FOUND")
        return record

    def exists(self, trust_reference: str) -> bool:
        return self.get(trust_reference) is not None

    def _get_for_update(self, connection: Any, trust_reference: str, *, lock: bool = True) -> TrustRecord | None:
        suffix = " FOR UPDATE" if lock else ""
        row = connection.execute(text(f"""
            SELECT trust_reference, schema_version, algorithm, key_id, public_key,
                   public_key_fingerprint, provider_reference, provider_backend_type,
                   environment, target_reference, generation, created_at, status,
                   provider_classification, rotation_deferred, record_hash
              FROM governance.production_trust_records
             WHERE trust_reference = :trust_reference
            {suffix}
        """), {"trust_reference": trust_reference}).mappings().first()
        if row is None:
            return None
        record = TrustRecord(
            schema_version=row["schema_version"],
            trust_reference=row["trust_reference"],
            algorithm=row["algorithm"],
            key_id=row["key_id"],
            public_key=row["public_key"],
            public_key_fingerprint=row["public_key_fingerprint"],
            provider_reference=row["provider_reference"],
            provider_backend_type=row["provider_backend_type"],
            environment=row["environment"],
            target_reference=row["target_reference"],
            generation=row["generation"],
            created_at=row["created_at"],
            status=TrustStatus(row["status"]),
            provider_classification=SignerProviderClassification(row["provider_classification"]),
            rotation_deferred=row["rotation_deferred"],
        )
        if _trust_record_hash(record) != row["record_hash"]:
            raise CoreError("PRODUCTION_TRUST_DURABLE_HASH_MISMATCH")
        return record


def require_postgres_production_trust_store_config(
    *,
    mode: AuthorityEnvironmentMode,
    sqlalchemy_url: str | None,
) -> PostgresProductionTrustStore:
    if mode == AuthorityEnvironmentMode.REAL_PRODUCTION and not sqlalchemy_url:
        raise CoreError("PRODUCTION_TRUST_STORE_CONFIG_REQUIRED")
    if not sqlalchemy_url:
        raise CoreError("PRODUCTION_TRUST_STORE_CONFIG_REQUIRED")
    if mode == AuthorityEnvironmentMode.REAL_PRODUCTION:
        return PostgresProductionTrustStore(
            sqlalchemy_url,
            expected_database_name=R1_PRODUCTION_CONTROL_DATABASE_NAME,
        )
    raise CoreError("PRODUCTION_TRUST_STORE_CONFIG_REQUIRED")


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
    storage_class: str | None = None
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

    @field_validator("created_at")
    @classmethod
    def _admission_created_at_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_CREATED_AT_TIMEZONE_REQUIRED")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_admission(self) -> "ProductionSignerAdmissionRecord":
        if self.schema_version != PRODUCTION_SIGNER_ADMISSION_SCHEMA_VERSION:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_SCHEMA_UNSUPPORTED")
        if self.algorithm != "Ed25519":
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_ALGORITHM_MISMATCH")
        if self.storage_policy not in APPROVED_PRODUCTION_STORAGE_POLICIES:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORAGE_POLICY_MISMATCH")
        if self.storage_class is not None and self.storage_class not in {item.value for item in ProductionSignerStorageClass}:
            raise CoreError("PRODUCTION_SIGNER_STORAGE_CLASS_UNSUPPORTED")
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


def _admission_record_payload(record: ProductionSignerAdmissionRecord) -> dict[str, Any]:
    return record.validate_admission().model_dump(mode="json")


def _admission_record_hash(record: ProductionSignerAdmissionRecord) -> str:
    return sha256_hex(_admission_record_payload(record))


def apply_postgres_production_signer_admission_store_migration(
    sqlalchemy_url: str,
    *,
    expected_database_name: str,
) -> None:
    """Explicit B2 control-plane migration for durable production signer admission.

    The migration is intentionally separate from ordinary store construction.
    Production store reads/writes must not opportunistically create schema, and
    REAL production must use an owner/migrator-controlled migration path.
    """

    engine = create_engine(sqlalchemy_url, pool_pre_ping=True)
    with engine.begin() as connection:
        _assert_postgres_trust_store_database_identity(connection, expected_database_name)
        connection.execute(text("CREATE SCHEMA IF NOT EXISTS governance"))
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS governance.schema_migrations (
                migration_id TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )
        """))
        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS governance.production_signer_admission_records (
                admission_reference TEXT PRIMARY KEY,
                schema_version TEXT NOT NULL,
                provider_reference TEXT NOT NULL UNIQUE,
                provider_backend_type TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                key_id TEXT NOT NULL,
                public_key_fingerprint TEXT NOT NULL,
                environment TEXT NOT NULL,
                target_reference TEXT NOT NULL,
                storage_policy TEXT NOT NULL,
                storage_class TEXT,
                permission_policy TEXT NOT NULL,
                custody_policy_version TEXT NOT NULL,
                provisioning_reference TEXT NOT NULL,
                provisioning_generation INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                admission_hash TEXT NOT NULL,
                durable_store_schema_version TEXT NOT NULL,
                persisted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                provenance JSONB NOT NULL DEFAULT '{}'::jsonb,
                CONSTRAINT production_signer_admission_schema_version_ck
                    CHECK (schema_version = 'qingyu-b2-production-signer-admission-v1'),
                CONSTRAINT production_signer_admission_store_schema_version_ck
                    CHECK (durable_store_schema_version = 'qingyu-b2-postgres-production-signer-admission-store-v1'),
                CONSTRAINT production_signer_admission_algorithm_ck
                    CHECK (algorithm = 'Ed25519'),
                CONSTRAINT production_signer_admission_status_ck
                    CHECK (status IN ('ACTIVE', 'REVOKED', 'RETIRED')),
                CONSTRAINT production_signer_admission_generation_ck
                    CHECK (provisioning_generation >= 1),
                CONSTRAINT production_signer_admission_key_id_ck
                    CHECK (key_id ~ '^[0-9a-f]{64}$'),
                CONSTRAINT production_signer_admission_fingerprint_ck
                    CHECK (public_key_fingerprint ~ '^[0-9a-f]{64}$'),
                CONSTRAINT production_signer_admission_hash_ck
                    CHECK (admission_hash ~ '^[0-9a-f]{64}$')
            )
        """))
        connection.execute(text("""
            INSERT INTO governance.schema_migrations (migration_id, schema_version)
            VALUES (:migration_id, :schema_version)
            ON CONFLICT (migration_id) DO NOTHING
        """), {
            "migration_id": POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID,
            "schema_version": POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION,
        })


def apply_r1_production_signer_admission_store_migration(sqlalchemy_url: str) -> None:
    apply_postgres_production_signer_admission_store_migration(
        sqlalchemy_url,
        expected_database_name=R1_PRODUCTION_CONTROL_DATABASE_NAME,
    )


class PostgresProductionSignerAdmissionStore:
    """Durable PostgreSQL ProductionSignerAdmissionStore-compatible implementation."""

    def __init__(self, sqlalchemy_url: str, *, expected_database_name: str):
        if not expected_database_name:
            raise CoreError("DATABASE_SAFETY_VIOLATION")
        self.sqlalchemy_url = sqlalchemy_url
        self.expected_database_name = expected_database_name
        self.engine = create_engine(sqlalchemy_url, pool_pre_ping=True)

    def create_if_absent_exact(self, record: ProductionSignerAdmissionRecord, *, provenance: Mapping[str, Any] | None = None) -> str:
        payload = _admission_record_payload(record)
        admission_hash = _admission_record_hash(record)
        try:
            with self.engine.begin() as connection:
                _assert_postgres_trust_store_database_identity(connection, self.expected_database_name)
                result = connection.execute(text("""
                    INSERT INTO governance.production_signer_admission_records (
                        admission_reference, schema_version, provider_reference, provider_backend_type,
                        algorithm, key_id, public_key_fingerprint, environment, target_reference,
                        storage_policy, storage_class, permission_policy, custody_policy_version,
                        provisioning_reference, provisioning_generation, status, created_at, admission_hash,
                        durable_store_schema_version, provenance
                    )
                    VALUES (
                        :admission_reference, :schema_version, :provider_reference, :provider_backend_type,
                        :algorithm, :key_id, :public_key_fingerprint, :environment, :target_reference,
                        :storage_policy, :storage_class, :permission_policy, :custody_policy_version,
                        :provisioning_reference, :provisioning_generation, :status, :created_at, :admission_hash,
                        :durable_store_schema_version, CAST(:provenance AS jsonb)
                    )
                    ON CONFLICT DO NOTHING
                """), {
                    **payload,
                    "status": record.status.value,
                    "admission_hash": admission_hash,
                    "durable_store_schema_version": POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION,
                    "provenance": canonical_bytes(provenance or {}).decode("utf-8"),
                })
                if result.rowcount == 1:
                    return "CREATED"
                existing = self._get_for_update(connection, record.admission_reference, lock=False)
                if existing is None:
                    # Another immutable identity can own the unique provider reference.
                    raise CoreError("PRODUCTION_SIGNER_ADMISSION_IDENTITY_CONFLICT")
                if _admission_record_hash(existing) != admission_hash or _admission_record_payload(existing) != payload:
                    raise CoreError("PRODUCTION_SIGNER_ADMISSION_IDENTITY_CONFLICT")
                return "IDEMPOTENT_EXISTING"
        except ProgrammingError as exc:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_REQUIRED") from exc
        except IntegrityError as exc:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_IDENTITY_CONFLICT") from exc

    def add(self, record: ProductionSignerAdmissionRecord) -> None:
        self.create_if_absent_exact(record)

    def get(self, admission_reference: str) -> ProductionSignerAdmissionRecord | None:
        try:
            with self.engine.begin() as connection:
                _assert_postgres_trust_store_database_identity(connection, self.expected_database_name)
                return self._get_for_update(connection, admission_reference, lock=False)
        except ProgrammingError as exc:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_REQUIRED") from exc

    def resolve(self, admission_reference: str) -> ProductionSignerAdmissionRecord:
        record = self.get(admission_reference)
        if record is None:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_NOT_FOUND")
        return record

    def resolve_for_trust(self, trust_record: TrustRecord) -> ProductionSignerAdmissionRecord:
        try:
            with self.engine.begin() as connection:
                _assert_postgres_trust_store_database_identity(connection, self.expected_database_name)
                rows = connection.execute(text("""
                    SELECT admission_reference
                      FROM governance.production_signer_admission_records
                     WHERE provider_reference = :provider_reference
                """), {"provider_reference": trust_record.provider_reference}).mappings().all()
                if len(rows) != 1:
                    raise CoreError("PRODUCTION_SIGNER_ADMISSION_NOT_FOUND")
                record = self._get_for_update(connection, rows[0]["admission_reference"], lock=False)
                if record is None:
                    raise CoreError("PRODUCTION_SIGNER_ADMISSION_NOT_FOUND")
                return record
        except ProgrammingError as exc:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_REQUIRED") from exc

    def count(self) -> int:
        try:
            with self.engine.begin() as connection:
                _assert_postgres_trust_store_database_identity(connection, self.expected_database_name)
                return int(connection.execute(text("SELECT count(*) FROM governance.production_signer_admission_records")).scalar_one())
        except ProgrammingError as exc:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_REQUIRED") from exc

    def _get_for_update(self, connection: Any, admission_reference: str, *, lock: bool = True) -> ProductionSignerAdmissionRecord | None:
        suffix = " FOR UPDATE" if lock else ""
        row = connection.execute(text(f"""
            SELECT admission_reference, schema_version, provider_reference, provider_backend_type,
                   algorithm, key_id, public_key_fingerprint, environment, target_reference,
                   storage_policy, storage_class, permission_policy, custody_policy_version,
                   provisioning_reference, provisioning_generation, status, created_at, admission_hash
              FROM governance.production_signer_admission_records
             WHERE admission_reference = :admission_reference
            {suffix}
        """), {"admission_reference": admission_reference}).mappings().first()
        if row is None:
            return None
        record = ProductionSignerAdmissionRecord(
            schema_version=row["schema_version"],
            admission_reference=row["admission_reference"],
            provider_reference=row["provider_reference"],
            provider_backend_type=row["provider_backend_type"],
            algorithm=row["algorithm"],
            key_id=row["key_id"],
            public_key_fingerprint=row["public_key_fingerprint"],
            environment=row["environment"],
            target_reference=row["target_reference"],
            storage_policy=row["storage_policy"],
            storage_class=row["storage_class"],
            permission_policy=row["permission_policy"],
            custody_policy_version=row["custody_policy_version"],
            provisioning_reference=row["provisioning_reference"],
            provisioning_generation=row["provisioning_generation"],
            status=ProductionSignerAdmissionStatus(row["status"]),
            created_at=row["created_at"],
        )
        if _admission_record_hash(record) != row["admission_hash"]:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_DURABLE_HASH_MISMATCH")
        return record


def require_postgres_production_signer_admission_store_config(
    *,
    mode: AuthorityEnvironmentMode,
    sqlalchemy_url: str | None,
) -> PostgresProductionSignerAdmissionStore:
    if mode == AuthorityEnvironmentMode.REAL_PRODUCTION and not sqlalchemy_url:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORE_CONFIG_REQUIRED")
    if not sqlalchemy_url:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORE_CONFIG_REQUIRED")
    if mode == AuthorityEnvironmentMode.REAL_PRODUCTION:
        return PostgresProductionSignerAdmissionStore(
            sqlalchemy_url,
            expected_database_name=R1_PRODUCTION_CONTROL_DATABASE_NAME,
        )
    raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORE_CONFIG_REQUIRED")


@dataclass(frozen=True, slots=True)
class ProductionSignerAdmissionRecoveryBinding:
    ext_rec_01_status: str
    source_backup_sha256: str
    encrypted_asset_sha256: str
    release_identifier: str
    remote_asset_identifier: str
    remote_repository_visibility: str

    def validate_binding(self) -> "ProductionSignerAdmissionRecoveryBinding":
        if self.ext_rec_01_status != "CLOSED":
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_RECOVERY_GATE_NOT_CLOSED")
        if self.source_backup_sha256 != "0bcac9aacb35372e8ae732bef3fc39c5033e623fffe54421dd8c85aaa2c5f362":
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_RECOVERY_SOURCE_MISMATCH")
        if self.encrypted_asset_sha256 != "fa906348960fcaac7d5e2f752a346efcbebf0e19d3786059677ced0efae6abd0":
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_RECOVERY_ASSET_MISMATCH")
        if self.release_identifier != "backup-trust-control-20260924T142657Z-073c4f3a":
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_RECOVERY_RELEASE_MISMATCH")
        if self.remote_asset_identifier != "RA_kwDOUikIh84i76Iu":
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_RECOVERY_ASSET_MISMATCH")
        if self.remote_repository_visibility != "PRIVATE":
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_RECOVERY_VISIBILITY_MISMATCH")
        return self


class ProductionSignerAdmissionProvisioningService:
    """Canonical composition for future REAL production Admission provisioning."""

    def __init__(
        self,
        *,
        trust_store: PostgresProductionTrustStore,
        admission_store: PostgresProductionSignerAdmissionStore,
        signer_provider: SignerProvider,
        recovery_binding: ProductionSignerAdmissionRecoveryBinding,
    ):
        if not isinstance(trust_store, PostgresProductionTrustStore):
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_TRUST_STORE_REQUIRED")
        if not isinstance(admission_store, PostgresProductionSignerAdmissionStore):
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_DURABLE_STORE_REQUIRED")
        self.trust_store = trust_store
        self.admission_store = admission_store
        self.signer_provider = signer_provider
        self.recovery_binding = recovery_binding.validate_binding()

    def create_admission(
        self,
        *,
        admission_reference: str,
        trust_reference: str,
        custody_policy_version: str,
        provisioning_reference: str,
        provisioning_generation: int,
        created_at: datetime,
        provenance: Mapping[str, Any] | None = None,
    ) -> str:
        trust_record = self.trust_store.resolve(trust_reference)
        if trust_record.status != TrustStatus.ACTIVE:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_TRUST_NOT_ACTIVE")
        if self.signer_provider.provider_reference != trust_record.provider_reference:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_PROVIDER_MISMATCH")
        if self.signer_provider.key_id != trust_record.key_id:
            raise CoreError("PRODUCTION_SIGNER_ADMISSION_KEY_ID_MISMATCH")
        verify_production_signer_admission(
            trust_record=trust_record,
            admission_store=ProductionSignerAdmissionStore({
                admission_reference: ProductionSignerAdmissionRecord(
                    admission_reference=admission_reference,
                    provider_reference=trust_record.provider_reference,
                    provider_backend_type=trust_record.provider_backend_type,
                    algorithm=trust_record.algorithm,
                    key_id=trust_record.key_id,
                    public_key_fingerprint=trust_record.public_key_fingerprint,
                    environment=trust_record.environment,
                    target_reference=trust_record.target_reference,
                    storage_policy=PRODUCTION_WSL_ROOTFS_STORAGE_POLICY,
                    storage_class=ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value,
                    permission_policy=PRODUCTION_PERMISSION_POLICY,
                    custody_policy_version=custody_policy_version,
                    provisioning_reference=provisioning_reference,
                    provisioning_generation=provisioning_generation,
                    status=ProductionSignerAdmissionStatus.ACTIVE,
                    created_at=created_at,
                )
            }),
            signer_provider=self.signer_provider,
        )
        record = ProductionSignerAdmissionRecord(
            admission_reference=admission_reference,
            provider_reference=trust_record.provider_reference,
            provider_backend_type=trust_record.provider_backend_type,
            algorithm=trust_record.algorithm,
            key_id=trust_record.key_id,
            public_key_fingerprint=trust_record.public_key_fingerprint,
            environment=trust_record.environment,
            target_reference=trust_record.target_reference,
            storage_policy=PRODUCTION_WSL_ROOTFS_STORAGE_POLICY,
            storage_class=ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value,
            permission_policy=PRODUCTION_PERMISSION_POLICY,
            custody_policy_version=custody_policy_version,
            provisioning_reference=provisioning_reference,
            provisioning_generation=provisioning_generation,
            status=ProductionSignerAdmissionStatus.ACTIVE,
            created_at=created_at,
        )
        return self.admission_store.create_if_absent_exact(record, provenance=provenance)

    def read_admission(self, admission_reference: str) -> ProductionSignerAdmissionRecord:
        return self.admission_store.resolve(admission_reference)


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
    if admission.storage_policy not in APPROVED_PRODUCTION_STORAGE_POLICIES:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORAGE_POLICY_MISMATCH")
    if admission.permission_policy != PRODUCTION_PERMISSION_POLICY:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_PERMISSION_POLICY_MISMATCH")
    if admission.storage_policy != PRODUCTION_WSL_ROOTFS_STORAGE_POLICY:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORAGE_POLICY_MISMATCH")
    resolved_attestation = inspect_r1_production_signer_storage(
        signer_provider,
        environment=trust_record.environment,
        target_reference=trust_record.target_reference,
    )
    if admission.storage_class is not None and admission.storage_class != resolved_attestation.storage_class:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORAGE_CLASS_MISMATCH")
    if resolved_attestation.storage_class != ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value:
        raise CoreError("PRODUCTION_SIGNER_ADMISSION_STORAGE_POLICY_MISMATCH")
    validate_file_backed_provider_policy(
        signer_provider,
        storage_attestation=resolved_attestation,
        environment=trust_record.environment,
        target_reference=trust_record.target_reference,
    )


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


# Additive OBS-02 foundation. Existing Trust/Admission payloads and migrations
# remain historical contracts; this record carries the new authority separately.
PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_SCHEMA_VERSION = "qingyu-b2-production-signer-admission-trust-binding-v1"
POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION = "qingyu-b2-postgres-production-signer-admission-trust-binding-store-v1"
POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID = "b2_003_postgres_production_signer_admission_trust_binding_store"
_BINDING_ERROR_PREFIX = "PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_"


class ProductionSignerAdmissionTrustBindingRequest(BaseModel):
    """Owner inputs only: durable source hashes cannot be supplied by the caller."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    admission_reference: str = Field(min_length=1)
    trust_reference: str = Field(min_length=1)
    created_at: datetime
    provenance: dict[str, Any]

    @field_validator("created_at")
    @classmethod
    def _binding_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise CoreError(_BINDING_ERROR_PREFIX + "CREATED_AT_TIMEZONE_REQUIRED")
        return value.astimezone(timezone.utc)

    @field_validator("provenance", mode="before")
    @classmethod
    def _binding_provenance(cls, value: Any) -> dict[str, Any]:
        def valid(item: Any) -> bool:
            if isinstance(item, dict):
                return all(isinstance(k, str) and bool(k) and valid(v) for k, v in item.items())
            if isinstance(item, list):
                return all(valid(v) for v in item)
            return item is None or type(item) in (str, int, float, bool)

        if not isinstance(value, dict) or not value or not valid(value):
            raise CoreError(_BINDING_ERROR_PREFIX + "PROVENANCE_INVALID")
        try:
            # Detach nested caller-owned objects and reject NaN/Infinity.
            return json.loads(json.dumps(value, allow_nan=False))
        except (ValueError, TypeError) as exc:
            raise CoreError(_BINDING_ERROR_PREFIX + "PROVENANCE_INVALID") from exc


class ProductionSignerAdmissionTrustBinding(ProductionSignerAdmissionTrustBindingRequest):
    schema_version: str = PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_SCHEMA_VERSION
    admission_hash: str
    trust_hash: str

    @field_validator("admission_hash", "trust_hash")
    @classmethod
    def _binding_source_hash(cls, value: str) -> str:
        if not _HEX64.fullmatch(value):
            raise CoreError(_BINDING_ERROR_PREFIX + "HASH_INVALID")
        return value

    @model_validator(mode="after")
    def validate_binding(self) -> "ProductionSignerAdmissionTrustBinding":
        if self.schema_version != PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_SCHEMA_VERSION:
            raise CoreError(_BINDING_ERROR_PREFIX + "SCHEMA_UNSUPPORTED")
        return self

    @property
    def binding_hash(self) -> str:
        return sha256_hex(self.model_dump(mode="json"))


def _binding_database_error(exc: DBAPIError) -> CoreError:
    # No blanket IntegrityError -> IDENTITY_CONFLICT classification. Unique
    # conflicts are arbitrated by INSERT and exact readback, not exceptions.
    code = getattr(exc.orig, "sqlstate", None)
    suffix = {
        "42P01": "STORE_SCHEMA_REQUIRED", "3F000": "STORE_SCHEMA_REQUIRED",
        "42501": "STORE_PERMISSION_DENIED", "23503": "SOURCE_REFERENCE_INVALID",
        "23514": "STORE_CONSTRAINT_VIOLATION", "23502": "STORE_CONSTRAINT_VIOLATION",
        "40001": "STORE_TRANSACTION_RETRY_REQUIRED", "40P01": "STORE_TRANSACTION_RETRY_REQUIRED",
    }.get(code, "STORE_DATABASE_ERROR")
    return CoreError(_BINDING_ERROR_PREFIX + suffix)


def apply_postgres_production_signer_admission_trust_binding_store_migration(
    sqlalchemy_url: str, *, expected_database_name: str,
) -> None:
    """Additive b2_003 candidate; never backfills or rewrites source authority.

    Uses the established explicit callable migration mechanism. Real executor
    allowlisting and role grants belong to a separately authorized future stage.
    """
    engine = create_engine(sqlalchemy_url, pool_pre_ping=True)
    try:
        with engine.begin() as connection:
            _assert_postgres_trust_store_database_identity(connection, expected_database_name)
            prerequisites = connection.execute(text("""
                SELECT migration_id, schema_version FROM governance.schema_migrations
                 WHERE migration_id IN (:trust, :admission)
            """), {"trust": POSTGRES_PRODUCTION_TRUST_STORE_MIGRATION_ID,
                     "admission": POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID}).all()
            if dict(prerequisites) != {
                POSTGRES_PRODUCTION_TRUST_STORE_MIGRATION_ID: POSTGRES_PRODUCTION_TRUST_STORE_SCHEMA_VERSION,
                POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID: POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION,
            }:
                raise CoreError(_BINDING_ERROR_PREFIX + "MIGRATION_PREREQUISITES_REQUIRED")
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS governance.production_signer_admission_trust_bindings (
                    admission_reference TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    admission_hash TEXT NOT NULL CHECK (admission_hash ~ '^[0-9a-f]{64}$'),
                    trust_reference TEXT NOT NULL UNIQUE,
                    trust_hash TEXT NOT NULL CHECK (trust_hash ~ '^[0-9a-f]{64}$'),
                    created_at TIMESTAMPTZ NOT NULL,
                    provenance JSONB NOT NULL CHECK (jsonb_typeof(provenance) = 'object' AND provenance <> '{}'::jsonb),
                    binding_hash TEXT NOT NULL CHECK (binding_hash ~ '^[0-9a-f]{64}$'),
                    durable_store_schema_version TEXT NOT NULL,
                    persisted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    CONSTRAINT admission_trust_binding_schema_ck CHECK (
                        schema_version = 'qingyu-b2-production-signer-admission-trust-binding-v1'),
                    CONSTRAINT admission_trust_binding_store_schema_ck CHECK (
                        durable_store_schema_version = 'qingyu-b2-postgres-production-signer-admission-trust-binding-store-v1'),
                    CONSTRAINT admission_trust_binding_admission_fk FOREIGN KEY (admission_reference)
                        REFERENCES governance.production_signer_admission_records(admission_reference)
                        ON UPDATE RESTRICT ON DELETE RESTRICT,
                    CONSTRAINT admission_trust_binding_trust_fk FOREIGN KEY (trust_reference)
                        REFERENCES governance.production_trust_records(trust_reference)
                        ON UPDATE RESTRICT ON DELETE RESTRICT
                )
            """))
            connection.execute(text("""
                INSERT INTO governance.schema_migrations (migration_id, schema_version)
                VALUES (:migration_id, :schema_version) ON CONFLICT DO NOTHING
            """), {"migration_id": POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID,
                     "schema_version": POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION})
            version = connection.execute(text("SELECT schema_version FROM governance.schema_migrations WHERE migration_id=:id"),
                                         {"id": POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID}).scalar_one()
            if version != POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION:
                raise CoreError(_BINDING_ERROR_PREFIX + "STORE_SCHEMA_UNSUPPORTED")
    except DBAPIError as exc:
        raise _binding_database_error(exc) from exc
    finally:
        engine.dispose()


def apply_r1_production_signer_admission_trust_binding_store_migration(sqlalchemy_url: str) -> None:
    apply_postgres_production_signer_admission_trust_binding_store_migration(
        sqlalchemy_url, expected_database_name=R1_PRODUCTION_CONTROL_DATABASE_NAME,
    )


class PostgresProductionSignerAdmissionTrustBindingStore:
    """Immutable relational authority; source validation and INSERT share a connection.

    READ COMMITTED gives the SELECT after a waiting ON CONFLICT a new snapshot,
    including the winner's committed row. No locking SELECT or UPDATE is used.
    Role credentials, ownership and grants are separately provisioned prerequisites.
    """

    def __init__(self, sqlalchemy_url: str, *, expected_database_name: str):
        if not expected_database_name:
            raise CoreError("DATABASE_SAFETY_VIOLATION")
        self.expected_database_name = expected_database_name
        self.engine = create_engine(sqlalchemy_url, pool_pre_ping=True, isolation_level="READ COMMITTED")

    def _sources(self, connection: Any, admission_reference: str, trust_reference: str) -> tuple[ProductionSignerAdmissionRecord, TrustRecord]:
        admission_row = connection.execute(text("SELECT * FROM governance.production_signer_admission_records WHERE admission_reference=:ref"),
                                           {"ref": admission_reference}).mappings().first()
        if admission_row is None:
            raise CoreError(_BINDING_ERROR_PREFIX + "ADMISSION_NOT_FOUND")
        trust_row = connection.execute(text("SELECT * FROM governance.production_trust_records WHERE trust_reference=:ref"),
                                       {"ref": trust_reference}).mappings().first()
        if trust_row is None:
            raise CoreError(_BINDING_ERROR_PREFIX + "TRUST_NOT_FOUND")
        if (admission_row["durable_store_schema_version"] != POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION
                or trust_row["durable_store_schema_version"] != POSTGRES_PRODUCTION_TRUST_STORE_SCHEMA_VERSION):
            raise CoreError(_BINDING_ERROR_PREFIX + "SOURCE_SCHEMA_UNSUPPORTED")
        admission = ProductionSignerAdmissionRecord(**{k: admission_row[k] for k in ProductionSignerAdmissionRecord.model_fields})
        trust = TrustRecord(**{k: trust_row[k] for k in TrustRecord.model_fields})
        if _admission_record_hash(admission) != admission_row["admission_hash"]:
            raise CoreError(_BINDING_ERROR_PREFIX + "ADMISSION_HASH_MISMATCH")
        if _trust_record_hash(trust) != trust_row["record_hash"]:
            raise CoreError(_BINDING_ERROR_PREFIX + "TRUST_HASH_MISMATCH")
        if admission.status != ProductionSignerAdmissionStatus.ACTIVE or trust.status != TrustStatus.ACTIVE:
            raise CoreError(_BINDING_ERROR_PREFIX + "SOURCE_NOT_ACTIVE")
        for name in ("algorithm", "provider_reference", "provider_backend_type", "key_id",
                     "public_key_fingerprint", "environment", "target_reference"):
            if getattr(admission, name) != getattr(trust, name):
                raise CoreError(_BINDING_ERROR_PREFIX + "SIGNER_TRUST_MISMATCH")
        return admission, trust

    def _get(self, connection: Any, admission_reference: str) -> ProductionSignerAdmissionTrustBinding | None:
        row = connection.execute(text("SELECT * FROM governance.production_signer_admission_trust_bindings WHERE admission_reference=:ref"),
                                 {"ref": admission_reference}).mappings().first()
        if row is None:
            return None
        if row["durable_store_schema_version"] != POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION:
            raise CoreError(_BINDING_ERROR_PREFIX + "STORE_SCHEMA_UNSUPPORTED")
        binding = ProductionSignerAdmissionTrustBinding(**{k: row[k] for k in ProductionSignerAdmissionTrustBinding.model_fields})
        if binding.binding_hash != row["binding_hash"]:
            raise CoreError(_BINDING_ERROR_PREFIX + "DURABLE_HASH_MISMATCH")
        return binding

    def _insert_exact(self, connection: Any, binding: ProductionSignerAdmissionTrustBinding) -> str:
        result = connection.execute(text("""
            INSERT INTO governance.production_signer_admission_trust_bindings
                (schema_version, admission_reference, admission_hash, trust_reference, trust_hash,
                 created_at, provenance, binding_hash, durable_store_schema_version)
            VALUES (:schema_version, :admission_reference, :admission_hash, :trust_reference, :trust_hash,
                    :created_at, CAST(:provenance AS jsonb), :binding_hash, :durable_store_schema_version)
            ON CONFLICT DO NOTHING
        """), {**binding.model_dump(mode="json"), "binding_hash": binding.binding_hash,
                 "provenance": canonical_bytes(binding.provenance).decode("utf-8"),
                 "durable_store_schema_version": POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION})
        if result.rowcount == 1:
            return "CREATED"
        existing = self._get(connection, binding.admission_reference)
        if existing is None or existing.model_dump(mode="json") != binding.model_dump(mode="json"):
            raise CoreError(_BINDING_ERROR_PREFIX + "IDENTITY_CONFLICT")
        return "IDEMPOTENT_EXISTING"

    def create_if_absent_exact(self, binding: ProductionSignerAdmissionTrustBinding) -> str:
        # Revalidate even a model_copy/model_construct and detach provenance before IO.
        binding = ProductionSignerAdmissionTrustBinding.model_validate(binding.model_dump())
        try:
            with self.engine.begin() as connection:
                _assert_postgres_trust_store_database_identity(connection, self.expected_database_name)
                existing = self._get(connection, binding.admission_reference)
                if existing is not None and existing.model_dump(mode="json") != binding.model_dump(mode="json"):
                    raise CoreError(_BINDING_ERROR_PREFIX + "IDENTITY_CONFLICT")
                admission, trust = self._sources(connection, binding.admission_reference, binding.trust_reference)
                if binding.admission_hash != _admission_record_hash(admission):
                    raise CoreError(_BINDING_ERROR_PREFIX + "ADMISSION_HASH_MISMATCH")
                if binding.trust_hash != _trust_record_hash(trust):
                    raise CoreError(_BINDING_ERROR_PREFIX + "TRUST_HASH_MISMATCH")
                return self._insert_exact(connection, binding)
        except DBAPIError as exc:
            raise _binding_database_error(exc) from exc

    def create_from_sources(self, request: ProductionSignerAdmissionTrustBindingRequest) -> str:
        request = ProductionSignerAdmissionTrustBindingRequest.model_validate(request.model_dump())
        try:
            with self.engine.begin() as connection:
                _assert_postgres_trust_store_database_identity(connection, self.expected_database_name)
                admission, trust = self._sources(connection, request.admission_reference, request.trust_reference)
                binding = ProductionSignerAdmissionTrustBinding(**request.model_dump(),
                    admission_hash=_admission_record_hash(admission), trust_hash=_trust_record_hash(trust))
                return self._insert_exact(connection, binding)
        except DBAPIError as exc:
            raise _binding_database_error(exc) from exc

    def get(self, admission_reference: str) -> ProductionSignerAdmissionTrustBinding | None:
        try:
            with self.engine.begin() as connection:
                _assert_postgres_trust_store_database_identity(connection, self.expected_database_name)
                return self._get(connection, admission_reference)
        except DBAPIError as exc:
            raise _binding_database_error(exc) from exc

    def resolve(self, admission_reference: str) -> ProductionSignerAdmissionTrustBinding:
        binding = self.get(admission_reference)
        if binding is None:
            raise CoreError(_BINDING_ERROR_PREFIX + "NOT_FOUND")
        return binding

    def count(self) -> int:
        try:
            with self.engine.begin() as connection:
                _assert_postgres_trust_store_database_identity(connection, self.expected_database_name)
                return int(connection.execute(text("SELECT count(*) FROM governance.production_signer_admission_trust_bindings")).scalar_one())
        except DBAPIError as exc:
            raise _binding_database_error(exc) from exc


def require_postgres_production_signer_admission_trust_binding_store_config(
    *, mode: AuthorityEnvironmentMode, sqlalchemy_url: str | None,
) -> PostgresProductionSignerAdmissionTrustBindingStore:
    if mode != AuthorityEnvironmentMode.REAL_PRODUCTION or not sqlalchemy_url:
        raise CoreError(_BINDING_ERROR_PREFIX + "STORE_CONFIG_REQUIRED")
    return PostgresProductionSignerAdmissionTrustBindingStore(
        sqlalchemy_url, expected_database_name=R1_PRODUCTION_CONTROL_DATABASE_NAME,
    )


class ProductionSignerAdmissionTrustBindingProvisioningService:
    """Explicit future provisioning; never wired into activation or automatic backfill."""

    def __init__(self, *, binding_store: PostgresProductionSignerAdmissionTrustBindingStore):
        if not isinstance(binding_store, PostgresProductionSignerAdmissionTrustBindingStore):
            raise CoreError(_BINDING_ERROR_PREFIX + "DURABLE_STORE_REQUIRED")
        self.binding_store = binding_store

    def create_binding(self, *, admission_reference: str, trust_reference: str,
                       created_at: datetime, provenance: dict[str, Any]) -> str:
        request = ProductionSignerAdmissionTrustBindingRequest(
            admission_reference=admission_reference, trust_reference=trust_reference,
            created_at=created_at, provenance=provenance,
        )
        # Derivation, canonical source validation and exactly one INSERT occur in
        # the store's single guarded transaction, including direct store callers.
        return self.binding_store.create_from_sources(request)

    def read_binding(self, admission_reference: str) -> ProductionSignerAdmissionTrustBinding:
        return self.binding_store.resolve(admission_reference)
