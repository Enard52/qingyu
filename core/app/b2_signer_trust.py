from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath
from enum import StrEnum
import re
import subprocess
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
