from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.b2_signer_trust import (
    APPROVED_R1_PRODUCTION_PROVIDER_BACKEND,
    PRODUCTION_PERMISSION_POLICY,
    PRODUCTION_STORAGE_POLICY,
    PRODUCTION_WSL_ROOTFS_STORAGE_POLICY,
    AuthorityEnvironmentMode,
    EncryptedFileBackedEd25519SignerProvider,
    InMemoryEd25519SignerProvider,
    ProductionSignerAdmissionRecord,
    ProductionSignerAdmissionStatus,
    ProductionSignerAdmissionStore,
    ProductionSignerStorageAttestation,
    ProductionSignerStorageAttestationStore,
    ProductionSignerStorageInspectionResult,
    ProductionSignerStorageInspector,
    TRUSTED_STORAGE_INSPECTOR_ATTESTED_BY,
    ProductionSignerStorageClass,
    SignerProviderClassification,
    validate_file_backed_provider_policy,
    TrustRecord,
    TrustStatus,
    ensure_production_eligible,
    sign_smi_payload,
    verify_smi_signature,
)
from app.errors import CoreError
import pytest

NOW = datetime.now(timezone.utc)

EXPECTED_PRODUCTION_KEY_ID = "c8846c02c0456182cb36d555b93d185172db8bcc01e699c9e3861cb9f5fc91ca"


def _real_wsl_production_provider_record_admission():
    key_path = "//wsl.localhost/qingyu-prod-local-01/etc/qingyu/secrets/production-signer/qingyu-prod-signer-01.pem"
    passphrase_path = "//wsl.localhost/qingyu-prod-local-01/etc/qingyu/secrets/production-signer/qingyu-prod-signer-01.passphrase"
    provider = EncryptedFileBackedEd25519SignerProvider(
        provider_reference="qingyu-prod-signer-01",
        encrypted_private_key_path=key_path,
        passphrase_provider=lambda: Path(passphrase_path).read_bytes().strip(),
        classification=SignerProviderClassification.PRODUCTION_ELIGIBLE,
    )
    record = TrustRecord.from_provider(
        trust_reference="ephemeral-test-production-trust-ref",
        provider=provider,
        environment="qingyu-production-primary",
        target_reference="prod-target-ref-001",
        generation=1,
        created_at=NOW,
    )
    admission = _admission(
        record,
        storage_policy=PRODUCTION_WSL_ROOTFS_STORAGE_POLICY,
        storage_class=ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value,
        custody_policy_version="ephemeral-test-only",
        provisioning_reference="ephemeral-test-only-no-durable-record",
    )
    return provider, record, ProductionSignerAdmissionStore({admission.admission_reference: admission})


def test_encrypted_file_backed_provider_contract_signs_without_metadata_secret_exposure(tmp_path):
    passphrase = b"unit-test-passphrase-not-production"
    key = Ed25519PrivateKey.generate()
    encrypted_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    key_path = tmp_path / "signer.ed25519.encrypted.pem"
    key_path.write_bytes(encrypted_pem)

    provider = EncryptedFileBackedEd25519SignerProvider(
        provider_reference="encrypted-file-test-provider",
        encrypted_private_key_path=str(key_path),
        passphrase_provider=lambda: passphrase,
        classification=SignerProviderClassification.PRODUCTION_ELIGIBLE,
    )
    record = TrustRecord.from_provider(
        trust_reference="trust-ref",
        provider=provider,
        environment="qingyu-prod-env",
        target_reference="target-ref",
        generation=1,
        created_at=NOW,
    )
    payload = {"intent_id": "i", "signer_key_id": record.key_id, "target_reference": "target-ref"}
    signature = sign_smi_payload(provider, payload)

    verify_smi_signature(canonical_payload=payload, signature_hex=signature, trust_record=record)
    metadata = provider.readiness_metadata()
    assert metadata["storage"] == "encrypted-file-backed"
    assert metadata["private_key_exposed"] is False
    assert metadata["passphrase_exposed"] is False
    assert "unit-test-passphrase" not in str(metadata)


def test_in_memory_provider_remains_test_only_contract():
    provider = InMemoryEd25519SignerProvider(
        provider_reference="in-memory-test-provider",
        private_key=Ed25519PrivateKey.generate(),
    )
    metadata = provider.readiness_metadata()
    assert metadata["classification"] == SignerProviderClassification.TEST_ONLY.value
    assert metadata["private_key_exposed"] is False


def _d_backed_test_dir(name: str) -> Path:
    root = Path("<repo>/production/qingyu-prod-local-01/temp/b2-signer-trust-tests") / name
    root.mkdir(parents=True, exist_ok=True)
    return root


def _encrypted_provider(name="prod-provider"):
    passphrase = b"unit-test-passphrase-not-production"
    key = Ed25519PrivateKey.generate()
    encrypted_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    key_path = _d_backed_test_dir(name) / "signer.ed25519.encrypted.pem"
    key_path.write_bytes(encrypted_pem)
    provider = EncryptedFileBackedEd25519SignerProvider(
        provider_reference=name,
        encrypted_private_key_path=str(key_path),
        passphrase_provider=lambda: passphrase,
        classification=SignerProviderClassification.PRODUCTION_ELIGIBLE,
    )
    record = TrustRecord.from_provider(
        trust_reference=f"trust:{name}",
        provider=provider,
        environment="qingyu-real-prod-primary",
        target_reference="target-real-001",
        generation=1,
        created_at=NOW,
    )
    return provider, record




def _storage_attestation(provider, record, **updates):
    data = {
        "storage_class": ProductionSignerStorageClass.D_BACKED_HOST_PATH.value,
        "provider_reference": provider.provider_reference,
        "environment": record.environment,
        "target_reference": record.target_reference,
        "logical_secret_path_reference": provider.encrypted_private_key_path,
        "host_backing_volume": "D:",
        "host_backing_artifact_reference": "<repo>/production/qingyu-prod-local-01/temp/b2-signer-trust-tests",
        "qingyu_storage_root_reference": "<repo>/production/qingyu-prod-local-01",
        "backing_verified": True,
        "guest_secret_dir_mode": "0o700",
        "guest_key_file_mode": "0o600",
        "guest_passphrase_file_mode": "0o600",
        "attested_by": "provisioning-storage-inspection-boundary",
        "provider_self_attested": False,
        "host_admin_boundary_claimed": False,
        "host_admin_trusted_computing_base": True,
        "created_at": NOW,
    }
    data.update(updates)
    return ProductionSignerStorageAttestation(**data)


def _admission(record: TrustRecord, **updates):
    data = {
        "admission_reference": "synthetic-admission-fixture",
        "provider_reference": record.provider_reference,
        "provider_backend_type": record.provider_backend_type,
        "algorithm": record.algorithm,
        "key_id": record.key_id,
        "public_key_fingerprint": record.public_key_fingerprint,
        "environment": record.environment,
        "target_reference": record.target_reference,
        "storage_policy": PRODUCTION_STORAGE_POLICY,
        "permission_policy": PRODUCTION_PERMISSION_POLICY,
        "custody_policy_version": "synthetic-custody-policy-v1",
        "provisioning_reference": "synthetic-provisioning-fixture-not-real",
        "provisioning_generation": 1,
        "status": ProductionSignerAdmissionStatus.ACTIVE,
        "created_at": NOW,
    }
    data.update(updates)
    return ProductionSignerAdmissionRecord(**data)


def test_real_production_admission_accepts_file_backed_provider_via_owned_os_inspector():
    provider, record, store = _real_wsl_production_provider_record_admission()
    ensure_production_eligible(
        record,
        mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
        admission_store=store,
        signer_provider=provider,
    )
    assert provider.key_id == EXPECTED_PRODUCTION_KEY_ID


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ({"key_id": "0" * 64}, "PRODUCTION_SIGNER_ADMISSION_KEY_ID_MISMATCH"),
        ({"public_key_fingerprint": "1" * 64}, "PRODUCTION_SIGNER_ADMISSION_FINGERPRINT_MISMATCH"),
        ({"provider_reference": "wrong-provider"}, "PRODUCTION_SIGNER_ADMISSION_NOT_FOUND"),
        ({"provider_backend_type": "wrong-backend"}, "PRODUCTION_SIGNER_ADMISSION_BACKEND_NOT_APPROVED"),
        ({"environment": "wrong-env"}, "PRODUCTION_SIGNER_ADMISSION_ENVIRONMENT_MISMATCH"),
        ({"target_reference": "wrong-target"}, "PRODUCTION_SIGNER_ADMISSION_TARGET_MISMATCH"),
        ({"status": ProductionSignerAdmissionStatus.REVOKED}, "PRODUCTION_SIGNER_ADMISSION_NOT_ACTIVE"),
        ({"storage_policy": "C_BACKED_FORBIDDEN"}, "PRODUCTION_SIGNER_ADMISSION_STORAGE_POLICY_MISMATCH"),
        ({"permission_policy": "WORLD_READABLE_FORBIDDEN"}, "PRODUCTION_SIGNER_ADMISSION_PERMISSION_POLICY_MISMATCH"),
    ],
)
def test_real_production_admission_negative_matrix(mutation, expected):
    provider, record = _encrypted_provider(f"negative-{expected.lower()}")
    if mutation.get("storage_policy") == "C_BACKED_FORBIDDEN":
        with pytest.raises(CoreError, match=expected):
            _admission(record, **mutation)
        return
    store = ProductionSignerAdmissionStore({"bad": _admission(record, **mutation)})
    with pytest.raises(CoreError, match=expected):
        ensure_production_eligible(
            record,
            mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
            admission_store=store,
            signer_provider=provider,
        )


def test_in_memory_provider_mislabeled_production_eligible_is_never_admitted():
    provider = InMemoryEd25519SignerProvider(
        provider_reference="mislabeled-in-memory",
        private_key=Ed25519PrivateKey.generate(),
        classification=SignerProviderClassification.PRODUCTION_ELIGIBLE,
    )
    record = TrustRecord.from_provider(
        trust_reference="trust:mislabeled-in-memory",
        provider=provider,
        environment="qingyu-real-prod-primary",
        target_reference="target-real-001",
        generation=1,
        created_at=NOW,
    )
    store = ProductionSignerAdmissionStore({"bad": _admission(record)})
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_BACKEND_NOT_APPROVED"):
        ensure_production_eligible(
            record,
            mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
            admission_store=store,
            signer_provider=provider,
        )


def test_real_production_missing_admission_fails_before_classification_can_authorize():
    provider, record = _encrypted_provider("missing-admission")
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_NOT_FOUND"):
        ensure_production_eligible(
            record,
            mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
            admission_store=ProductionSignerAdmissionStore(),
            signer_provider=provider,
        )




class TrustedTestStorageInspector(ProductionSignerStorageInspector):
    inspector_version = "qingyu-b2-test-os-observed-storage-inspector"
    trusted_for_real_production = True

    def __init__(self, observation):
        self.observation = observation

    def inspect(self, *, provider, environment: str, target_reference: str):
        return self.attest(self.observation)


def _trusted_wsl_observation(provider_reference="qingyu-prod-signer-01", **updates):
    root = Path("<repo>/production/qingyu-prod-local-01")
    base = root / "wsl"
    base.mkdir(parents=True, exist_ok=True)
    (base / "ext4.vhdx").touch(exist_ok=True)
    data = {
        "signer_reference": "qingyu-prod-signer-01",
        "provider_reference": provider_reference,
        "environment": "qingyu-production-primary",
        "target_reference": "prod-target-ref-001",
        "storage_class": ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value,
        "distro_reference": "qingyu-prod-local-01",
        "wsl_version": 2,
        "registered_base_path": str(base),
        "host_backing_artifact_reference": str(base / "ext4.vhdx"),
        "qingyu_storage_root_reference": str(root),
        "logical_secret_path_reference": "/etc/qingyu/secrets/production-signer/qingyu-prod-signer-01.pem",
        "guest_secret_dir_mode": "0o700",
        "guest_key_file_mode": "0o600",
        "guest_passphrase_file_mode": "0o600",
        "encrypted_format_verified": True,
        "passphrase_separation_verified": True,
        "host_acl_state": "HOST_STORAGE_ACL_ACCEPTABLE",
        "observed_at": NOW,
    }
    data.update(updates)
    return ProductionSignerStorageInspectionResult(**data)


def test_trusted_storage_inspector_derives_attestation_and_store_resolves_it():
    inspector = TrustedTestStorageInspector(_trusted_wsl_observation())
    attestation = inspector.inspect(provider=type("P", (), {"provider_reference": "qingyu-prod-signer-01"})(), environment="qingyu-production-primary", target_reference="prod-target-ref-001")
    store = ProductionSignerStorageAttestationStore({attestation.provider_reference: attestation})
    resolved = store.resolve_for_provider(
        provider_reference="qingyu-prod-signer-01",
        environment="qingyu-production-primary",
        target_reference="prod-target-ref-001",
    )
    assert resolved.storage_class == ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value
    assert resolved.backing_verified is True
    assert resolved.evidence_hash
    assert resolved.inspector_version == inspector.inspector_version
    assert resolved.attested_by == TRUSTED_STORAGE_INSPECTOR_ATTESTED_BY
    assert resolved.os_observed is True


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ({"distro_reference": "wrong-distro"}, "PRODUCTION_SIGNER_WSL_DISTRO_UNAPPROVED"),
        ({"wsl_version": 1}, "PRODUCTION_SIGNER_WSL_VERSION_UNAPPROVED"),
        ({"registered_base_path": "<repo>-evil/wsl"}, "PRODUCTION_SIGNER_STORAGE_ROOT_UNAPPROVED"),
        ({"host_backing_artifact_reference": "<repo>/production/other/wsl/ext4.vhdx"}, "PRODUCTION_SIGNER_WSL_BACKING_ARTIFACT_INVALID"),
        ({"host_backing_artifact_reference": "C:/qingyu/production/qingyu-prod-local-01/wsl/ext4.vhdx"}, "PRODUCTION_SIGNER_WSL_BACKING_ARTIFACT_INVALID"),
        ({"guest_secret_dir_mode": "0o755"}, "PRODUCTION_SIGNER_GUEST_PERMISSION_POLICY_INVALID"),
        ({"guest_key_file_mode": "0o644"}, "PRODUCTION_SIGNER_GUEST_PERMISSION_POLICY_INVALID"),
        ({"guest_passphrase_file_mode": "0o644"}, "PRODUCTION_SIGNER_GUEST_PERMISSION_POLICY_INVALID"),
        ({"encrypted_format_verified": False}, "SIGNER_PROVIDER_ENCRYPTION_FORMAT_INVALID"),
        ({"passphrase_separation_verified": False}, "PRODUCTION_SIGNER_PASSPHRASE_SEPARATION_UNVERIFIED"),
        ({"host_acl_state": "HOST_STORAGE_ACL_UNVERIFIED"}, "PRODUCTION_SIGNER_HOST_ACL_UNSAFE"),
    ],
)
def test_trusted_storage_inspector_negative_matrix(mutation, expected):
    inspector = TrustedTestStorageInspector(_trusted_wsl_observation(**mutation))
    with pytest.raises(CoreError, match=expected):
        inspector.inspect(provider=type("P", (), {"provider_reference": "qingyu-prod-signer-01"})(), environment="qingyu-production-primary", target_reference="prod-target-ref-001")


def test_storage_attestation_store_missing_and_mismatched_records_fail_closed():
    store = ProductionSignerStorageAttestationStore()
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_STORAGE_ATTESTATION_REQUIRED"):
        store.resolve_for_provider(provider_reference="missing", environment="qingyu-production-primary", target_reference="prod-target-ref-001")
    attestation = TrustedTestStorageInspector(_trusted_wsl_observation()).inspect(provider=type("P", (), {"provider_reference": "qingyu-prod-signer-01"})(), environment="qingyu-production-primary", target_reference="prod-target-ref-001")
    store.add(attestation)
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_STORAGE_ATTESTATION_ENVIRONMENT_MISMATCH"):
        store.resolve_for_provider(provider_reference="qingyu-prod-signer-01", environment="wrong-env", target_reference="prod-target-ref-001")


def test_real_production_public_boundary_rejects_caller_storage_trust_parameters():
    provider, record, store = _real_wsl_production_provider_record_admission()
    fabricated = object()
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        ensure_production_eligible(
            record,
            mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
            admission_store=store,
            signer_provider=provider,
            storage_attestation=fabricated,
        )
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        ensure_production_eligible(
            record,
            mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
            admission_store=store,
            signer_provider=provider,
            storage_attestation_store=ProductionSignerStorageAttestationStore(),
        )
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        ensure_production_eligible(
            record,
            mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
            admission_store=store,
            signer_provider=provider,
            storage_inspector=TrustedTestStorageInspector(_trusted_wsl_observation()),
        )


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ({"storage_class": "UNKNOWN"}, "PRODUCTION_SIGNER_STORAGE_CLASS_UNSUPPORTED"),
        ({"backing_verified": False}, "PRODUCTION_SIGNER_STORAGE_BACKING_UNVERIFIED"),
        ({"host_backing_volume": "C:"}, "PRODUCTION_SIGNER_STORAGE_HOST_VOLUME_UNAPPROVED"),
        ({"provider_reference": "wrong-provider"}, "PRODUCTION_SIGNER_STORAGE_ATTESTATION_PROVIDER_MISMATCH"),
        ({"environment": "wrong-env"}, "PRODUCTION_SIGNER_STORAGE_ATTESTATION_ENVIRONMENT_MISMATCH"),
        ({"target_reference": "wrong-target"}, "PRODUCTION_SIGNER_STORAGE_ATTESTATION_TARGET_MISMATCH"),
        ({"guest_key_file_mode": "0o644"}, "PRODUCTION_SIGNER_GUEST_PERMISSION_POLICY_INVALID"),
        ({"host_admin_boundary_claimed": True}, "PRODUCTION_SIGNER_HOST_ADMIN_BOUNDARY_OVERCLAIMED"),
    ],
)
def test_storage_attestation_model_negative_matrix(mutation, expected):
    provider, record = _encrypted_provider(f"storage-negative-{expected.lower()}")
    with pytest.raises(CoreError, match=expected):
        attestation = _storage_attestation(provider, record, **mutation)
        validate_file_backed_provider_policy(provider, storage_attestation=attestation, environment=record.environment, target_reference=record.target_reference)


def test_d_backed_wsl_rootfs_attestation_accepts_posix_and_unc_paths(tmp_path):
    passphrase = b"unit-test-passphrase-not-production"
    key = Ed25519PrivateKey.generate()
    encrypted_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    key_path = tmp_path / "qingyu-prod-signer-01.pem"
    key_path.write_bytes(encrypted_pem)
    posix_provider = EncryptedFileBackedEd25519SignerProvider(
        provider_reference="qingyu-prod-signer-01",
        encrypted_private_key_path=str(key_path),
        passphrase_provider=lambda: passphrase,
        classification=SignerProviderClassification.PRODUCTION_ELIGIBLE,
    )
    record = TrustRecord.from_provider(
        trust_reference="trust:wsl-attested",
        provider=posix_provider,
        environment="qingyu-production-primary",
        target_reference="prod-target-ref-001",
        generation=1,
        created_at=NOW,
    )
    root = Path("<repo>/production/qingyu-prod-local-01")
    root.mkdir(parents=True, exist_ok=True)
    (root / "ext4.vhdx").touch(exist_ok=True)
    attestation = ProductionSignerStorageAttestation(
        storage_class=ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value,
        distro_reference="qingyu-prod-local-01",
        wsl_version=2,
        registered_base_path=str(root),
        approved_qingyu_root=str(root),
        provider_reference=posix_provider.provider_reference,
        environment=record.environment,
        target_reference=record.target_reference,
        logical_secret_path_reference="/etc/qingyu/secrets/production-signer/qingyu-prod-signer-01.pem",
        host_backing_volume="D:",
        host_backing_artifact_reference=str(root / "ext4.vhdx"),
        qingyu_storage_root_reference=str(root),
        backing_verified=True,
        attested_by=TRUSTED_STORAGE_INSPECTOR_ATTESTED_BY,
        os_observed=True,
        observed_at=NOW,
        created_at=NOW,
    )
    # The product accepts WSL rootfs only via attestation; path spelling alone is not authority.
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_STORAGE_ATTESTATION_PATH_MISMATCH"):
        validate_file_backed_provider_policy(posix_provider, storage_attestation=attestation, environment=record.environment, target_reference=record.target_reference)
    unc_provider = EncryptedFileBackedEd25519SignerProvider(
        provider_reference="qingyu-prod-signer-01",
        encrypted_private_key_path="//wsl.localhost/qingyu-prod-local-01/etc/qingyu/secrets/production-signer/qingyu-prod-signer-01.pem",
        passphrase_provider=lambda: passphrase,
        classification=SignerProviderClassification.PRODUCTION_ELIGIBLE,
    )
    assert unc_provider.encrypted_private_key_path.endswith(attestation.logical_secret_path_reference)
    # Do not open the synthetic UNC path in unit tests; path matching is covered separately from file IO.
    assert attestation.storage_class == ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value


def test_unencrypted_key_fails_storage_policy(tmp_path):
    passphrase = b"unit-test-passphrase-not-production"
    key = Ed25519PrivateKey.generate()
    unencrypted_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path = _d_backed_test_dir("unencrypted-key") / "signer.pem"
    key_path.write_bytes(unencrypted_pem)
    provider = EncryptedFileBackedEd25519SignerProvider(
        provider_reference="unencrypted-key",
        encrypted_private_key_path=str(key_path),
        passphrase_provider=lambda: passphrase,
        classification=SignerProviderClassification.PRODUCTION_ELIGIBLE,
    )
    record = TrustRecord.from_provider(
        trust_reference="trust:unencrypted-key",
        provider=EncryptedFileBackedEd25519SignerProvider(
            provider_reference="unencrypted-key",
            encrypted_private_key_path=str(_encrypted_provider("unencrypted-key-record")[0].encrypted_private_key_path),
            passphrase_provider=lambda: passphrase,
            classification=SignerProviderClassification.PRODUCTION_ELIGIBLE,
        ),
        environment="qingyu-real-prod-primary",
        target_reference="target-real-001",
        generation=1,
        created_at=NOW,
    )
    with pytest.raises(CoreError, match="SIGNER_PROVIDER_ENCRYPTION_FORMAT_INVALID"):
        validate_file_backed_provider_policy(provider, storage_attestation=_storage_attestation(provider, record), environment=record.environment, target_reference=record.target_reference)


def test_trust_status_errors_distinguish_revoked_and_retired():
    provider = InMemoryEd25519SignerProvider(
        provider_reference="status-provider",
        private_key=Ed25519PrivateKey.generate(),
    )
    active = TrustRecord.from_provider(
        trust_reference="trust:status",
        provider=provider,
        environment="env",
        target_reference="target",
        generation=1,
        created_at=NOW,
    )
    payload = {"intent_id": "status", "signer_key_id": active.key_id}
    signature = sign_smi_payload(provider, payload)
    verify_smi_signature(canonical_payload=payload, signature_hex=signature, trust_record=active)
    with pytest.raises(CoreError, match="SMI_SIGNER_TRUST_REVOKED"):
        verify_smi_signature(canonical_payload=payload, signature_hex=signature, trust_record=active.model_copy(update={"status": TrustStatus.REVOKED}))
    with pytest.raises(CoreError, match="SMI_SIGNER_TRUST_RETIRED"):
        verify_smi_signature(canonical_payload=payload, signature_hex=signature, trust_record=active.model_copy(update={"status": TrustStatus.RETIRED}))


def test_wsl_storage_observation_must_be_trusted_os_observed_and_fresh():
    observation = _trusted_wsl_observation()
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_STORAGE_ATTESTATION_NOT_OS_OBSERVED"):
        ProductionSignerStorageInspector().attest(observation)
    stale = TrustedTestStorageInspector(_trusted_wsl_observation(observed_at=NOW - timedelta(days=30)))
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_STORAGE_ATTESTATION_STALE"):
        stale.inspect(provider=type("P", (), {"provider_reference": "qingyu-prod-signer-01"})(), environment="qingyu-production-primary", target_reference="prod-target-ref-001")


def test_wsl_storage_canonical_path_and_backing_artifact_negatives():
    root = Path("<repo>/production/qingyu-prod-local-01")
    evil = root.parent / "evil"
    evil.mkdir(parents=True, exist_ok=True)
    (evil / "ext4.vhdx").touch(exist_ok=True)
    traversal = str(root / "wsl" / ".." / ".." / "evil" / "ext4.vhdx")
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_WSL_BACKING_ARTIFACT_INVALID|PRODUCTION_SIGNER_STORAGE_ROOT_UNAPPROVED"):
        TrustedTestStorageInspector(_trusted_wsl_observation(host_backing_artifact_reference=traversal)).inspect(provider=type("P", (), {"provider_reference": "qingyu-prod-signer-01"})(), environment="qingyu-production-primary", target_reference="prod-target-ref-001")
    missing = str(root / "wsl" / "missing.vhdx")
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_WSL_BACKING_ARTIFACT_INVALID"):
        TrustedTestStorageInspector(_trusted_wsl_observation(host_backing_artifact_reference=missing)).inspect(provider=type("P", (), {"provider_reference": "qingyu-prod-signer-01"})(), environment="qingyu-production-primary", target_reference="prod-target-ref-001")


def test_real_production_does_not_accept_caller_fabricated_wsl_attestation_or_inspector():
    provider, record, store = _real_wsl_production_provider_record_admission()
    fabricated = TrustedTestStorageInspector(_trusted_wsl_observation(provider_reference=provider.provider_reference, environment=record.environment, target_reference=record.target_reference)).inspect(provider=provider, environment=record.environment, target_reference=record.target_reference)
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        ensure_production_eligible(record, mode=AuthorityEnvironmentMode.REAL_PRODUCTION, admission_store=store, signer_provider=provider, storage_attestation=fabricated)
    with pytest.raises(TypeError, match="unexpected keyword argument"):
        ensure_production_eligible(record, mode=AuthorityEnvironmentMode.REAL_PRODUCTION, admission_store=store, signer_provider=provider, storage_inspector=TrustedTestStorageInspector(_trusted_wsl_observation()))

