from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.b2_signer_trust import (
    APPROVED_R1_PRODUCTION_PROVIDER_BACKEND,
    PRODUCTION_PERMISSION_POLICY,
    PRODUCTION_STORAGE_POLICY,
    AuthorityEnvironmentMode,
    EncryptedFileBackedEd25519SignerProvider,
    InMemoryEd25519SignerProvider,
    ProductionSignerAdmissionRecord,
    ProductionSignerAdmissionStatus,
    ProductionSignerAdmissionStore,
    SignerProviderClassification,
    TrustRecord,
    TrustStatus,
    ensure_production_eligible,
    sign_smi_payload,
    verify_smi_signature,
)
from app.errors import CoreError
import pytest

NOW = datetime(2026, 9, 20, 12, 0, tzinfo=timezone.utc)


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


def test_real_production_admission_accepts_only_file_backed_provider_with_matching_record():
    provider, record = _encrypted_provider("prod-provider-positive")
    store = ProductionSignerAdmissionStore({"a": _admission(record)})
    ensure_production_eligible(
        record,
        mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
        admission_store=store,
        signer_provider=provider,
    )


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
