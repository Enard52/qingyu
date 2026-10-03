from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
from threading import Barrier
from urllib.parse import quote

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.b2_production_authority import SYNTHETIC_PRODUCTION_TEST
from app.b2_signer_trust import (
    AuthorityEnvironmentMode,
    EncryptedFileBackedEd25519SignerProvider,
    InMemoryEd25519SignerProvider,
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID,
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION,
    POSTGRES_PRODUCTION_TRUST_STORE_MIGRATION_ID,
    PostgresProductionSignerAdmissionStore,
    PostgresProductionTrustStore,
    ProductionSignerAdmissionProvisioningService,
    ProductionSignerAdmissionRecord,
    ProductionSignerAdmissionRecoveryBinding,
    ProductionSignerAdmissionStatus,
    ProductionSignerAdmissionStore,
    ProductionSignerStorageClass,
    ProductionSignerStorageInspectionResult,
    ProductionSignerStorageInspector,
    R1_PRODUCTION_CONTROL_DATABASE_NAME,
    SignerProviderClassification,
    TrustRecord,
    TrustStatus,
    TrustStore,
    PRODUCTION_WSL_ROOTFS_STORAGE_POLICY,
    _admission_record_hash,
    _admission_record_payload,
    _trust_record_hash,
    apply_postgres_production_signer_admission_store_migration,
    apply_postgres_production_trust_store_migration,
    apply_r1_production_signer_admission_store_migration,
    apply_r1_production_trust_store_migration,
    require_postgres_production_signer_admission_store_config,
)
import app.b2_signer_trust as signer_trust_module
from app.errors import CoreError
from tests.test_foundation_closure_rehearsal import FoundationPostgresEnvironment

NOW = datetime(2026, 9, 24, 12, 0, 0, 123456, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def pg_env(tmp_path_factory):
    env = FoundationPostgresEnvironment(tmp_path_factory.mktemp("b2_admission_store")).create()
    try:
        yield env
    finally:
        env.destroy()


@pytest.fixture()
def control_db(pg_env):
    name = "admission_store_" + datetime.now(timezone.utc).strftime("%H%M%S%f")
    pg_env.create_database(name)
    return name


def trust_record(*, trust_reference="admission-trust-01", environment=SYNTHETIC_PRODUCTION_TEST, target_reference="admission-target-01"):
    provider = InMemoryEd25519SignerProvider(
        provider_reference=f"admission-signer:{trust_reference}",
        private_key=Ed25519PrivateKey.generate(),
        classification=SignerProviderClassification.SYNTHETIC_PRODUCTION_TEST_ONLY,
    )
    record = TrustRecord.from_provider(
        trust_reference=trust_reference,
        provider=provider,
        environment=environment,
        target_reference=target_reference,
        generation=1,
        created_at=NOW,
        status=TrustStatus.ACTIVE,
    )
    return provider, record


def admission_for(record: TrustRecord, **updates):
    data = {
        "admission_reference": "admission:primary",
        "provider_reference": record.provider_reference,
        "provider_backend_type": record.provider_backend_type,
        "algorithm": record.algorithm,
        "key_id": record.key_id,
        "public_key_fingerprint": record.public_key_fingerprint,
        "environment": record.environment,
        "target_reference": record.target_reference,
        "storage_policy": "D_BACKED_QINGYU_PROTECTED_STORAGE",
        "storage_class": None,
        "permission_policy": "GUEST_OWNER_ONLY_0700_0600",
        "custody_policy_version": "admission-custody-policy-v1",
        "provisioning_reference": "admission-foundation-rehearsal",
        "provisioning_generation": 1,
        "status": ProductionSignerAdmissionStatus.ACTIVE,
        "created_at": NOW,
    }
    data.update(updates)
    return ProductionSignerAdmissionRecord(**data)


def admission_with(record: ProductionSignerAdmissionRecord, **updates):
    data = record.model_dump()
    data.update(updates)
    return ProductionSignerAdmissionRecord(**data)


def migrate_both(url: str, database: str) -> None:
    apply_postgres_production_trust_store_migration(url, expected_database_name=database)
    apply_postgres_production_signer_admission_store_migration(url, expected_database_name=database)


def least_privilege_provisioner_url(pg_env, database: str) -> str:
    import psycopg

    role = "qingyu_control_provisioner"
    password = "least_privilege_provisioner_test_only"
    with psycopg.connect(host="127.0.0.1", port=pg_env.port, dbname=database, user="postgres", password=pg_env.password) as connection:
        connection.execute(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qingyu_control_provisioner') THEN
                    CREATE ROLE qingyu_control_provisioner LOGIN PASSWORD 'least_privilege_provisioner_test_only'
                        NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
                END IF;
            END
            $$;
            """
        )
        connection.execute("GRANT CONNECT ON DATABASE " + connection.info.dbname + " TO qingyu_control_provisioner")
        connection.execute("GRANT USAGE ON SCHEMA governance TO qingyu_control_provisioner")
        connection.execute("GRANT SELECT ON governance.production_trust_records TO qingyu_control_provisioner")
        connection.execute("GRANT SELECT, INSERT ON governance.production_signer_admission_records TO qingyu_control_provisioner")
        connection.execute("REVOKE UPDATE, DELETE, TRUNCATE ON governance.production_signer_admission_records FROM qingyu_control_provisioner")
    authority = f"{role}:{quote(password)}" + f"@127.0.0.1:{pg_env.port}"
    return "postgresql+psycopg://" + authority + f"/{database}"


def provisioner_privileges(pg_env, database: str) -> dict[str, bool]:
    import psycopg

    with psycopg.connect(host="127.0.0.1", port=pg_env.port, dbname=database, user="postgres", password=pg_env.password) as connection:
        row = connection.execute(
            """
            SELECT has_table_privilege('qingyu_control_provisioner','governance.production_signer_admission_records','SELECT'),
                   has_table_privilege('qingyu_control_provisioner','governance.production_signer_admission_records','INSERT'),
                   has_table_privilege('qingyu_control_provisioner','governance.production_signer_admission_records','UPDATE'),
                   has_table_privilege('qingyu_control_provisioner','governance.production_signer_admission_records','DELETE'),
                   has_table_privilege('qingyu_control_provisioner','governance.production_signer_admission_records','TRUNCATE')
            """
        ).fetchone()
    return {"select": row[0], "insert": row[1], "update": row[2], "delete": row[3], "truncate": row[4]}


def provisioner_role_attributes(pg_env, database: str) -> dict[str, bool]:
    import psycopg

    with psycopg.connect(host="127.0.0.1", port=pg_env.port, dbname=database, user="postgres", password=pg_env.password) as connection:
        row = connection.execute(
            """
            SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls
              FROM pg_roles
             WHERE rolname = 'qingyu_control_provisioner'
            """
        ).fetchone()
    return {"superuser": row[0], "createdb": row[1], "createrole": row[2], "bypassrls": row[3]}


def _governance_objects(pg_env, database: str) -> tuple[bool, bool, bool]:
    import psycopg

    with psycopg.connect(host="127.0.0.1", port=pg_env.port, dbname=database, user="postgres", password=pg_env.password) as connection:
        schema_exists = connection.execute("SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name='governance')").fetchone()[0]
        trust_exists = connection.execute(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='governance' AND table_name='production_trust_records')"
        ).fetchone()[0]
        admission_exists = connection.execute(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='governance' AND table_name='production_signer_admission_records')"
        ).fetchone()[0]
    return bool(schema_exists), bool(trust_exists), bool(admission_exists)


def test_admission_hash_canonicalizes_timezone_equivalent_instants_and_rejects_naive_datetime():
    _, trust = trust_record()
    instant = datetime(2026, 9, 22, 12, 13, 58, 598009, tzinfo=timezone.utc)
    offsets = [timezone.utc, timezone(timedelta(0)), timezone(timedelta(hours=-12)), timezone(timedelta(hours=8))]

    hashes = {
        _admission_record_hash(admission_for(trust, created_at=instant.astimezone(offset)))
        for offset in offsets
    }
    payloads = [
        _admission_record_payload(admission_for(trust, created_at=instant.astimezone(offset)))
        for offset in offsets
    ]

    assert len(hashes) == 1
    assert {payload["created_at"] for payload in payloads} == {"2026-09-22T12:13:58.598009Z"}
    assert _admission_record_hash(admission_for(trust, created_at=instant + timedelta(microseconds=1))) not in hashes
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_CREATED_AT_TIMEZONE_REQUIRED"):
        admission_for(trust, created_at=datetime(2026, 9, 22, 12, 13, 58, 598009))


def test_explicit_migration_roundtrip_hash_restart_and_schema_metadata(pg_env, control_db):
    url = pg_env.url(control_db)
    _, trust = trust_record()
    admission = admission_for(trust)
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_REQUIRED"):
        PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db).resolve(admission.admission_reference)

    migrate_both(url, control_db)
    trust_store = PostgresProductionTrustStore(url, expected_database_name=control_db)
    admission_store = PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db)
    assert trust_store.create_if_absent_exact(trust) == "CREATED"
    assert admission_store.create_if_absent_exact(admission, provenance={"test": "roundtrip"}) == "CREATED"
    assert admission_store.create_if_absent_exact(admission, provenance={"test": "idempotent"}) == "IDEMPOTENT_EXISTING"

    restarted = PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db)
    reloaded = restarted.resolve(admission.admission_reference)
    assert reloaded == admission
    assert _admission_record_hash(reloaded) == admission.admission_hash
    assert restarted.resolve_for_trust(trust) == admission

    import psycopg
    with psycopg.connect(host="127.0.0.1", port=pg_env.port, dbname=control_db, user="postgres", password=pg_env.password) as connection:
        migrations = dict(connection.execute("SELECT migration_id, schema_version FROM governance.schema_migrations").fetchall())
    assert migrations[POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID] == POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION
    assert migrations[POSTGRES_PRODUCTION_TRUST_STORE_MIGRATION_ID]


def test_postgres_timestamp_with_session_timezone_roundtrips_to_same_admission_hash(pg_env, control_db):
    url = pg_env.url(control_db)
    _, trust = trust_record(trust_reference="timezone-admission")
    admission = admission_for(trust, admission_reference="admission:timezone", created_at=datetime(2026, 9, 22, 12, 13, 58, 598009, tzinfo=timezone.utc))
    migrate_both(url, control_db)
    assert PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db).create_if_absent_exact(admission) == "CREATED"

    timezone_url = url + "?options=" + quote("-c timezone=Etc/GMT+12")
    reloaded = PostgresProductionSignerAdmissionStore(timezone_url, expected_database_name=control_db).resolve(admission.admission_reference)

    assert reloaded == admission
    assert _admission_record_hash(reloaded) == _admission_record_hash(admission)


@pytest.mark.parametrize(
    "mutation",
    [
        {"key_id": "0" * 64},
        {"public_key_fingerprint": "1" * 64},
        {"environment": "wrong-env"},
        {"target_reference": "wrong-target"},
        {"provisioning_reference": "different-provisioning"},
        {"status": ProductionSignerAdmissionStatus.REVOKED},
    ],
)
def test_conflicting_admission_identity_fails_closed(pg_env, control_db, mutation):
    url = pg_env.url(control_db)
    migrate_both(url, control_db)
    _, trust = trust_record()
    admission = admission_for(trust)
    store = PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db)
    assert store.create_if_absent_exact(admission) == "CREATED"
    changed = admission_with(admission, **mutation)
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_IDENTITY_CONFLICT|PRODUCTION_SIGNER_ADMISSION_HEX_INVALID"):
        store.create_if_absent_exact(changed)
    assert store.resolve(admission.admission_reference) == admission


def test_concurrent_identical_admission_create_is_idempotent(pg_env, control_db):
    url = pg_env.url(control_db)
    migrate_both(url, control_db)
    _, trust = trust_record()
    admission = admission_for(trust)
    barrier = Barrier(6)

    def create_once():
        barrier.wait(timeout=10)
        return PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db).create_if_absent_exact(admission)

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(lambda _: create_once(), range(6)))
    assert results.count("CREATED") == 1
    assert results.count("IDEMPOTENT_EXISTING") == 5
    assert PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db).count() == 1


def test_concurrent_conflicting_admission_create_accepts_one_identity(pg_env, control_db):
    url = pg_env.url(control_db)
    migrate_both(url, control_db)
    _, first_trust = trust_record(trust_reference="concurrent-conflict")
    _, second_trust = trust_record(trust_reference="concurrent-conflict")
    first = admission_for(first_trust, admission_reference="admission:conflict")
    second = admission_for(second_trust, admission_reference="admission:conflict")
    barrier = Barrier(2)

    def create(record):
        barrier.wait(timeout=10)
        try:
            return PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db).create_if_absent_exact(record)
        except CoreError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(create, [first, second]))
    assert sorted(results) == ["CREATED", "PRODUCTION_SIGNER_ADMISSION_IDENTITY_CONFLICT"]
    assert PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db).count() == 1


def test_wrong_database_migration_and_store_reject_before_any_ddl(pg_env):
    wrong = "not_qingyu_control_for_admission"
    pg_env.create_database(wrong)
    assert _governance_objects(pg_env, wrong) == (False, False, False)
    with pytest.raises(CoreError, match="DATABASE_SAFETY_VIOLATION"):
        apply_r1_production_signer_admission_store_migration(pg_env.url(wrong))
    assert _governance_objects(pg_env, wrong) == (False, False, False)
    with pytest.raises(CoreError, match="DATABASE_SAFETY_VIOLATION"):
        PostgresProductionSignerAdmissionStore(pg_env.url(wrong), expected_database_name=R1_PRODUCTION_CONTROL_DATABASE_NAME).count()
    assert _governance_objects(pg_env, wrong) == (False, False, False)


def test_correct_canonical_qingyu_control_rehearsal_migrates_admission_store(pg_env):
    pg_env.create_database(R1_PRODUCTION_CONTROL_DATABASE_NAME)
    apply_r1_production_trust_store_migration(pg_env.url(R1_PRODUCTION_CONTROL_DATABASE_NAME))
    apply_r1_production_signer_admission_store_migration(pg_env.url(R1_PRODUCTION_CONTROL_DATABASE_NAME))
    assert _governance_objects(pg_env, R1_PRODUCTION_CONTROL_DATABASE_NAME) == (True, True, True)


def test_real_production_missing_config_fails_closed_without_memory_fallback():
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_STORE_CONFIG_REQUIRED"):
        require_postgres_production_signer_admission_store_config(
            mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
            sqlalchemy_url=None,
        )


def test_recovery_gate_requires_immutable_frozen_evidence_not_boolean():
    good = ProductionSignerAdmissionRecoveryBinding(
        ext_rec_01_status="CLOSED",
        source_backup_sha256="0bcac9aacb35372e8ae732bef3fc39c5033e623fffe54421dd8c85aaa2c5f362",
        encrypted_asset_sha256="fa906348960fcaac7d5e2f752a346efcbebf0e19d3786059677ced0efae6abd0",
        release_identifier="backup-trust-control-20260924T142657Z-073c4f3a",
        remote_asset_identifier="RA_kwDOUikIh84i76Iu",
        remote_repository_visibility="PRIVATE",
    )
    assert good.validate_binding() is good
    with pytest.raises(TypeError):
        ProductionSignerAdmissionRecoveryBinding(recovery_ready=True)  # type: ignore[call-arg]
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_RECOVERY_GATE_NOT_CLOSED"):
        ProductionSignerAdmissionRecoveryBinding(
            ext_rec_01_status="OPEN",
            source_backup_sha256=good.source_backup_sha256,
            encrypted_asset_sha256=good.encrypted_asset_sha256,
            release_identifier=good.release_identifier,
            remote_asset_identifier=good.remote_asset_identifier,
            remote_repository_visibility=good.remote_repository_visibility,
        ).validate_binding()


def test_admission_store_has_no_authority_smi_genesis_or_qingyu_prod_side_effects(pg_env, control_db):
    url = pg_env.url(control_db)
    migrate_both(url, control_db)
    _, trust = trust_record(trust_reference="side-effect-boundary")
    admission = admission_for(trust, admission_reference="admission:side-effect-boundary")
    assert PostgresProductionTrustStore(url, expected_database_name=control_db).create_if_absent_exact(trust) == "CREATED"
    assert PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db).create_if_absent_exact(admission) == "CREATED"

    import psycopg
    with psycopg.connect(host="127.0.0.1", port=pg_env.port, dbname=control_db, user="postgres", password=pg_env.password) as connection:
        schemas = {row[0] for row in connection.execute("SELECT schema_name FROM information_schema.schemata").fetchall()}
        governance_tables = {
            row[0]
            for row in connection.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='governance'"
            ).fetchall()
        }
    assert "qingyu_prod" not in schemas
    assert governance_tables == {
        "schema_migrations",
        "production_trust_records",
        "production_signer_admission_records",
    }
    assert not any("authority" in table for table in governance_tables)
    assert not any("smi" in table for table in governance_tables)
    assert not any("genesis" in table for table in governance_tables)


def test_pg_dump_restore_preserves_trust_and_admission_identity(pg_env, control_db, tmp_path):
    url = pg_env.url(control_db)
    migrate_both(url, control_db)
    _, trust = trust_record()
    admission = admission_for(trust)
    assert PostgresProductionTrustStore(url, expected_database_name=control_db).create_if_absent_exact(trust) == "CREATED"
    assert PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db).create_if_absent_exact(admission) == "CREATED"

    dump_path = tmp_path / "admission-store.sql"
    pg_env.dump(control_db, dump_path)
    restored = control_db + "_restore"
    pg_env.restore(restored, dump_path)
    assert PostgresProductionTrustStore(pg_env.url(restored), expected_database_name=restored).resolve(trust.trust_reference) == trust
    restored_admission = PostgresProductionSignerAdmissionStore(pg_env.url(restored), expected_database_name=restored).resolve(admission.admission_reference)
    assert restored_admission == admission
    assert _admission_record_hash(restored_admission) == admission.admission_hash
    assert _trust_record_hash(PostgresProductionTrustStore(pg_env.url(restored), expected_database_name=restored).resolve(trust.trust_reference)) == _trust_record_hash(trust)


class TrustedServiceStorageInspector(ProductionSignerStorageInspector):
    inspector_version = "qingyu-b2-service-entrypoint-test-inspector"
    trusted_for_real_production = True

    def __init__(self, observation: ProductionSignerStorageInspectionResult):
        self.observation = observation

    def inspect(self, *, provider, environment: str, target_reference: str):
        return self.attest(self.observation)


def recovery_binding(**updates):
    data = {
        "ext_rec_01_status": "CLOSED",
        "source_backup_sha256": "0bcac9aacb35372e8ae732bef3fc39c5033e623fffe54421dd8c85aaa2c5f362",
        "encrypted_asset_sha256": "fa906348960fcaac7d5e2f752a346efcbebf0e19d3786059677ced0efae6abd0",
        "release_identifier": "backup-trust-control-20260924T142657Z-073c4f3a",
        "remote_asset_identifier": "RA_kwDOUikIh84i76Iu",
        "remote_repository_visibility": "PRIVATE",
    }
    data.update(updates)
    return ProductionSignerAdmissionRecoveryBinding(**data)


def encrypted_provider(tmp_path: Path, name="entrypoint-provider", *, key=None):
    passphrase = b"unit-test-passphrase-not-production"
    key = key or Ed25519PrivateKey.generate()
    encrypted_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )
    key_path = tmp_path / f"{name}.encrypted.pem"
    key_path.write_bytes(encrypted_pem)
    return EncryptedFileBackedEd25519SignerProvider(
        provider_reference=name,
        encrypted_private_key_path=str(key_path),
        passphrase_provider=lambda: passphrase,
        classification=SignerProviderClassification.PRODUCTION_ELIGIBLE,
    )


def trusted_storage_observation(provider, record, tmp_path: Path):
    root = Path("<repo>/production/qingyu-prod-local-01/temp/entrypoint-service-tests") / tmp_path.name
    registered = root / "wsl"
    registered.mkdir(parents=True, exist_ok=True)
    vhdx = registered / "ext4.vhdx"
    vhdx.touch(exist_ok=True)
    return ProductionSignerStorageInspectionResult(
        signer_reference=provider.provider_reference,
        provider_reference=provider.provider_reference,
        environment=record.environment,
        target_reference=record.target_reference,
        storage_class=ProductionSignerStorageClass.D_BACKED_WSL_ROOTFS.value,
        distro_reference="qingyu-prod-local-01",
        wsl_version=2,
        registered_base_path=str(registered),
        host_backing_artifact_reference=str(vhdx),
        qingyu_storage_root_reference=str(root),
        logical_secret_path_reference="/etc/qingyu/secrets/production-signer/qingyu-prod-signer-01.pem",
        guest_secret_dir_mode="0o700",
        guest_key_file_mode="0o600",
        guest_passphrase_file_mode="0o600",
        encrypted_format_verified=True,
        passphrase_separation_verified=True,
        host_acl_state="HOST_STORAGE_ACL_ACCEPTABLE",
        observed_at=datetime.now(timezone.utc),
    )


def service_entrypoint_fixture(pg_env, control_db, tmp_path, monkeypatch, *, trust=True, provider_name="entrypoint-provider", key=None, recovery=None):
    url = pg_env.url(control_db)
    migrate_both(url, control_db)
    provider = encrypted_provider(tmp_path, provider_name, key=key)
    record = TrustRecord.from_provider(
        trust_reference="entrypoint-trust-01",
        provider=provider,
        environment="qingyu-production-primary",
        target_reference="prod-target-ref-001",
        generation=1,
        created_at=NOW,
        status=TrustStatus.ACTIVE,
    )
    monkeypatch.setattr(
        signer_trust_module,
        "build_r1_production_signer_storage_inspector",
        lambda: TrustedServiceStorageInspector(trusted_storage_observation(provider, record, tmp_path)),
    )
    monkeypatch.setattr(signer_trust_module, "_provider_key_path_matches_attestation", lambda *_args, **_kwargs: True)
    trust_store = PostgresProductionTrustStore(url, expected_database_name=control_db)
    if trust:
        assert trust_store.create_if_absent_exact(record) == "CREATED"
    admission_store = PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db)
    service = ProductionSignerAdmissionProvisioningService(
        trust_store=trust_store,
        admission_store=admission_store,
        signer_provider=provider,
        recovery_binding=recovery or recovery_binding(),
    )
    return service, trust_store, admission_store, provider, record


def create_via_service(service, record, *, admission_reference="admission:service-entrypoint", provisioning_reference="service-entrypoint-test"):
    return service.create_admission(
        admission_reference=admission_reference,
        trust_reference=record.trust_reference,
        custody_policy_version="service-entrypoint-custody-v1",
        provisioning_reference=provisioning_reference,
        provisioning_generation=1,
        created_at=NOW,
        provenance={"test": "direct-service-entrypoint"},
    )


def test_direct_service_entrypoint_success_idempotency_readback_and_trust_preservation(pg_env, control_db, tmp_path, monkeypatch):
    service, trust_store, admission_store, _, record = service_entrypoint_fixture(pg_env, control_db, tmp_path, monkeypatch)
    before_hash = _trust_record_hash(trust_store.resolve(record.trust_reference))

    assert create_via_service(service, record) == "CREATED"
    assert create_via_service(service, record) == "IDEMPOTENT_EXISTING"

    admission = service.read_admission("admission:service-entrypoint")
    assert admission_store.count() == 1
    assert admission.admission_reference == "admission:service-entrypoint"
    assert admission.provider_reference == record.provider_reference
    assert admission.key_id == record.key_id
    assert admission.storage_policy == PRODUCTION_WSL_ROOTFS_STORAGE_POLICY
    assert _admission_record_hash(admission) == admission.admission_hash
    assert _trust_record_hash(trust_store.resolve(record.trust_reference)) == before_hash


def test_direct_service_missing_durable_trust_fails_closed_without_fallback(pg_env, control_db, tmp_path, monkeypatch):
    service, _, admission_store, _, record = service_entrypoint_fixture(pg_env, control_db, tmp_path, monkeypatch, trust=False)
    with pytest.raises(CoreError, match="SMI_SIGNER_TRUST_NOT_FOUND"):
        create_via_service(service, record)
    assert admission_store.count() == 0


def test_direct_service_rejects_in_memory_stores(pg_env, control_db, tmp_path):
    provider, record = trust_record(trust_reference="in-memory-entrypoint")
    admission_store = PostgresProductionSignerAdmissionStore(pg_env.url(control_db), expected_database_name=control_db)
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_TRUST_STORE_REQUIRED"):
        ProductionSignerAdmissionProvisioningService(
            trust_store=TrustStore({record.trust_reference: record}),  # type: ignore[name-defined]
            admission_store=admission_store,
            signer_provider=provider,
            recovery_binding=recovery_binding(),
        )
    url = pg_env.url(control_db)
    apply_postgres_production_trust_store_migration(url, expected_database_name=control_db)
    trust_store = PostgresProductionTrustStore(url, expected_database_name=control_db)
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_DURABLE_STORE_REQUIRED"):
        ProductionSignerAdmissionProvisioningService(
            trust_store=trust_store,
            admission_store=ProductionSignerAdmissionStore(),  # type: ignore[name-defined]
            signer_provider=provider,
            recovery_binding=recovery_binding(),
        )


@pytest.mark.parametrize(
    "mutation, expected",
    [
        ({"ext_rec_01_status": "OPEN"}, "PRODUCTION_SIGNER_ADMISSION_RECOVERY_GATE_NOT_CLOSED"),
        ({"source_backup_sha256": "0" * 64}, "PRODUCTION_SIGNER_ADMISSION_RECOVERY_SOURCE_MISMATCH"),
        ({"encrypted_asset_sha256": "1" * 64}, "PRODUCTION_SIGNER_ADMISSION_RECOVERY_ASSET_MISMATCH"),
        ({"release_identifier": "wrong-release"}, "PRODUCTION_SIGNER_ADMISSION_RECOVERY_RELEASE_MISMATCH"),
        ({"remote_asset_identifier": "wrong-asset"}, "PRODUCTION_SIGNER_ADMISSION_RECOVERY_ASSET_MISMATCH"),
        ({"remote_repository_visibility": "PUBLIC"}, "PRODUCTION_SIGNER_ADMISSION_RECOVERY_VISIBILITY_MISMATCH"),
    ],
)
def test_direct_service_recovery_binding_failures_happen_before_mutation(pg_env, control_db, tmp_path, monkeypatch, mutation, expected):
    with pytest.raises(CoreError, match=expected):
        service_entrypoint_fixture(pg_env, control_db, tmp_path, monkeypatch, recovery=recovery_binding(**mutation))
    migrate_both(pg_env.url(control_db), control_db)
    assert PostgresProductionSignerAdmissionStore(pg_env.url(control_db), expected_database_name=control_db).count() == 0


def test_direct_service_signer_trust_mismatch_matrix_fails_before_mutation(pg_env, control_db, tmp_path, monkeypatch):
    service, trust_store, admission_store, provider, record = service_entrypoint_fixture(pg_env, control_db, tmp_path, monkeypatch)
    mismatched_provider = encrypted_provider(tmp_path, "different-provider")
    provider_ref_mismatch = ProductionSignerAdmissionProvisioningService(
        trust_store=trust_store,
        admission_store=admission_store,
        signer_provider=mismatched_provider,
        recovery_binding=recovery_binding(),
    )
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_PROVIDER_MISMATCH"):
        create_via_service(provider_ref_mismatch, record, admission_reference="admission:provider-mismatch")

    different_key_provider = encrypted_provider(tmp_path, provider.provider_reference)
    key_mismatch = ProductionSignerAdmissionProvisioningService(
        trust_store=trust_store,
        admission_store=admission_store,
        signer_provider=different_key_provider,
        recovery_binding=recovery_binding(),
    )
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_KEY_ID_MISMATCH"):
        create_via_service(key_mismatch, record, admission_reference="admission:key-mismatch")

    in_memory = InMemoryEd25519SignerProvider(
        provider_reference=provider.provider_reference,
        private_key=Ed25519PrivateKey.generate(),
        classification=SignerProviderClassification.PRODUCTION_ELIGIBLE,
    )
    backend_mismatch = ProductionSignerAdmissionProvisioningService(
        trust_store=trust_store,
        admission_store=admission_store,
        signer_provider=in_memory,
        recovery_binding=recovery_binding(),
    )
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_KEY_ID_MISMATCH|PRODUCTION_SIGNER_PROVIDER_BACKEND_NOT_APPROVED"):
        create_via_service(backend_mismatch, record, admission_reference="admission:backend-mismatch")

    assert admission_store.count() == 0


def test_direct_service_wrong_database_rejects_before_admission_mutation(pg_env, tmp_path, monkeypatch):
    wrong = "entrypoint_wrong_db"
    pg_env.create_database(wrong)
    assert _governance_objects(pg_env, wrong) == (False, False, False)
    provider = encrypted_provider(tmp_path, "wrong-db-provider")
    record = TrustRecord.from_provider(
        trust_reference="wrong-db-trust",
        provider=provider,
        environment="qingyu-production-primary",
        target_reference="prod-target-ref-001",
        generation=1,
        created_at=NOW,
    )
    monkeypatch.setattr(
        signer_trust_module,
        "build_r1_production_signer_storage_inspector",
        lambda: TrustedServiceStorageInspector(trusted_storage_observation(provider, record, tmp_path)),
    )
    monkeypatch.setattr(signer_trust_module, "_provider_key_path_matches_attestation", lambda *_args, **_kwargs: True)
    guarded_service = ProductionSignerAdmissionProvisioningService(
        trust_store=PostgresProductionTrustStore(pg_env.url(wrong), expected_database_name=R1_PRODUCTION_CONTROL_DATABASE_NAME),
        admission_store=PostgresProductionSignerAdmissionStore(pg_env.url(wrong), expected_database_name=R1_PRODUCTION_CONTROL_DATABASE_NAME),
        signer_provider=provider,
        recovery_binding=recovery_binding(),
    )
    with pytest.raises(CoreError, match="DATABASE_SAFETY_VIOLATION"):
        create_via_service(guarded_service, record)
    assert _governance_objects(pg_env, wrong) == (False, False, False)


def test_direct_service_pre_migration_admission_store_fails_without_opportunistic_table(pg_env, control_db, tmp_path, monkeypatch):
    url = pg_env.url(control_db)
    apply_postgres_production_trust_store_migration(url, expected_database_name=control_db)
    provider = encrypted_provider(tmp_path, "pre-migration-provider")
    record = TrustRecord.from_provider(
        trust_reference="pre-migration-trust",
        provider=provider,
        environment="qingyu-production-primary",
        target_reference="prod-target-ref-001",
        generation=1,
        created_at=NOW,
    )
    assert PostgresProductionTrustStore(url, expected_database_name=control_db).create_if_absent_exact(record) == "CREATED"
    monkeypatch.setattr(
        signer_trust_module,
        "build_r1_production_signer_storage_inspector",
        lambda: TrustedServiceStorageInspector(trusted_storage_observation(provider, record, tmp_path)),
    )
    monkeypatch.setattr(signer_trust_module, "_provider_key_path_matches_attestation", lambda *_args, **_kwargs: True)
    service = ProductionSignerAdmissionProvisioningService(
        trust_store=PostgresProductionTrustStore(url, expected_database_name=control_db),
        admission_store=PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db),
        signer_provider=provider,
        recovery_binding=recovery_binding(),
    )
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_REQUIRED"):
        create_via_service(service, record, admission_reference="admission:pre-migration")
    assert _governance_objects(pg_env, control_db) == (True, True, False)


def test_direct_service_conflict_fails_closed_and_preserves_existing_row(pg_env, control_db, tmp_path, monkeypatch):
    service, _, admission_store, _, record = service_entrypoint_fixture(pg_env, control_db, tmp_path, monkeypatch)
    assert create_via_service(service, record, admission_reference="admission:conflict-service", provisioning_reference="first") == "CREATED"
    before = service.read_admission("admission:conflict-service")
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_IDENTITY_CONFLICT"):
        create_via_service(service, record, admission_reference="admission:conflict-service", provisioning_reference="second")
    assert admission_store.count() == 1
    assert service.read_admission("admission:conflict-service") == before


def test_direct_service_success_has_no_governance_side_effects(pg_env, control_db, tmp_path, monkeypatch):
    service, trust_store, admission_store, _, record = service_entrypoint_fixture(pg_env, control_db, tmp_path, monkeypatch)
    before = _trust_record_hash(trust_store.resolve(record.trust_reference))
    assert create_via_service(service, record, admission_reference="admission:side-effect-service") == "CREATED"
    assert admission_store.count() == 1
    assert _trust_record_hash(trust_store.resolve(record.trust_reference)) == before

    import psycopg
    with psycopg.connect(host="127.0.0.1", port=pg_env.port, dbname=control_db, user="postgres", password=pg_env.password) as connection:
        schemas = {row[0] for row in connection.execute("SELECT schema_name FROM information_schema.schemata").fetchall()}
        governance_tables = {
            row[0]
            for row in connection.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='governance'"
            ).fetchall()
        }
    assert "qingyu_prod" not in schemas
    assert governance_tables == {
        "schema_migrations",
        "production_trust_records",
        "production_signer_admission_records",
    }
    assert not any("authority" in table for table in governance_tables)
    assert not any("smi" in table for table in governance_tables)
    assert not any("genesis" in table for table in governance_tables)


def test_least_privilege_provisioner_service_create_replay_and_conflict_without_update(pg_env, control_db, tmp_path, monkeypatch):
    admin_url = pg_env.url(control_db)
    migrate_both(admin_url, control_db)
    provider = encrypted_provider(tmp_path, "least-privilege-provider")
    record = TrustRecord.from_provider(
        trust_reference="least-privilege-trust",
        provider=provider,
        environment="qingyu-production-primary",
        target_reference="prod-target-ref-001",
        generation=1,
        created_at=NOW,
        status=TrustStatus.ACTIVE,
    )
    monkeypatch.setattr(
        signer_trust_module,
        "build_r1_production_signer_storage_inspector",
        lambda: TrustedServiceStorageInspector(trusted_storage_observation(provider, record, tmp_path)),
    )
    monkeypatch.setattr(signer_trust_module, "_provider_key_path_matches_attestation", lambda *_args, **_kwargs: True)
    assert PostgresProductionTrustStore(admin_url, expected_database_name=control_db).create_if_absent_exact(record) == "CREATED"

    provisioner_url = least_privilege_provisioner_url(pg_env, control_db)
    privileges = provisioner_privileges(pg_env, control_db)
    assert privileges == {"select": True, "insert": True, "update": False, "delete": False, "truncate": False}
    assert provisioner_role_attributes(pg_env, control_db) == {
        "superuser": False,
        "createdb": False,
        "createrole": False,
        "bypassrls": False,
    }
    service = ProductionSignerAdmissionProvisioningService(
        trust_store=PostgresProductionTrustStore(provisioner_url, expected_database_name=control_db),
        admission_store=PostgresProductionSignerAdmissionStore(provisioner_url, expected_database_name=control_db),
        signer_provider=provider,
        recovery_binding=recovery_binding(),
    )

    assert create_via_service(service, record, admission_reference="admission:least-privilege") == "CREATED"
    first = service.read_admission("admission:least-privilege")
    assert create_via_service(service, record, admission_reference="admission:least-privilege") == "IDEMPOTENT_EXISTING"
    service.trust_store.engine.dispose()
    service.admission_store.engine.dispose()
    del service
    restarted_service = ProductionSignerAdmissionProvisioningService(
        trust_store=PostgresProductionTrustStore(provisioner_url, expected_database_name=control_db),
        admission_store=PostgresProductionSignerAdmissionStore(provisioner_url, expected_database_name=control_db),
        signer_provider=provider,
        recovery_binding=recovery_binding(),
    )
    assert restarted_service.create_admission(
        admission_reference="admission:least-privilege",
        trust_reference=record.trust_reference,
        custody_policy_version="service-entrypoint-custody-v1",
        provisioning_reference="service-entrypoint-test",
        provisioning_generation=1,
        created_at=NOW,
        provenance={"test": "direct-service-entrypoint"},
    ) == "IDEMPOTENT_EXISTING"
    service = restarted_service
    with pytest.raises(CoreError, match="PRODUCTION_SIGNER_ADMISSION_IDENTITY_CONFLICT"):
        create_via_service(
            service,
            record,
            admission_reference="admission:least-privilege",
            provisioning_reference="different-immutable-payload",
        )

    assert service.read_admission("admission:least-privilege") == first
    assert PostgresProductionSignerAdmissionStore(provisioner_url, expected_database_name=control_db).count() == 1
    assert provisioner_privileges(pg_env, control_db) == privileges
    assert provisioner_role_attributes(pg_env, control_db) == {
        "superuser": False,
        "createdb": False,
        "createrole": False,
        "bypassrls": False,
    }


def test_least_privilege_identical_concurrent_creates_do_not_need_update(pg_env, control_db):
    admin_url = pg_env.url(control_db)
    migrate_both(admin_url, control_db)
    _, trust = trust_record(trust_reference="least-privilege-concurrent-identical")
    admission = admission_for(trust, admission_reference="admission:least-privilege-concurrent-identical")
    provisioner_url = least_privilege_provisioner_url(pg_env, control_db)
    assert provisioner_privileges(pg_env, control_db)["update"] is False
    barrier = Barrier(6)

    def create_once():
        barrier.wait(timeout=10)
        return PostgresProductionSignerAdmissionStore(provisioner_url, expected_database_name=control_db).create_if_absent_exact(admission)

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(lambda _: create_once(), range(6)))

    assert results.count("CREATED") == 1
    assert results.count("IDEMPOTENT_EXISTING") == 5
    store = PostgresProductionSignerAdmissionStore(provisioner_url, expected_database_name=control_db)
    assert store.count() == 1
    assert _admission_record_hash(store.resolve(admission.admission_reference)) == _admission_record_hash(admission)
    assert provisioner_privileges(pg_env, control_db)["update"] is False


def test_least_privilege_conflicting_concurrent_creates_preserve_winner_without_update(pg_env, control_db):
    admin_url = pg_env.url(control_db)
    migrate_both(admin_url, control_db)
    _, trust = trust_record(trust_reference="least-privilege-concurrent-conflict")
    first = admission_for(trust, admission_reference="admission:least-privilege-concurrent-conflict", provisioning_reference="winner-candidate")
    second = admission_with(first, provisioning_reference="conflicting-candidate")
    provisioner_url = least_privilege_provisioner_url(pg_env, control_db)
    assert provisioner_privileges(pg_env, control_db)["update"] is False

    barrier = Barrier(2)

    def create(record):
        barrier.wait(timeout=10)
        try:
            return PostgresProductionSignerAdmissionStore(provisioner_url, expected_database_name=control_db).create_if_absent_exact(record)
        except CoreError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(create, [first, second]))

    assert sorted(results) == ["CREATED", "PRODUCTION_SIGNER_ADMISSION_IDENTITY_CONFLICT"]
    store = PostgresProductionSignerAdmissionStore(provisioner_url, expected_database_name=control_db)
    assert store.count() == 1
    winner = store.resolve(first.admission_reference)
    assert winner in (first, second)
    assert _admission_record_hash(winner) in {_admission_record_hash(first), _admission_record_hash(second)}
    assert provisioner_privileges(pg_env, control_db)["update"] is False


@pytest.mark.parametrize("concurrent", [False, True])
def test_least_privilege_provider_unique_collision_is_identity_conflict(pg_env, control_db, concurrent):
    migrate_both(pg_env.url(control_db), control_db)
    _, trust = trust_record(trust_reference="provider-unique-collision")
    first = admission_for(trust, admission_reference="admission:provider-owner")
    second = admission_with(first, admission_reference="admission:provider-contender")
    url = least_privilege_provisioner_url(pg_env, control_db)
    privileges = provisioner_privileges(pg_env, control_db)
    assert privileges == {"select": True, "insert": True, "update": False, "delete": False, "truncate": False}
    barrier = Barrier(2) if concurrent else None

    def create(record):
        store = PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db)
        try:
            if barrier:
                barrier.wait(timeout=10)
            try:
                return store.create_if_absent_exact(record)
            except CoreError as exc:
                return exc.code
        finally:
            store.engine.dispose()

    if concurrent:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(create, [first, second]))
    else:
        results = [create(first), create(second)]
    assert sorted(results) == ["CREATED", "PRODUCTION_SIGNER_ADMISSION_IDENTITY_CONFLICT"]
    store = PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db)
    try:
        winner = first if results[0] == "CREATED" else second
        loser = second if winner == first else first
        assert store.count() == 1
        assert store.resolve(winner.admission_reference) == winner
        assert store.get(loser.admission_reference) is None
        assert store.create_if_absent_exact(winner) == "IDEMPOTENT_EXISTING"
        assert provisioner_privileges(pg_env, control_db) == privileges
    finally:
        store.engine.dispose()


def test_least_privilege_identical_concurrency_all_unique_constraints_multiround(pg_env, control_db):
    from sqlalchemy import event

    migrate_both(pg_env.url(control_db), control_db)
    url = least_privilege_provisioner_url(pg_env, control_db)
    privileges = provisioner_privileges(pg_env, control_db)
    assert privileges == {"select": True, "insert": True, "update": False, "delete": False, "truncate": False}
    rounds = int(os.environ.get("QINGYU_F01_STRESS_ROUNDS", "12"))
    assert 1 <= rounds <= 1000
    stores = [PostgresProductionSignerAdmissionStore(url, expected_database_name=control_db) for _ in range(6)]
    statements = []

    def capture(_conn, _cursor, statement, _parameters, _context, _executemany):
        statements.append(" ".join(statement.upper().split()))

    for store in stores:
        event.listen(store.engine, "before_cursor_execute", capture)
    try:
        with ThreadPoolExecutor(max_workers=6) as executor:
            for round_index in range(rounds):
                _, trust = trust_record(trust_reference=f"f01-round-{round_index}")
                admission = admission_for(trust, admission_reference=f"admission:f01-{round_index}")
                barrier = Barrier(6)

                def create(store):
                    barrier.wait(timeout=10)
                    return store.create_if_absent_exact(admission)

                results = list(executor.map(create, stores))
                assert results.count("CREATED") == 1, (round_index, results)
                assert results.count("IDEMPOTENT_EXISTING") == 5, (round_index, results)
                assert stores[0].count() == round_index + 1
                assert stores[0].resolve(admission.admission_reference) == admission
        inserts = [statement for statement in statements if statement.startswith("INSERT")]
        assert len(inserts) == rounds * 6
        # This mechanism assertion fails deterministically for the old narrow arbiter,
        # while the real PostgreSQL rounds verify canonical convergence and readback.
        assert all("ON CONFLICT DO NOTHING" in statement for statement in inserts)
        assert not any("FOR UPDATE" in statement or "FOR SHARE" in statement for statement in statements)
        assert all(statement.startswith(("SELECT", "INSERT")) for statement in statements)
        assert provisioner_privileges(pg_env, control_db) == privileges
    finally:
        for store in stores:
            store.engine.dispose()
