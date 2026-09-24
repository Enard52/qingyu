from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier
from urllib.parse import quote

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.b2_production_authority import SYNTHETIC_PRODUCTION_TEST
from app.b2_signer_trust import (
    AuthorityEnvironmentMode,
    InMemoryEd25519SignerProvider,
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID,
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION,
    POSTGRES_PRODUCTION_TRUST_STORE_MIGRATION_ID,
    PostgresProductionSignerAdmissionStore,
    PostgresProductionTrustStore,
    ProductionSignerAdmissionRecord,
    ProductionSignerAdmissionRecoveryBinding,
    ProductionSignerAdmissionStatus,
    R1_PRODUCTION_CONTROL_DATABASE_NAME,
    SignerProviderClassification,
    TrustRecord,
    TrustStatus,
    _admission_record_hash,
    _admission_record_payload,
    _trust_record_hash,
    apply_postgres_production_signer_admission_store_migration,
    apply_postgres_production_trust_store_migration,
    apply_r1_production_signer_admission_store_migration,
    apply_r1_production_trust_store_migration,
    require_postgres_production_signer_admission_store_config,
)
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
