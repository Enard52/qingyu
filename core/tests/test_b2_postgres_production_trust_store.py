from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import quote
from pathlib import Path
from threading import Barrier

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.b2_production_authority import SYNTHETIC_PRODUCTION_TEST
from app.b2_signer_trust import (
    AuthorityEnvironmentMode,
    InMemoryEd25519SignerProvider,
    POSTGRES_PRODUCTION_TRUST_STORE_MIGRATION_ID,
    POSTGRES_PRODUCTION_TRUST_STORE_SCHEMA_VERSION,
    PostgresProductionTrustStore,
    R1_PRODUCTION_CONTROL_DATABASE_NAME,
    SignerProviderClassification,
    TrustRecord,
    TrustStatus,
    _trust_record_hash,
    _trust_record_payload,
    apply_postgres_production_trust_store_migration,
    apply_r1_production_trust_store_migration,
    require_postgres_production_trust_store_config,
    sign_smi_payload,
    verify_smi_signature,
)
from app.errors import CoreError
from tests.test_foundation_closure_rehearsal import FoundationPostgresEnvironment

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def pg_env(tmp_path_factory):
    env = FoundationPostgresEnvironment(tmp_path_factory.mktemp("b2_trust_store")).create()
    try:
        yield env
    finally:
        env.destroy()


@pytest.fixture()
def control_db(pg_env):
    name = "trust_store_" + datetime.now(timezone.utc).strftime("%H%M%S%f")
    pg_env.create_database(name)
    return name


def trust_record(*, trust_reference="rehearsal-trust-01", environment=SYNTHETIC_PRODUCTION_TEST, target_reference="rehearsal-target-01"):
    provider = InMemoryEd25519SignerProvider(
        provider_reference=f"rehearsal-signer:{trust_reference}",
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


def trust_record_with(record: TrustRecord, **updates):
    data = record.model_dump()
    data.update(updates)
    return TrustRecord(**data)


def test_trust_record_hash_canonicalizes_timezone_equivalent_instants_and_rejects_naive_datetime():
    _, record = trust_record(trust_reference="timezone-matrix")
    instant = datetime(2026, 9, 22, 12, 13, 58, 598009, tzinfo=timezone.utc)
    offsets = [
        timezone.utc,
        timezone(timedelta(0)),
        timezone(timedelta(hours=-12)),
        timezone(timedelta(hours=8)),
        timezone(timedelta(hours=9)),
        timezone(timedelta(hours=5, minutes=30)),
    ]

    hashes = {
        _trust_record_hash(trust_record_with(record, created_at=instant.astimezone(offset)))
        for offset in offsets
    }
    payloads = [
        _trust_record_payload(trust_record_with(record, created_at=instant.astimezone(offset)))
        for offset in offsets
    ]

    assert len(hashes) == 1
    assert {payload["created_at"] for payload in payloads} == {"2026-09-22T12:13:58.598009Z"}
    assert (
        _trust_record_hash(trust_record_with(record, created_at=instant + timedelta(microseconds=1)))
        not in hashes
    )
    with pytest.raises(CoreError, match="TRUST_RECORD_CREATED_AT_TIMEZONE_REQUIRED"):
        trust_record_with(record, created_at=datetime(2026, 9, 22, 12, 13, 58, 598009))


def test_exact_production_datetime_offset_case_hashes_to_writer_value():
    _, record = trust_record(trust_reference="exact-production-offset")
    utc = trust_record_with(record, created_at=datetime(2026, 9, 22, 12, 13, 58, 598009, tzinfo=timezone.utc))
    offset = trust_record_with(record, created_at=datetime(2026, 9, 22, 0, 13, 58, 598009, tzinfo=timezone(timedelta(hours=-12))))

    assert _trust_record_payload(utc)["created_at"] == "2026-09-22T12:13:58.598009Z"
    assert _trust_record_payload(offset)["created_at"] == "2026-09-22T12:13:58.598009Z"
    assert _trust_record_hash(utc) == _trust_record_hash(offset)


def test_explicit_migration_then_exact_create_get_restart_and_crypto(pg_env, control_db):
    url = pg_env.url(control_db)
    provider, record = trust_record()
    with pytest.raises(CoreError, match="PRODUCTION_TRUST_STORE_SCHEMA_REQUIRED"):
        PostgresProductionTrustStore(url, expected_database_name=control_db).resolve(record.trust_reference)

    apply_postgres_production_trust_store_migration(url, expected_database_name=control_db)
    store = PostgresProductionTrustStore(url, expected_database_name=control_db)
    assert store.create_if_absent_exact(record, provenance={"test": "explicit-migration"}) == "CREATED"
    assert store.create_if_absent_exact(record, provenance={"test": "same-record"}) == "IDEMPOTENT_EXISTING"

    reloaded = PostgresProductionTrustStore(url, expected_database_name=control_db).resolve(record.trust_reference)
    assert reloaded == record
    payload = {"challenge": "durable-trust-roundtrip", "trust_reference": record.trust_reference}
    signature = sign_smi_payload(provider, payload)
    verify_smi_signature(canonical_payload=payload, signature_hex=signature, trust_record=reloaded)

    wrong_provider, wrong_record = trust_record(trust_reference="wrong-key")
    with pytest.raises(CoreError, match="SMI_SIGNATURE_INVALID"):
        verify_smi_signature(canonical_payload=payload, signature_hex=signature, trust_record=wrong_record)


def test_postgres_timestamp_with_session_timezone_roundtrips_to_same_trust_hash(pg_env, control_db):
    url = pg_env.url(control_db)
    provider, record = trust_record(
        trust_reference="timezone-roundtrip",
    )
    record = trust_record_with(
        record,
        created_at=datetime(2026, 9, 22, 12, 13, 58, 598009, tzinfo=timezone.utc),
    )
    apply_postgres_production_trust_store_migration(url, expected_database_name=control_db)
    writer = PostgresProductionTrustStore(url, expected_database_name=control_db)
    assert writer.create_if_absent_exact(record, provenance={"test": "timezone-roundtrip"}) == "CREATED"

    timezone_url = url + "?options=" + quote("-c timezone=Etc/GMT+12")
    reloaded = PostgresProductionTrustStore(
        timezone_url,
        expected_database_name=control_db,
    ).resolve(record.trust_reference)

    assert reloaded == record
    assert _trust_record_hash(reloaded) == _trust_record_hash(record)


@pytest.mark.parametrize(
    "mutation",
    [
        {"key_id": "0" * 64},
        {"public_key": "1" * 64, "key_id": "2" * 64, "public_key_fingerprint": "2" * 64},
        {"algorithm": "RSA"},
        {"provider_reference": "wrong-signer"},
        {"environment": "wrong-env"},
        {"target_reference": "wrong-target"},
    ],
)
def test_conflicting_identity_fails_closed(pg_env, control_db, mutation):
    url = pg_env.url(control_db)
    apply_postgres_production_trust_store_migration(url, expected_database_name=control_db)
    provider, record = trust_record()
    store = PostgresProductionTrustStore(url, expected_database_name=control_db)
    assert store.create_if_absent_exact(record) == "CREATED"
    changed = record.model_copy(update=mutation)
    with pytest.raises(CoreError, match="PRODUCTION_TRUST_IDENTITY_CONFLICT|SMI_SIGNER_ALGORITHM_MISMATCH|SMI_SIGNER_KEY_ID_MISMATCH|TRUST_RECORD_HEX_INVALID"):
        store.create_if_absent_exact(changed)
    assert store.resolve(record.trust_reference) == record


def test_concurrent_identical_create_is_idempotent(pg_env, control_db):
    url = pg_env.url(control_db)
    apply_postgres_production_trust_store_migration(url, expected_database_name=control_db)
    _, record = trust_record()
    barrier = Barrier(6)

    def create_once():
        barrier.wait(timeout=10)
        return PostgresProductionTrustStore(url, expected_database_name=control_db).create_if_absent_exact(record)

    with ThreadPoolExecutor(max_workers=6) as executor:
        results = list(executor.map(lambda _: create_once(), range(6)))
    assert results.count("CREATED") == 1
    assert results.count("IDEMPOTENT_EXISTING") == 5
    assert PostgresProductionTrustStore(url, expected_database_name=control_db).resolve(record.trust_reference) == record


def test_concurrent_conflict_accepts_one_identity_and_fails_other(pg_env, control_db):
    url = pg_env.url(control_db)
    apply_postgres_production_trust_store_migration(url, expected_database_name=control_db)
    _, first = trust_record(trust_reference="rehearsal-conflict")
    _, second = trust_record(trust_reference="rehearsal-conflict")
    barrier = Barrier(2)

    def create(record):
        barrier.wait(timeout=10)
        try:
            return PostgresProductionTrustStore(url, expected_database_name=control_db).create_if_absent_exact(record)
        except CoreError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(create, [first, second]))
    assert sorted(results) == ["CREATED", "PRODUCTION_TRUST_IDENTITY_CONFLICT"]
    stored = PostgresProductionTrustStore(url, expected_database_name=control_db).resolve("rehearsal-conflict")
    assert stored == first or stored == second


def test_pg_dump_restore_preserves_trust_identity(pg_env, control_db, tmp_path):
    url = pg_env.url(control_db)
    apply_postgres_production_trust_store_migration(url, expected_database_name=control_db)
    _, record = trust_record()
    assert PostgresProductionTrustStore(url, expected_database_name=control_db).create_if_absent_exact(record) == "CREATED"

    dump_path = tmp_path / "trust-store.sql"
    pg_env.dump(control_db, dump_path)
    restored = control_db + "_restore"
    pg_env.restore(restored, dump_path)
    assert PostgresProductionTrustStore(pg_env.url(restored), expected_database_name=restored).resolve(record.trust_reference) == record


def test_real_production_missing_config_fails_closed_without_memory_fallback():
    with pytest.raises(CoreError, match="PRODUCTION_TRUST_STORE_CONFIG_REQUIRED"):
        require_postgres_production_trust_store_config(
            mode=AuthorityEnvironmentMode.REAL_PRODUCTION,
            sqlalchemy_url=None,
        )


def _governance_objects(pg_env, database: str) -> tuple[bool, bool]:
    import psycopg

    with psycopg.connect(host="127.0.0.1", port=pg_env.port, dbname=database, user="postgres", password=pg_env.password) as connection:
        schema_exists = connection.execute("SELECT EXISTS (SELECT 1 FROM information_schema.schemata WHERE schema_name='governance')").fetchone()[0]
        table_exists = connection.execute(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='governance' AND table_name='production_trust_records')"
        ).fetchone()[0]
    return bool(schema_exists), bool(table_exists)


def test_wrong_database_migration_rejects_before_any_ddl(pg_env):
    wrong = "definitely_not_qingyu_control"
    pg_env.create_database(wrong)
    assert _governance_objects(pg_env, wrong) == (False, False)
    with pytest.raises(CoreError, match="DATABASE_SAFETY_VIOLATION"):
        apply_r1_production_trust_store_migration(pg_env.url(wrong))
    assert _governance_objects(pg_env, wrong) == (False, False)


def test_correct_canonical_qingyu_control_rehearsal_migrates_and_store_works(pg_env):
    pg_env.create_database(R1_PRODUCTION_CONTROL_DATABASE_NAME)
    apply_r1_production_trust_store_migration(pg_env.url(R1_PRODUCTION_CONTROL_DATABASE_NAME))
    assert _governance_objects(pg_env, R1_PRODUCTION_CONTROL_DATABASE_NAME) == (True, True)
    _, record = trust_record()
    store = PostgresProductionTrustStore(
        pg_env.url(R1_PRODUCTION_CONTROL_DATABASE_NAME),
        expected_database_name=R1_PRODUCTION_CONTROL_DATABASE_NAME,
    )
    assert store.create_if_absent_exact(record) == "CREATED"
    assert store.resolve(record.trust_reference) == record


def test_url_text_is_not_database_identity_authority(pg_env):
    wrong = "definitely_not_qingyu_control"
    pg_env.create_database(wrong)
    with pytest.raises(CoreError, match="DATABASE_SAFETY_VIOLATION"):
        apply_postgres_production_trust_store_migration(
            pg_env.url(wrong),
            expected_database_name=R1_PRODUCTION_CONTROL_DATABASE_NAME,
        )
    with pytest.raises(CoreError, match="DATABASE_SAFETY_VIOLATION"):
        PostgresProductionTrustStore(
            pg_env.url(wrong),
            expected_database_name=R1_PRODUCTION_CONTROL_DATABASE_NAME,
        ).resolve("anything")


def test_missing_expected_database_identity_fails_closed(pg_env, control_db):
    with pytest.raises(CoreError, match="DATABASE_SAFETY_VIOLATION"):
        apply_postgres_production_trust_store_migration(pg_env.url(control_db), expected_database_name="")
    with pytest.raises(CoreError, match="DATABASE_SAFETY_VIOLATION"):
        PostgresProductionTrustStore(pg_env.url(control_db), expected_database_name="")
