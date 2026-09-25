from __future__ import annotations

import json
from datetime import datetime, timezone
from urllib.parse import quote

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import create_engine, text

from app.b2_production_authority import SYNTHETIC_PRODUCTION_TEST
from app.b2_signer_trust import (
    InMemoryEd25519SignerProvider,
    PostgresProductionTrustStore,
    SignerProviderClassification,
    TrustRecord,
    TrustStatus,
    _trust_record_hash,
    apply_r1_production_signer_admission_store_migration,
    apply_r1_production_trust_store_migration,
)
from tests.test_foundation_closure_rehearsal import FoundationPostgresEnvironment
import ops.qingyu_control_migrator_executor as executor


class ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one(self):
        return self.value


class OneResult:
    def __init__(self, value):
        self.value = value

    def one(self):
        return self.value


class MappingsResult:
    def __init__(self, value):
        self.value = value

    def one(self):
        return self.value

    def all(self):
        return self.value


class FakeConnection:
    def __init__(self, *, session_user="qingyu_control_migrator", database="qingyu_control", owner_member=True):
        self.session_user = session_user
        self.current_user = session_user
        self.database = database
        self.owner_member = owner_member
        self.events: list[str] = []

    def execute(self, statement, parameters=None):
        sql = str(statement)
        normalized = " ".join(sql.split())
        if "session_user, current_user, current_database(), version()" in normalized:
            self.events.append("identity_before")
            return OneResult((self.session_user, self.current_user, self.database, "PostgreSQL fake"))
        if "pg_has_role" in normalized:
            self.events.append("owner_member")
            return ScalarResult(self.owner_member)
        if "rolcanlogin" in normalized:
            self.events.append("owner_nologin")
            return ScalarResult(False)
        if normalized == "SET ROLE qingyu_control_owner":
            self.events.append("set_owner")
            self.current_user = "qingyu_control_owner"
            return ScalarResult(None)
        if "session_user, current_user, current_database()" in normalized:
            self.events.append(f"identity_{self.current_user}")
            return OneResult((self.session_user, self.current_user, self.database))
        if normalized == "RESET ROLE":
            self.events.append("reset_role")
            self.current_user = self.session_user
            return ScalarResult(None)
        raise AssertionError(f"unexpected SQL: {normalized}")


class FakeBegin:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, exc_type, exc, tb):
        return False


class FakeEngine:
    def __init__(self, connection):
        self.connection = connection

    def begin(self):
        return FakeBegin(self.connection)


def test_default_mode_is_probe(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(executor, "_connect_url", lambda: "safe://internal")
    monkeypatch.setattr(executor, "_run_probe", lambda url, migration: calls.append((url, migration)) or {"status": "PASS", "mode": "PROBE"})
    assert executor.main([]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["mode"] == "PROBE"
    assert calls == [("safe://internal", executor.POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID)]


@pytest.mark.parametrize("confirm", [None, "", "yes", "true", "APPLY_B2_002_TO_QINGYU_CONTROL ", "apply_b2_002_to_qingyu_control"])
def test_apply_requires_exact_confirmation_before_connection(monkeypatch, capsys, confirm):
    monkeypatch.setattr(executor, "_connect_url", lambda: pytest.fail("credential read should not happen"))
    args = ["--mode", "apply", "--migration", executor.POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID]
    if confirm is not None:
        args += ["--confirm", confirm]
    assert executor.main(args) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["code"] in {"APPLY_CONFIRMATION_REQUIRED", "APPLY_CONFIRMATION_MISMATCH"}
    assert out["mutation_performed"] is False


def test_wrong_db_rejected_before_connection(monkeypatch, capsys):
    monkeypatch.setattr(executor, "_connect_url", lambda: pytest.fail("credential read should not happen"))
    assert executor.main(["--mode", "apply", "--target-database", "qingyu_prod", "--confirm", executor.APPLY_B2_002_TO_QINGYU_CONTROL]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["code"] == "TARGET_DATABASE_OVERRIDE_REJECTED"


def test_unknown_migration_rejected_before_connection(monkeypatch, capsys):
    monkeypatch.setattr(executor, "_connect_url", lambda: pytest.fail("credential read should not happen"))
    assert executor.main(["--mode", "apply", "--migration", "b2_999_evil", "--confirm", executor.APPLY_B2_002_TO_QINGYU_CONTROL]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["code"] == "MIGRATION_NOT_ALLOWLISTED"


def test_correct_confirmation_reaches_canonical_callable_once_after_guards(monkeypatch):
    connection = FakeConnection()
    calls = []
    monkeypatch.setattr(executor, "create_engine", lambda url, pool_pre_ping=True: FakeEngine(connection))
    monkeypatch.setattr(
        executor,
        "_assert_owner_authority_connection",
        lambda url: {"session_user": "qingyu_control_migrator", "current_user": "qingyu_control_owner", "database": "qingyu_control"},
    )
    monkeypatch.setattr(
        executor,
        "_collect_apply_postconditions",
        lambda url: {
            "b2_002_present": True,
            "admission_table_present": True,
            "trust_count": 1,
            "trust_record_hash": "f" * 64,
            "signer_key_id": "a" * 64,
            "b2_002_count": 1,
            "admission_row_count": 0,
        },
    )

    def sentinel(url):
        calls.append((url, list(connection.events)))

    result = executor._run_apply("internal://qingyu_control", executor.POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID, migration_callable=sentinel)
    assert result["status"] == "PASS"
    assert result["mutation_performed"] is True
    assert "options=-c+role%3Dqingyu_control_owner" in calls[0][0]
    assert calls[0][1] == ["identity_before", "owner_member", "owner_nologin", "set_owner", "identity_qingyu_control_owner", "reset_role"]


@pytest.mark.parametrize(
    "connection, expected",
    [
        (FakeConnection(session_user="postgres"), "MIGRATOR_SESSION_USER_MISMATCH"),
        (FakeConnection(database="qingyu_prod"), "DATABASE_IDENTITY_MISMATCH"),
        (FakeConnection(owner_member=False), "OWNER_ROLE_TRANSITION_FAILED"),
    ],
)
def test_failed_precondition_reaches_canonical_callable_zero_times(monkeypatch, connection, expected):
    calls = []
    monkeypatch.setattr(executor, "create_engine", lambda url, pool_pre_ping=True: FakeEngine(connection))
    with pytest.raises(RuntimeError, match=expected):
        executor._run_apply("safe://internal", executor.POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID, migration_callable=lambda url: calls.append(url))
    assert calls == []


def test_canonical_callable_failure_fails_closed(monkeypatch):
    connection = FakeConnection()
    monkeypatch.setattr(executor, "create_engine", lambda url, pool_pre_ping=True: FakeEngine(connection))
    monkeypatch.setattr(
        executor,
        "_assert_owner_authority_connection",
        lambda url: {"session_user": "qingyu_control_migrator", "current_user": "qingyu_control_owner", "database": "qingyu_control"},
    )
    with pytest.raises(RuntimeError, match="CANONICAL_MIGRATION_FAILED"):
        executor._run_apply("internal://qingyu_control", executor.POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID, migration_callable=lambda url: (_ for _ in ()).throw(RuntimeError("boom")))


def test_apply_rejects_caller_supplied_connection_options_before_canonical(monkeypatch):
    connection = FakeConnection()
    calls = []
    monkeypatch.setattr(executor, "create_engine", lambda url, pool_pre_ping=True: FakeEngine(connection))
    with pytest.raises(RuntimeError, match="MIGRATION_CONNECTION_OPTIONS_ALREADY_PRESENT"):
        executor._run_apply(
            "internal://qingyu_control?options=-c+role%3Dpostgres",
            executor.POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID,
            migration_callable=lambda url: calls.append(url),
        )
    assert calls == []


def test_apply_postcondition_missing_fails_closed(monkeypatch):
    connection = FakeConnection()
    calls = []
    monkeypatch.setattr(executor, "create_engine", lambda url, pool_pre_ping=True: FakeEngine(connection))
    monkeypatch.setattr(
        executor,
        "_assert_owner_authority_connection",
        lambda url: {"session_user": "qingyu_control_migrator", "current_user": "qingyu_control_owner", "database": "qingyu_control"},
    )
    monkeypatch.setattr(
        executor,
        "_collect_apply_postconditions",
        lambda url: {
            "b2_002_present": False,
            "admission_table_present": False,
            "trust_count": 1,
            "trust_record_hash": "f" * 64,
            "signer_key_id": "a" * 64,
            "b2_002_count": 0,
            "admission_row_count": 0,
        },
    )
    with pytest.raises(RuntimeError, match="APPLY_POSTCONDITION_MISSING"):
        executor._run_apply(
            "internal://qingyu_control",
            executor.POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID,
            migration_callable=lambda url: calls.append(url),
        )
    assert len(calls) == 1


def test_no_arbitrary_execution_surface_in_executor_source():
    source = open(executor.__file__, "r", encoding="utf-8").read()
    forbidden = ["eval(", "exec(", "importlib", "getattr(", "shell=True", "CREATE TABLE", "DROP TABLE", "ALTER TABLE"]
    assert [token for token in forbidden if token in source] == []


@pytest.mark.integration
def test_real_isolated_canonical_migration_runs_under_owner_authority_and_is_idempotent(tmp_path):
    pg_env = FoundationPostgresEnvironment(tmp_path).create()
    try:
        import psycopg

        synthetic_password = "synthetic_owner_context_repair_only"
        with psycopg.connect(host="127.0.0.1", port=pg_env.port, dbname="postgres", user="postgres", password=pg_env.password, autocommit=True) as connection:
            connection.execute("DROP DATABASE IF EXISTS qingyu_control WITH (FORCE)")
            connection.execute("DROP ROLE IF EXISTS qingyu_control_migrator")
            connection.execute("DROP ROLE IF EXISTS qingyu_control_owner")
            connection.execute("CREATE ROLE qingyu_control_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS")
            connection.execute("CREATE ROLE qingyu_control_migrator LOGIN PASSWORD 'synthetic_owner_context_repair_only' NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS")
            connection.execute("GRANT qingyu_control_owner TO qingyu_control_migrator")
            connection.execute("CREATE DATABASE qingyu_control OWNER qingyu_control_owner")
            connection.execute("REVOKE CREATE ON DATABASE qingyu_control FROM PUBLIC")

        owner_url = f"postgresql+psycopg://qingyu_control_migrator:{quote(synthetic_password)}@127.0.0.1:{pg_env.port}/qingyu_control?options={quote('-c role=qingyu_control_owner')}"
        migrator_url = f"postgresql+psycopg://qingyu_control_migrator:{quote(synthetic_password)}@127.0.0.1:{pg_env.port}/qingyu_control"

        apply_r1_production_trust_store_migration(owner_url)
        provider = InMemoryEd25519SignerProvider(
            provider_reference="isolated-owner-context-provider",
            private_key=Ed25519PrivateKey.generate(),
            classification=SignerProviderClassification.SYNTHETIC_PRODUCTION_TEST_ONLY,
        )
        trust = TrustRecord.from_provider(
            trust_reference="isolated-owner-context-trust",
            provider=provider,
            environment=SYNTHETIC_PRODUCTION_TEST,
            target_reference="isolated-owner-context-target",
            generation=1,
            created_at=datetime(2026, 9, 25, 12, 30, tzinfo=timezone.utc),
            status=TrustStatus.ACTIVE,
        )
        assert PostgresProductionTrustStore(owner_url, expected_database_name="qingyu_control").create_if_absent_exact(trust) == "CREATED"

        with pytest.raises(Exception, match="permission denied|InsufficientPrivilege|CREATE SCHEMA"):
            apply_r1_production_signer_admission_store_migration(migrator_url)

        result = executor._run_apply(migrator_url, executor.POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID)
        assert result["status"] == "PASS"
        assert result["session_user"] == "qingyu_control_migrator"
        assert result["current_user_before_set_role"] == "qingyu_control_migrator"
        assert result["migration_connection_session_user"] == "qingyu_control_migrator"
        assert result["migration_connection_current_user"] == "qingyu_control_owner"
        assert result["migration_connection_database"] == "qingyu_control"
        assert result["b2_002_count"] == 1
        assert result["admission_table_present"] is True
        assert result["admission_row_count"] == 0

        second = executor._run_apply(migrator_url, executor.POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID)
        assert second["status"] == "PASS"
        assert second["b2_002_count"] == 1
        assert second["admission_row_count"] == 0

        migrator_engine = create_engine(migrator_url, pool_pre_ping=True)
        with migrator_engine.begin() as connection:
            role = connection.execute(text("""
                SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls
                  FROM pg_roles WHERE rolname = 'qingyu_control_migrator'
            """)).one()
            owner = connection.execute(text("SELECT rolcanlogin FROM pg_roles WHERE rolname = 'qingyu_control_owner'")).scalar_one()
            has_db_create = connection.execute(text("SELECT has_database_privilege(current_user, current_database(), 'CREATE')")).scalar_one()
        owner_engine = create_engine(owner_url, pool_pre_ping=True)
        with owner_engine.begin() as connection:
            migrations = connection.execute(text("""
                SELECT migration_id, count(*) FROM governance.schema_migrations
                 WHERE migration_id IN ('b2_001_postgres_production_trust_store', 'b2_002_postgres_production_signer_admission_store')
                 GROUP BY migration_id ORDER BY migration_id
            """)).fetchall()
            trust_count, trust_hash = connection.execute(text("SELECT count(*), max(record_hash) FROM governance.production_trust_records")).one()
        assert tuple(role) == (False, False, False, False)
        assert owner is False
        assert has_db_create is False
        assert dict(migrations)[executor.POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID] == 1
        assert trust_count == 1
        assert trust_hash == _trust_record_hash(trust)
    finally:
        pg_env.destroy()
