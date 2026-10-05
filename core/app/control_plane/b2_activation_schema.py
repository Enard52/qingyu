"""Explicit candidate activation migrations; constructors never provision schemas.

No operational migrator allowlist entry or production executor is installed.
The Core migration does not insert an identity or change legacy Core rows.
"""
from sqlalchemy import text

from ..errors import CoreError

CONTROL_REVISION = "b2_004_activation_control_v2"
CORE_REVISION = "b2_005_scoped_core_new_genesis_v2"
SCHEMA_VERSION = "qingyu-scoped-activation-v2-1"


def apply_activation_migration(engine, *, database: str, kind: str):
    if kind not in {"control", "core"}:
        raise CoreError("B2_ACTIVATION_MIGRATION_KIND_INVALID")
    # This callable is deliberately candidate-only, until separately enabled.
    if database in {"qingyu_control", "qingyu_prod"}:
        raise CoreError("B2_REAL_MIGRATION_NOT_ENABLED")
    schema = "governance" if kind == "control" else "r1_core_v2"
    revision = CONTROL_REVISION if kind == "control" else CORE_REVISION
    with engine.begin() as c:
        if c.execute(text("SELECT current_database()")).scalar_one() != database:
            raise CoreError("B2_ACTIVATION_DATABASE_MISMATCH")
        if kind == "control":
            from ..b2_signer_trust import (
                POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID as prior,
                POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION as version,
            )
            found = c.execute(text("SELECT schema_version FROM governance.schema_migrations WHERE migration_id=:id"), {"id": prior}).scalar_one_or_none()
            if found != version:
                raise CoreError("B2_ACTIVATION_MIGRATION_PREREQUISITE_REQUIRED")
        c.execute(text(f"CREATE SCHEMA IF NOT EXISTS {schema}"))
        c.execute(text(f"CREATE TABLE IF NOT EXISTS {schema}.activation_migrations (revision TEXT PRIMARY KEY, version TEXT NOT NULL)"))
        found = c.execute(text(f"SELECT version FROM {schema}.activation_migrations WHERE revision=:id"), {"id": revision}).scalar_one_or_none()
        if found:
            if found != SCHEMA_VERSION:
                raise CoreError("B2_ACTIVATION_SCHEMA_VERSION_CONFLICT")
            return
        if kind == "control":
            c.execute(text("""CREATE TABLE governance.activation_authorities (
                authority_reference TEXT PRIMARY KEY,
                environment TEXT NOT NULL, target_reference TEXT NOT NULL,
                admission_reference TEXT NOT NULL REFERENCES governance.production_signer_admission_trust_bindings(admission_reference),
                record_wire BYTEA NOT NULL, record_hash TEXT NOT NULL UNIQUE CHECK (record_hash ~ '^[0-9a-f]{64}$'),
                UNIQUE(environment, target_reference),
                UNIQUE(authority_reference, record_hash),
                persisted_at TIMESTAMPTZ NOT NULL DEFAULT now())"""))
            c.execute(text("""CREATE TABLE governance.activation_smis (
                intent_id TEXT PRIMARY KEY, authority_reference TEXT NOT NULL,
                authority_hash TEXT NOT NULL, record_wire BYTEA NOT NULL,
                record_hash TEXT NOT NULL UNIQUE CHECK (record_hash ~ '^[0-9a-f]{64}$'),
                FOREIGN KEY(authority_reference, authority_hash) REFERENCES governance.activation_authorities(authority_reference, record_hash),
                persisted_at TIMESTAMPTZ NOT NULL DEFAULT now())"""))
            tables = ("activation_authorities", "activation_smis")
        else:
            c.execute(text("""CREATE TABLE r1_core_v2.identity (
                singleton SMALLINT PRIMARY KEY CHECK (singleton=1),
                identity_id UUID NOT NULL UNIQUE, continuity_id UUID NOT NULL UNIQUE,
                genesis_operation_id UUID NOT NULL UNIQUE,
                record_wire BYTEA NOT NULL, record_hash TEXT NOT NULL UNIQUE CHECK (record_hash ~ '^[0-9a-f]{64}$'))"""))
            c.execute(text("""CREATE TABLE r1_core_v2.genesis (
                singleton SMALLINT PRIMARY KEY CHECK (singleton=1),
                operation_id UUID NOT NULL UNIQUE REFERENCES r1_core_v2.identity(genesis_operation_id),
                identity_hash TEXT NOT NULL REFERENCES r1_core_v2.identity(record_hash),
                proof_wire BYTEA NOT NULL, proof_hash TEXT NOT NULL CHECK (proof_hash ~ '^[0-9a-f]{64}$'),
                persisted_at TIMESTAMPTZ NOT NULL DEFAULT now())"""))
            c.execute(text("""CREATE TABLE r1_core_v2.lifecycle (
                singleton SMALLINT PRIMARY KEY CHECK (singleton=1),
                genesis_operation_id UUID NOT NULL REFERENCES r1_core_v2.genesis(operation_id),
                state TEXT NOT NULL CHECK(state='GENESIS_DURABLE'),
                checkpoint_wire BYTEA NOT NULL,
                checkpoint_hash TEXT NOT NULL CHECK (checkpoint_hash ~ '^[0-9a-f]{64}$'))"""))
            tables = ("identity", "genesis", "lifecycle")
        c.execute(text(f"""CREATE FUNCTION {schema}.activation_immutable() RETURNS trigger
            LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
            RAISE EXCEPTION 'immutable activation history' USING ERRCODE='55000'; END $$"""))
        for table in tables:
            c.execute(text(f"CREATE TRIGGER activation_immutable BEFORE UPDATE OR DELETE ON {schema}.{table} FOR EACH ROW EXECUTE FUNCTION {schema}.activation_immutable()"))
            c.execute(text(f"CREATE TRIGGER activation_no_truncate BEFORE TRUNCATE ON {schema}.{table} FOR EACH STATEMENT EXECUTE FUNCTION {schema}.activation_immutable()"))
            c.execute(text(f"REVOKE ALL ON {schema}.{table} FROM PUBLIC"))
        c.execute(text(f"INSERT INTO {schema}.activation_migrations VALUES (:id,:version)"), {"id": revision, "version": SCHEMA_VERSION})
