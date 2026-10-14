"""Independent, signed-origin-only Alembic environment for R1 Authority.

This file deliberately does not read CORE_DATABASE_URL and does not support
offline SQL. A migration run must carry already durable signed origin files;
the caller is responsible for the separately signed post-migration attestation.
"""

from __future__ import annotations

from logging.config import fileConfig
import os
from pathlib import Path

from alembic import context
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.pool import NullPool

from app.control_plane.r1_provisioning import (
    verify_signed_initial_migration_intent,
    verify_signed_origin_wire,
)
from app.control_plane.r1_protocol import decode_canonical_wire
from app.control_plane.r1_root_pin import load_operator_root_pin
from app.control_plane import r1_schema_snapshot as snapshot
from app.control_plane.r1_schema_snapshot import (
    R1_METADATA,
    verify_initial_migration_artifact,
)


config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)


def _required_file(name: str) -> bytes:
    path = os.environ.get(name)
    if not path:
        raise RuntimeError(f"{name} is required for signed R1 migration")
    return Path(path).read_bytes()


def _verified_origin():
    expected_env = (Path(snapshot.__file__).resolve().parents[2] /
                    "control_plane_alembic" / "env.py")
    if Path(__file__).resolve() != expected_env:
        raise RuntimeError("R1 Alembic environment path differs from signed artifact")
    # This entrypoint is acceptance-only. The trust root is loaded from a
    # fixed, protected machine slot, never an environment-selected file or a
    # signed manifest supplied by the caller.
    pin = load_operator_root_pin("acceptance")
    if not pin.test_only:
        raise RuntimeError("R1 acceptance requires a preinstalled test-only root")
    intent_raw = _required_file("R1_SIGNED_INTENT_FILE")
    completion_raw = _required_file("R1_SIGNED_CREATION_COMPLETION_FILE")
    verify_signed_initial_migration_intent(decode_canonical_wire(intent_raw), pin.public_key)
    origin = verify_signed_origin_wire(
        intent_raw,
        completion_raw,
        pin.public_key,
    )
    if not origin.intent["test_only"] or origin.intent["environment"] != "acceptance":
        raise RuntimeError("R1 acceptance cannot consume a production origin")
    if origin.intent["operator_root_key_id"] != pin.key_id:
        raise RuntimeError("R1 signed intent differs from the machine root pin")
    verify_initial_migration_artifact(origin.intent["initial_migration_artifact_digest"])
    return origin


def _read_only_preflight(connection, origin) -> None:
    """Verify target and empty lineage before Alembic can create anything."""
    expected = origin.completion
    actual = connection.execute(text("""
        SELECT current_database() AS database_name, current_user AS current_role,
               d.oid AS database_oid, d.datdba AS owner_oid
        FROM pg_database AS d WHERE d.datname = current_database()
    """)).mappings().one()
    if (actual["database_name"] != expected["database_name"]
            or actual["database_oid"] != expected["database_oid"]
            or actual["owner_oid"] != expected["owner_oid"]
            or actual["current_role"] != origin.intent["roles"]["migrator"]):
        raise RuntimeError("R1 migration target/role differs from signed origin")
    system_id = connection.execute(
        text("SELECT system_identifier FROM pg_control_system()")
    ).scalar_one()
    if str(system_id) != expected["server_system_identifier"]:
        raise RuntimeError("R1 PostgreSQL cluster differs from signed origin")
    roles = dict(connection.execute(text(
        "SELECT rolname, oid FROM pg_roles WHERE rolname = ANY(:names)"
    ), {"names": list(origin.intent["roles"].values())}).all())
    for duty, name in origin.intent["roles"].items():
        if roles.get(name) != expected["role_oids"][duty]:
            raise RuntimeError("R1 role identity differs from signed origin")
    objects = connection.execute(text("""
        SELECT n.nspname, c.relname
          FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
         WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast')
           AND n.nspname NOT LIKE 'pg_temp_%'
           AND n.nspname NOT LIKE 'pg_toast_temp_%'
           AND c.relkind IN ('r','p','v','m','S','f')
    """)).all()
    if objects:
        raise RuntimeError("R1 initial migration requires a new empty database")
    if connection.execute(text(
        "SELECT 1 FROM pg_namespace WHERE nspname = 'control_plane'"
    )).first():
        raise RuntimeError("R1 Authority schema already exists")


def run_migrations_online() -> None:
    origin = _verified_origin()  # Signature and artifact before DB connection.
    # A database URL and signed manifests cannot independently prove the
    # Docker volume, TLS endpoint or key-store identity. Keep this entrypoint
    # closed until the read-only external target inspector is wired in.
    raise RuntimeError("R1 independent target inspector is not yet installed")
    dsn = os.environ.get("R1_AUTHORITY_MIGRATION_DATABASE_URL")
    if not dsn:
        raise RuntimeError("R1_AUTHORITY_MIGRATION_DATABASE_URL is required")
    parsed = make_url(dsn)
    if parsed.database != origin.intent["database_name"]:
        raise RuntimeError("R1 database URL differs from signed intent")
    if parsed.database == "qingyu_control_acceptance":
        raise RuntimeError("legacy database is forensic-only")
    engine = create_engine(dsn, poolclass=NullPool, hide_parameters=True)
    try:
        with engine.connect() as connection:
            with connection.begin():
                connection.execute(text("SET TRANSACTION READ ONLY"))
                _read_only_preflight(connection, origin)
            config.attributes["r1_verified_origin"] = origin
            context.configure(
                connection=connection,
                target_metadata=R1_METADATA,
                version_table="cp_alembic_version",
                version_table_schema="public",
                include_schemas=True,
                compare_type=True,
            )
            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    raise RuntimeError("offline R1 migration is prohibited")
run_migrations_online()
