from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from app.b2_signer_trust import (
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID,
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID,
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION,
    POSTGRES_PRODUCTION_TRUST_STORE_MIGRATION_ID,
    POSTGRES_PRODUCTION_TRUST_STORE_SCHEMA_VERSION,
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION,
    R1_PRODUCTION_CONTROL_DATABASE_NAME,
    apply_r1_production_signer_admission_store_migration,
    apply_r1_production_signer_admission_trust_binding_store_migration,
)

SECRET_PATH = "/etc/qingyu/secrets/control-postgres.env"
WSL_DISTRO = "qingyu-prod-local-01"
APPLY_B2_002_TO_QINGYU_CONTROL = "APPLY_B2_002_TO_QINGYU_CONTROL"
APPLY_B2_003_TO_QINGYU_CONTROL = "APPLY_B2_003_TO_QINGYU_CONTROL"
CONTROL_MIGRATOR_ROLE = "qingyu_control_migrator"
CONTROL_OWNER_ROLE = "qingyu_control_owner"
ALLOWED_MIGRATIONS = {
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID: {
        "schema_version": POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION,
        "callable": "app.b2_signer_trust.apply_r1_production_signer_admission_store_migration",
        "target_database": R1_PRODUCTION_CONTROL_DATABASE_NAME,
        "confirmation": APPLY_B2_002_TO_QINGYU_CONTROL,
    },
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID: {
        "schema_version": POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION,
        "callable": "app.b2_signer_trust.apply_r1_production_signer_admission_trust_binding_store_migration",
        "target_database": R1_PRODUCTION_CONTROL_DATABASE_NAME,
        "confirmation": APPLY_B2_003_TO_QINGYU_CONTROL,
    },
}


def _fail(code: str, **extra: Any) -> int:
    payload = {"status": "FAIL", "code": code, "mutation_performed": False}
    payload.update(extra)
    print(json.dumps(payload, sort_keys=True))
    return 2


def _run_wsl(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["wsl.exe", "-d", WSL_DISTRO, "--", *args],
        check=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _read_control_env() -> dict[str, str]:
    completed = _run_wsl(["sudo", "cat", SECRET_PATH])
    values: dict[str, str] = {}
    for raw in completed.stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _safe_secret_metadata() -> dict[str, str]:
    listing = _run_wsl(["sudo", "ls", "-ln", SECRET_PATH]).stdout.strip().split()
    size = _run_wsl(["sudo", "wc", "-c", SECRET_PATH]).stdout.strip().split()[0]
    return {
        "owner_uid": listing[2],
        "group_gid": listing[3],
        "mode_text": listing[0],
        "size_bytes": size,
        "path": SECRET_PATH,
    }


def _connect_url() -> str:
    values = _read_control_env()
    url = values.get("CONTROL_DATABASE_URL_MIGRATOR")
    if not url:
        raise RuntimeError("CONTROL_DATABASE_URL_MIGRATOR_MISSING")
    return url


def _validate_target(target_db: str) -> str | None:
    if target_db != R1_PRODUCTION_CONTROL_DATABASE_NAME:
        return "TARGET_DATABASE_OVERRIDE_REJECTED"
    return None


def _validate_migration(migration_id: str) -> str | None:
    if migration_id not in ALLOWED_MIGRATIONS:
        return "MIGRATION_NOT_ALLOWLISTED"
    return None


def _validate_confirmation(migration_id: str, target_db: str, confirmation: str | None) -> str | None:
    expected = ALLOWED_MIGRATIONS[migration_id]["confirmation"]
    expected_target = ALLOWED_MIGRATIONS[migration_id]["target_database"]
    if target_db != expected_target:
        return "TARGET_DATABASE_OVERRIDE_REJECTED"
    if confirmation is None:
        return "APPLY_CONFIRMATION_REQUIRED"
    if confirmation != expected:
        return "APPLY_CONFIRMATION_MISMATCH"
    return None


def _assert_identity(identity: Any) -> None:
    if identity[0] != CONTROL_MIGRATOR_ROLE:
        raise RuntimeError("MIGRATOR_SESSION_USER_MISMATCH")
    if identity[2] != R1_PRODUCTION_CONTROL_DATABASE_NAME:
        raise RuntimeError("DATABASE_IDENTITY_MISMATCH")


def _collect_readonly_state(connection: Any) -> dict[str, Any]:
    b2_002 = connection.execute(text("""
        SELECT EXISTS (
            SELECT 1 FROM governance.schema_migrations
             WHERE migration_id = 'b2_002_postgres_production_signer_admission_store'
        )
    """)).scalar_one()
    admission_table = connection.execute(text(
        "SELECT to_regclass('governance.production_signer_admission_records') IS NOT NULL"
    )).scalar_one()
    trust = connection.execute(text("""
        SELECT count(*) AS trust_count,
               max(record_hash) AS record_hash,
               max(key_id) AS key_id
          FROM governance.production_trust_records
    """)).mappings().one()
    return {
        "b2_002_present": bool(b2_002),
        "admission_table_present": bool(admission_table),
        "trust_count": int(trust["trust_count"]),
        "trust_record_hash": trust["record_hash"],
        "signer_key_id": trust["key_id"],
    }


BINDING_TABLE = "governance.production_signer_admission_trust_bindings"
BINDING_LEDGER_VERSIONS = {
    POSTGRES_PRODUCTION_TRUST_STORE_MIGRATION_ID: POSTGRES_PRODUCTION_TRUST_STORE_SCHEMA_VERSION,
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID: POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION,
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID: POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION,
}


def _collect_binding_state(connection: Any) -> dict[str, Any]:
    identity = connection.execute(text("SELECT session_user, current_user, current_database()")).one()
    if tuple(identity) != (CONTROL_MIGRATOR_ROLE, CONTROL_OWNER_ROLE, R1_PRODUCTION_CONTROL_DATABASE_NAME):
        raise RuntimeError("MIGRATION_CONNECTION_IDENTITY_MISMATCH")
    ledger = connection.execute(text("SELECT migration_id, schema_version FROM governance.schema_migrations")).all()
    versions = {name: [version for migration, version in ledger if migration == name]
                for name in BINDING_LEDGER_VERSIONS}
    sources = connection.execute(text("""
        SELECT (SELECT coalesce(jsonb_agg(t ORDER BY trust_reference), '[]'::jsonb)
                  FROM governance.production_trust_records t) AS trusts,
               (SELECT coalesce(jsonb_agg(a ORDER BY admission_reference), '[]'::jsonb)
                  FROM governance.production_signer_admission_records a) AS admissions
    """)).mappings().one()
    present = connection.execute(text("SELECT to_regclass(:table) IS NOT NULL"), {"table": BINDING_TABLE}).scalar_one()
    count = connection.execute(text("SELECT count(*) FROM governance.production_signer_admission_trust_bindings")).scalar_one() if present else None
    return {"ledger_versions": versions, "sources": dict(sources), "binding_table_present": bool(present), "binding_row_count": count}


def _require_binding_preconditions(state: dict[str, Any]) -> None:
    versions = state["ledger_versions"]
    for name, version in BINDING_LEDGER_VERSIONS.items():
        if name != POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID and versions[name] != [version]:
            raise RuntimeError("B2_003_PREREQUISITES_REQUIRED")
    if versions[POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID]:
        raise RuntimeError("B2_003_ALREADY_APPLIED")
    if state["binding_table_present"]:
        raise RuntimeError("B2_003_PRECONDITION_FAILED")


def _binding_structure(connection: Any) -> dict[str, Any]:
    rows = connection.execute(text("""
        SELECT contype, pg_get_constraintdef(oid) AS definition
          FROM pg_constraint WHERE conrelid = to_regclass(:table)
    """), {"table": BINDING_TABLE}).all()
    # PostgreSQL renders harmless parentheses and text casts in CHECK expressions.
    def normalized(value: str) -> str:
        return "".join(value.replace("::text", "").split()).replace("(", "").replace(")", "")
    expected = [
        ("p", "PRIMARY KEY (admission_reference)"),
        ("u", "UNIQUE (trust_reference)"),
        ("f", "FOREIGN KEY (admission_reference) REFERENCES governance.production_signer_admission_records(admission_reference) ON UPDATE RESTRICT ON DELETE RESTRICT"),
        ("f", "FOREIGN KEY (trust_reference) REFERENCES governance.production_trust_records(trust_reference) ON UPDATE RESTRICT ON DELETE RESTRICT"),
        ("c", "CHECK (admission_hash ~ '^[0-9a-f]{64}$')"),
        ("c", "CHECK (trust_hash ~ '^[0-9a-f]{64}$')"),
        ("c", "CHECK (binding_hash ~ '^[0-9a-f]{64}$')"),
        ("c", "CHECK (schema_version = 'qingyu-b2-production-signer-admission-trust-binding-v1')"),
        ("c", "CHECK (durable_store_schema_version = 'qingyu-b2-postgres-production-signer-admission-trust-binding-store-v1')"),
        ("c", "CHECK (jsonb_typeof(provenance) = 'object' AND provenance <> '{}'::jsonb)"),
    ]
    owners = connection.execute(text("""
        SELECT pg_get_userbyid(c.relowner), pg_get_userbyid(n.nspowner)
          FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
         WHERE c.oid=to_regclass(:table)
    """), {"table": BINDING_TABLE}).one()
    valid = (sorted((kind, normalized(definition)) for kind, definition in rows) ==
             sorted((kind, normalized(definition)) for kind, definition in expected)
             and tuple(owners) == (CONTROL_OWNER_ROLE, CONTROL_OWNER_ROLE))
    if not valid:
        raise RuntimeError("B2_003_STRUCTURE_MISMATCH")
    return {"constraints": [{"type": kind, "definition": definition} for kind, definition in rows],
            "table_owner": owners[0], "schema_owner": owners[1], "verified": True}


def _collect_binding_postconditions(url: str, before: dict[str, Any]) -> dict[str, Any]:
    engine = create_engine(url, pool_pre_ping=True)
    try:
        with engine.begin() as connection:
            state = _collect_binding_state(connection)
            if (state["ledger_versions"] != {name: [version] for name, version in BINDING_LEDGER_VERSIONS.items()}
                    or not state["binding_table_present"] or state["binding_row_count"] != 0
                    or state["sources"] != before["sources"]):
                raise RuntimeError("B2_003_POSTCONDITION_FAILED")
            structure = _binding_structure(connection)
        return {**state, "source_preservation": True, "structure": structure}
    finally:
        engine.dispose()


def _canonical_migration_callable(migration_id: str) -> Callable[[str], None]:
    # Code-level callables only. Metadata strings are never dynamically resolved.
    return {
        POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID: apply_r1_production_signer_admission_store_migration,
        POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID: apply_r1_production_signer_admission_trust_binding_store_migration,
    }[migration_id]


def _run_probe(url: str, migration_id: str) -> dict[str, Any]:
    engine = create_engine(url, pool_pre_ping=True)
    with engine.begin() as connection:
        identity_before = connection.execute(
            text("SELECT session_user, current_user, current_database(), version()")
        ).one()
        _assert_identity(identity_before)
        owner_member = connection.execute(
            text("SELECT pg_has_role(current_user, 'qingyu_control_owner', 'MEMBER')")
        ).scalar_one()
        connection.execute(text("SET ROLE qingyu_control_owner"))
        identity_during = connection.execute(
            text("SELECT session_user, current_user, current_database()")
        ).one()
        readonly_state = (_collect_binding_state(connection) if migration_id == POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID
                          else _collect_readonly_state(connection))
        connection.execute(text("RESET ROLE"))
        identity_after = connection.execute(
            text("SELECT session_user, current_user, current_database()")
        ).one()
        role_rows = connection.execute(text("""
            SELECT rolname, rolcanlogin, rolsuper, rolcreatedb, rolcreaterole,
                   rolreplication, rolbypassrls, rolinherit
              FROM pg_roles
             WHERE rolname IN ('qingyu_control_owner', 'qingyu_control_migrator')
             ORDER BY rolname
        """)).mappings().all()

    return {
        "status": "PASS",
        "mode": "PROBE",
        "credential_source": _safe_secret_metadata(),
        "migration_id": migration_id,
        "migration_schema_version": ALLOWED_MIGRATIONS[migration_id]["schema_version"],
        "canonical_callable": ALLOWED_MIGRATIONS[migration_id]["callable"],
        "target_database": R1_PRODUCTION_CONTROL_DATABASE_NAME,
        "session_user": identity_before[0],
        "current_user_before_set_role": identity_before[1],
        "database": identity_before[2],
        "server_version_prefix": str(identity_before[3]).split(",", 1)[0],
        "owner_member": bool(owner_member),
        "current_user_during_owner_role": identity_during[1],
        "session_user_during_owner_role": identity_during[0],
        "current_user_after_reset_role": identity_after[1],
        "roles": [dict(row) for row in role_rows],
        "mutation_performed": False,
        "apply_callable_imported": callable(_canonical_migration_callable(migration_id)),
        **readonly_state,
    }



def _url_with_fixed_owner_role(url: str) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    if "options" in query:
        raise RuntimeError("MIGRATION_CONNECTION_OPTIONS_ALREADY_PRESENT")
    query["options"] = f"-c role={CONTROL_OWNER_ROLE}"
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _migration_connection_identity(url: str) -> dict[str, str]:
    engine = create_engine(url, pool_pre_ping=True)
    with engine.begin() as connection:
        identity = connection.execute(text("SELECT session_user, current_user, current_database()")).one()
        superuser = connection.execute(text("SELECT bool_or(rolsuper) FROM pg_roles WHERE rolname IN (session_user, current_user)")).scalar_one()
        if superuser:
            raise RuntimeError("MIGRATION_SUPERUSER_NOT_ALLOWED")
    return {
        "session_user": identity[0],
        "current_user": identity[1],
        "database": identity[2],
    }


def _assert_owner_authority_connection(url: str) -> dict[str, str]:
    identity = _migration_connection_identity(url)
    if identity["session_user"] != CONTROL_MIGRATOR_ROLE:
        raise RuntimeError("MIGRATION_CONNECTION_SESSION_USER_MISMATCH")
    if identity["current_user"] != CONTROL_OWNER_ROLE:
        raise RuntimeError("MIGRATION_CONNECTION_CURRENT_USER_MISMATCH")
    if identity["database"] != R1_PRODUCTION_CONTROL_DATABASE_NAME:
        raise RuntimeError("MIGRATION_CONNECTION_DATABASE_MISMATCH")
    return identity


def _collect_apply_postconditions(url: str) -> dict[str, Any]:
    engine = create_engine(url, pool_pre_ping=True)
    with engine.begin() as connection:
        readonly_state = _collect_readonly_state(connection)
        b2_002_count = connection.execute(text("""
            SELECT count(*) FROM governance.schema_migrations
             WHERE migration_id = 'b2_002_postgres_production_signer_admission_store'
        """)).scalar_one()
        admission_row_count = connection.execute(text(
            "SELECT count(*) FROM governance.production_signer_admission_records"
        )).scalar_one() if readonly_state["admission_table_present"] else 0
    return {
        **readonly_state,
        "b2_002_count": int(b2_002_count),
        "admission_row_count": int(admission_row_count),
    }

def _run_apply(
    url: str,
    migration_id: str,
) -> dict[str, Any]:
    if _validate_migration(migration_id):
        raise RuntimeError("MIGRATION_NOT_ALLOWLISTED")
    is_binding = migration_id == POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID
    engine = create_engine(url, pool_pre_ping=True)
    with engine.begin() as connection:
        identity_before = connection.execute(
            text("SELECT session_user, current_user, current_database(), version()")
        ).one()
        _assert_identity(identity_before)
        owner_member = connection.execute(
            text("SELECT pg_has_role(current_user, :owner_role, 'MEMBER')"), {"owner_role": CONTROL_OWNER_ROLE}
        ).scalar_one()
        if not owner_member:
            raise RuntimeError("OWNER_ROLE_TRANSITION_FAILED")
        owner_can_login = connection.execute(
            text("SELECT rolcanlogin FROM pg_roles WHERE rolname = :owner_role"), {"owner_role": CONTROL_OWNER_ROLE}
        ).scalar_one()
        if owner_can_login:
            raise RuntimeError("OWNER_ROLE_LOGIN_NOT_ALLOWED")
        connection.execute(text("SET ROLE qingyu_control_owner"))
        identity_during = connection.execute(
            text("SELECT session_user, current_user, current_database()")
        ).one()
        if identity_during[0] != CONTROL_MIGRATOR_ROLE or identity_during[1] != CONTROL_OWNER_ROLE or identity_during[2] != R1_PRODUCTION_CONTROL_DATABASE_NAME:
            raise RuntimeError("OWNER_ROLE_TRANSITION_FAILED")
        before = _collect_binding_state(connection) if is_binding else None
        if is_binding:
            _require_binding_preconditions(before)
        connection.execute(text("RESET ROLE"))
    migration_url = _url_with_fixed_owner_role(url)
    migration_identity = _assert_owner_authority_connection(migration_url)
    try:
        _canonical_migration_callable(migration_id)(migration_url)
    except Exception as exc:  # no fallback; no manual SQL; no retry as another role
        raise RuntimeError("CANONICAL_MIGRATION_FAILED") from exc
    if is_binding:
        try:
            postconditions = _collect_binding_postconditions(migration_url, before)
        except DBAPIError as exc:
            raise RuntimeError("B2_003_POSTCHECK_UNAVAILABLE") from exc
    else:
        postconditions = _collect_apply_postconditions(migration_url)
    mutation_confirmed = bool(postconditions["binding_table_present"]) if is_binding else bool(postconditions["b2_002_present"] and postconditions["admission_table_present"])
    if not mutation_confirmed:
        raise RuntimeError("APPLY_POSTCONDITION_MISSING")
    return {
        "status": "PASS",
        "mode": "APPLY",
        "migration_id": migration_id,
        "target_database": R1_PRODUCTION_CONTROL_DATABASE_NAME,
        "session_user": identity_before[0],
        "current_user_before_set_role": identity_before[1],
        "current_user_during_owner_role": identity_during[1],
        "migration_connection_session_user": migration_identity["session_user"],
        "migration_connection_current_user": migration_identity["current_user"],
        "migration_connection_database": migration_identity["database"],
        "migration_result": "CANONICAL_MIGRATION_CALL_COMPLETED",
        "mutation_performed": mutation_confirmed,
        **postconditions,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Qingyu qingyu_control migrator executor")
    parser.add_argument("--mode", choices=["probe", "apply"], default="probe")
    parser.add_argument("--migration", default=POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID)
    parser.add_argument("--target-db", "--target-database", dest="target_db", default=R1_PRODUCTION_CONTROL_DATABASE_NAME)
    parser.add_argument("--confirm", default=None)
    args = parser.parse_args(argv)

    target_error = _validate_target(args.target_db)
    if target_error:
        return _fail(target_error, target_db=args.target_db)
    migration_error = _validate_migration(args.migration)
    if migration_error:
        return _fail(migration_error, migration=args.migration)
    if args.mode == "apply":
        confirm_error = _validate_confirmation(args.migration, args.target_db, args.confirm)
        if confirm_error:
            return _fail(confirm_error, migration=args.migration, target_db=args.target_db)

    try:
        if args.mode == "probe":
            result = _run_probe(_connect_url(), args.migration)
        else:
            result = _run_apply(_connect_url(), args.migration)
    except RuntimeError as exc:
        code = str(exc).splitlines()[0]
        if code not in {
            "MIGRATOR_SESSION_USER_MISMATCH",
            "DATABASE_IDENTITY_MISMATCH",
            "OWNER_ROLE_TRANSITION_FAILED",
            "OWNER_ROLE_LOGIN_NOT_ALLOWED",
            "MIGRATION_CONNECTION_OPTIONS_ALREADY_PRESENT",
            "MIGRATION_CONNECTION_SESSION_USER_MISMATCH",
            "MIGRATION_CONNECTION_CURRENT_USER_MISMATCH",
            "MIGRATION_CONNECTION_DATABASE_MISMATCH",
            "CANONICAL_MIGRATION_FAILED",
            "APPLY_POSTCONDITION_MISSING",
            "CONTROL_DATABASE_URL_MIGRATOR_MISSING",
            "MIGRATION_NOT_ALLOWLISTED",
            "MIGRATION_SUPERUSER_NOT_ALLOWED",
            "MIGRATION_CONNECTION_IDENTITY_MISMATCH",
            "B2_003_PREREQUISITES_REQUIRED",
            "B2_003_ALREADY_APPLIED",
            "B2_003_PRECONDITION_FAILED",
            "B2_003_POSTCONDITION_FAILED",
            "B2_003_STRUCTURE_MISMATCH",
            "B2_003_POSTCHECK_UNAVAILABLE",
        }:
            code = exc.__class__.__name__
        return _fail(code, migration=args.migration, target_db=args.target_db,
                     mutation_performed=code in {"B2_003_POSTCONDITION_FAILED", "B2_003_STRUCTURE_MISMATCH", "B2_003_POSTCHECK_UNAVAILABLE"})
    except Exception as exc:
        return _fail(exc.__class__.__name__, migration=args.migration, target_db=args.target_db)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
