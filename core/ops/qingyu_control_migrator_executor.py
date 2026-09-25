from __future__ import annotations

import argparse
import json
import subprocess
import sys
from typing import Any

from sqlalchemy import create_engine, text

from app.b2_signer_trust import (
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID,
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION,
    R1_PRODUCTION_CONTROL_DATABASE_NAME,
    apply_r1_production_signer_admission_store_migration,
)

SECRET_PATH = "/etc/qingyu/secrets/control-postgres.env"
WSL_DISTRO = "qingyu-prod-local-01"
ALLOWED_MIGRATIONS = {
    POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID: {
        "schema_version": POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_SCHEMA_VERSION,
        "callable": "app.b2_signer_trust.apply_r1_production_signer_admission_store_migration",
    }
}


def _fail(code: str, **extra: Any) -> int:
    payload = {"status": "FAIL", "code": code}
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
    mode_text = listing[0]
    owner_uid = listing[2]
    group_gid = listing[3]
    return {
        "owner_uid": owner_uid,
        "group_gid": group_gid,
        "mode_text": mode_text,
        "size_bytes": size,
        "path": SECRET_PATH,
    }


def _connect_url() -> str:
    values = _read_control_env()
    url = values.get("CONTROL_DATABASE_URL_MIGRATOR")
    if not url:
        raise RuntimeError("CONTROL_DATABASE_URL_MIGRATOR_MISSING")
    return url


def _run_probe(url: str, migration_id: str) -> dict[str, Any]:
    engine = create_engine(url, pool_pre_ping=True)
    with engine.begin() as connection:
        identity_before = connection.execute(
            text("SELECT session_user, current_user, current_database(), version()")
        ).one()
        if identity_before[0] != "qingyu_control_migrator":
            raise RuntimeError("MIGRATOR_SESSION_USER_MISMATCH")
        if identity_before[2] != R1_PRODUCTION_CONTROL_DATABASE_NAME:
            raise RuntimeError("DATABASE_IDENTITY_MISMATCH")

        owner_member = connection.execute(
            text("SELECT pg_has_role(current_user, 'qingyu_control_owner', 'MEMBER')")
        ).scalar_one()

        connection.execute(text("SET ROLE qingyu_control_owner"))
        identity_during = connection.execute(
            text("SELECT session_user, current_user, current_database()")
        ).one()
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
        "b2_002_present": bool(b2_002),
        "admission_table_present": bool(admission_table),
        "trust_count": int(trust["trust_count"]),
        "trust_record_hash": trust["record_hash"],
        "signer_key_id": trust["key_id"],
        "mutation_performed": False,
        "apply_callable_imported": callable(apply_r1_production_signer_admission_store_migration),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Qingyu qingyu_control migrator executor")
    parser.add_argument("--mode", choices=["probe", "apply"], default="probe")
    parser.add_argument("--migration", default=POSTGRES_PRODUCTION_SIGNER_ADMISSION_STORE_MIGRATION_ID)
    parser.add_argument("--target-db", default=R1_PRODUCTION_CONTROL_DATABASE_NAME)
    args = parser.parse_args(argv)

    if args.target_db != R1_PRODUCTION_CONTROL_DATABASE_NAME:
        return _fail("TARGET_DATABASE_OVERRIDE_REJECTED", target_db=args.target_db)
    if args.migration not in ALLOWED_MIGRATIONS:
        return _fail("MIGRATION_NOT_ALLOWLISTED", migration=args.migration)
    if args.mode == "apply":
        return _fail("APPLY_MODE_DISABLED_FOR_THIS_TASK", migration=args.migration)

    try:
        result = _run_probe(_connect_url(), args.migration)
    except Exception as exc:
        return _fail(exc.__class__.__name__, detail=str(exc).splitlines()[0][:200])
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

