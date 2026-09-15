"""Run tests ONLY against an explicitly identified disposable F3 container.

Never provisions/adopts a cluster, runs Alembic, reads an acceptance Root, or
prints a credential. Docker's synthetic test password stays in process memory
and the pytest child environment. Reports contain public evidence only.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import psycopg
from psycopg.conninfo import make_conninfo


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))


def inspect_resource(kind: str, identity: str) -> dict:
    command = (["docker", "container", "inspect", identity] if kind == "container"
               else ["docker", kind, "inspect", identity])
    result = subprocess.run(command, check=True, capture_output=True, text=True,
                            timeout=15, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    values = json.loads(result.stdout)
    if len(values) != 1:
        raise RuntimeError("explicit test resource unavailable")
    return values[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--cluster-system-id", required=True)
    parser.add_argument("--report-dir", required=True)
    parser.add_argument("pytest_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if (not re.fullmatch(r"[0-9a-f]{64}", args.container_id)
            or not re.fullmatch(r"[0-9a-f]{32}", args.run_id)
            or not re.fullmatch(r"[0-9]{10,32}", args.cluster_system_id)):
        raise RuntimeError("exact independently recorded test identities required")
    report_dir = (ROOT / args.report_dir).resolve()
    evidence_root = (ROOT / "docs/evidence/r1-f3-coordinator").resolve()
    if not report_dir.is_relative_to(evidence_root) or report_dir == evidence_root:
        raise RuntimeError("report must be a new child of F3 evidence directory")
    if report_dir.exists():
        raise RuntimeError("refusing to overwrite prior test evidence")

    container = inspect_resource("container", args.container_id)
    expected_name = "r1_f3_test_only_" + args.run_id
    labels = {"io.qingyu.purpose": "R1_F3_TEST_ONLY", "io.qingyu.run": args.run_id}
    if (container["Id"] != args.container_id or container["Name"] != "/" + expected_name
            or container["Config"]["Labels"] != labels or not container["State"]["Running"]):
        raise RuntimeError("test container provenance mismatch")
    bindings = container["NetworkSettings"]["Ports"]["5432/tcp"]
    if len(bindings) != 1 or bindings[0]["HostIp"] != "127.0.0.1":
        raise RuntimeError("test database must publish only one loopback binding")
    # Read only the already-verified disposable container's synthetic credential.
    config = dict(item.split("=", 1) for item in container["Config"]["Env"] if "=" in item)
    database = "r1_f3_test_" + args.run_id
    if config.get("POSTGRES_DB") != database or config.get("POSTGRES_USER") != "r1_f3_test_admin":
        raise RuntimeError("test-only admin/database identity mismatch")
    password = config["POSTGRES_PASSWORD"]
    params = dict(host="127.0.0.1", port=bindings[0]["HostPort"], dbname=database,
                  user="r1_f3_test_admin", password=password, sslmode="disable", connect_timeout="5")
    environment = {
        "R1_F3_TEST_ONLY": "1", "R1_F3_TEST_CONTAINER_ID": args.container_id,
        "R1_F3_TEST_CONTAINER_NAME": expected_name, "R1_F3_TEST_RUN_ID": args.run_id,
        "R1_F3_TEST_CLUSTER_SYSTEM_IDENTIFIER": args.cluster_system_id,
        "R1_F3_TEST_DATABASE_URL": make_conninfo(**params),
    }
    os.environ.update(environment)
    from r1_f3_target import verify_test_target
    expected_system = verify_test_target(params)
    with psycopg.connect(**params, options="-c default_transaction_read_only=on") as connection:
        actual = connection.execute("SELECT current_database(), version(), "
            "(SELECT system_identifier::text FROM pg_control_system())").fetchone()
        if actual[0] != database or actual[2] != expected_system:
            raise RuntimeError("database is not independently identified disposable cluster")

    from app.control_plane.r1_candidate_schema import F3_SCHEMA_DIGEST
    from app.control_plane.r1_schema_snapshot import verify_schema_snapshot
    networks = []
    for name, value in container["NetworkSettings"]["Networks"].items():
        observed = inspect_resource("network", value["NetworkID"])
        networks.append({"name": name, "id": observed["Id"], "internal": observed["Internal"],
                         "options": observed["Options"], "labels": observed["Labels"]})
    paths = sorted(set(ROOT.glob("app/control_plane/r1_*"))
                   | set(ROOT.glob("app/r1_*.py")) | set(ROOT.glob("tests/*r1*f3*"))
                   | set(ROOT.glob("tests/test_r1*coordinator*")))
    test_args = args.pytest_args
    if test_args[:1] == ["--"]:
        test_args = test_args[1:]
    if not test_args:
        test_args = ["tests/test_r1_coordinator_postgres.py"]
    report = {
        "scope": "TEST-ONLY F3 COORDINATOR EVIDENCE; NOT R1 POSTGRESQL ACCEPTANCE",
        "started_utc": datetime.now(timezone.utc).isoformat(), "run_id": args.run_id,
        "container": expected_name, "container_id": args.container_id,
        "image": container["Config"]["Image"], "image_id": container["Image"],
        "database": database, "cluster_system_identifier": actual[2], "version": actual[1],
        "endpoint": {"host": "127.0.0.1", "port": int(params["port"])},
        "volume": container["Mounts"][0]["Name"], "networks": networks,
        "credentials": "new synthetic test passwords; memory/child environment only; never acceptance secrets",
        "tls": "Explicit disposable local SQL profile: disabled; no production/acceptance TLS admission",
        "candidate_source_digest": F3_SCHEMA_DIGEST, "unchanged_authored_baseline_digest": verify_schema_snapshot(),
        "source_hashes": {str(path.relative_to(ROOT)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in paths if path.is_file()},
        "pytest_arguments": test_args, "formal_alembic_run": False,
        "legacy_resource_access": False, "signed_migration_intent": "NOT STARTED",
    }
    report_dir.mkdir(parents=True)
    command = [sys.executable, "-m", "pytest", "-q", "-ra", "--tb=short", *test_args]
    output = []
    with subprocess.Popen(command, cwd=ROOT, env={**os.environ, **environment},
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, encoding="utf-8", errors="replace") as process:
        assert process.stdout is not None
        for line in process.stdout:
            safe = line.replace(environment["R1_F3_TEST_DATABASE_URL"], "[REDACTED TEST CONNECTION]")
            safe = safe.replace(password, "[REDACTED TEST PASSWORD]")
            output.append(safe)
            print(safe, end="", flush=True)
        result = process.wait()
    report.update(finished_utc=datetime.now(timezone.utc).isoformat(), exit_code=result)
    (report_dir / "pytest.txt").write_text("".join(output), encoding="utf-8")
    (report_dir / "evidence.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("F3 TEST-ONLY evidence:", str(report_dir))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
