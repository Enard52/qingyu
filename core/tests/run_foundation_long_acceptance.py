from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import time
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.canonical import sha256_hex
from app.errors import CoreError
from app.foundation_rehearsal import (
    PRODUCTION_MARKERS,
    REHEARSAL_ENVIRONMENT,
    PersistentRehearsalAuthority,
    PostgresAuthorityStateStore,
    RehearsalTarget,
    assert_rehearsal_genesis_request,
    assert_rehearsal_isolation,
    backup_metadata,
    build_restore_request,
    canonical_read_model,
    rehearsal_identity_summary,
    verify_backup_metadata,
)
from app.schemas import GenesisRequest
from tests.test_foundation_closure_rehearsal import (
    FoundationPostgresEnvironment,
    genesis_request,
    mutation_request,
)


def persistent_authority(env: FoundationPostgresEnvironment) -> PersistentRehearsalAuthority:
    env.create_database("foundation_authority")
    return PersistentRehearsalAuthority(PostgresAuthorityStateStore(env.url("foundation_authority")))


def restart_authority(env: FoundationPostgresEnvironment) -> PersistentRehearsalAuthority:
    return PersistentRehearsalAuthority(PostgresAuthorityStateStore(env.url("foundation_authority")))


def docker_lines(*args: str) -> list[str]:
    output = subprocess.check_output(["docker", *args], stderr=subprocess.STDOUT, text=True).strip()
    if not output:
        return []
    return [line for line in output.splitlines() if line.strip()]


def owner_resource_snapshot(owner: str) -> dict[str, Any]:
    label = f"qingyu.foundation.owner={owner}"
    return {
        "containers": docker_lines("ps", "-a", "--filter", f"label={label}", "--format", "{{.Names}} {{.Status}}"),
        "volumes": docker_lines("volume", "ls", "--filter", f"label={label}", "--format", "{{.Name}}"),
        "networks": docker_lines("network", "ls", "--filter", f"label={label}", "--format", "{{.Name}}"),
    }


def global_resource_snapshot() -> dict[str, Any]:
    label = "qingyu.foundation.owner"
    return {
        "containers": docker_lines("ps", "-a", "--filter", f"label={label}", "--format", "{{.Names}} {{.Status}}"),
        "volumes": docker_lines("volume", "ls", "--filter", f"label={label}", "--format", "{{.Name}}"),
        "networks": docker_lines("network", "ls", "--filter", f"label={label}", "--format", "{{.Name}}"),
    }


def postgres_activity(env: FoundationPostgresEnvironment) -> dict[str, Any]:
    import psycopg

    with psycopg.connect(host="127.0.0.1", port=env.port, dbname="postgres", user="postgres", password=env.password, connect_timeout=2) as connection:
        rows = connection.execute(
            """
            SELECT datname, state, count(*)
            FROM pg_stat_activity
            WHERE datname LIKE 'foundation_%'
            GROUP BY datname, state
            ORDER BY datname, state
            """
        ).fetchall()
    return {f"{datname}:{state or 'none'}": count for datname, state, count in rows}


def state_checkpoint(label: str, service: Any, authority: PersistentRehearsalAuthority, continuity_id: uuid.UUID) -> dict[str, Any]:
    checkpoint = authority.export_checkpoint(continuity_id)
    try:
        read_model = service.core_read_model()
    except CoreError as exc:
        return {
            "label": label,
            "read_model_available": False,
            "read_model_error": str(exc),
            "authority_state": checkpoint,
            "recovery_state": checkpoint.get("recovery_state"),
        }
    return {
        "label": label,
        "read_model_available": True,
        "identity": read_model.identity_reference,
        "continuity_id": read_model.identity_reference["continuity_id"],
        "generation": read_model.generation,
        "state_version": read_model.generation["state_version"],
        "recovery_epoch": read_model.generation["continuity_epoch"],
        "authority_state": checkpoint,
        "recovery_state": read_model.governed_state["recovery_state"],
        "read_model_hash": read_model.read_model_hash,
        "governed_state_canonical_hash": sha256_hex(read_model.governed_state),
        "canonical_payload_sha256": sha256_hex(canonical_read_model(read_model)),
    }


def expect_core_error(label: str, fn: Any, expected_substrings: tuple[str, ...]) -> dict[str, Any]:
    try:
        fn()
    except CoreError as exc:
        code = str(exc)
        return {
            "case": label,
            "status": "PASS",
            "error": code,
            "fail_closed": any(item in code for item in expected_substrings),
        }
    return {"case": label, "status": "FAIL", "error": None, "fail_closed": False}


def production_boundary_guard() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    prod_target = RehearsalTarget(
        owner="qingyu-production-owner",
        host="10.0.0.5",
        port=5432,
        database="production",
        container="production-postgres",
        network="production-net",
        volume="production-volume",
        environment_marker="production",
    )
    cases.append(expect_core_error(
        "production_target_rejected",
        lambda: assert_rehearsal_isolation(prod_target),
        ("FOUNDATION_REHEARSAL",),
    ))
    request = genesis_request().model_copy(update={
        "continuity_alias": "qingyu-production",
        "governance_provenance": {
            "environment": "production",
            "production_activated": True,
            "requires_b2_activation": False,
            "production_activation_artifact": True,
        },
    })
    cases.append(expect_core_error(
        "production_genesis_marker_rejected",
        lambda: assert_rehearsal_genesis_request(request),
        ("FOUNDATION_REHEARSAL",),
    ))
    exposed_conversion_methods = [
        name for name in (
            "activate_production",
            "mark_production_active",
            "consume_production_credential",
            "export_production_genesis_artifact",
        )
        if hasattr(PersistentRehearsalAuthority, name)
    ]
    cases.append({
        "case": "no_rehearsal_to_production_conversion_api",
        "status": "PASS" if not exposed_conversion_methods else "FAIL",
        "exposed_methods": exposed_conversion_methods,
    })
    return {
        "status": "PASS" if all(case["status"] == "PASS" and case.get("fail_closed", True) for case in cases) else "FAIL",
        "production_markers": sorted(PRODUCTION_MARKERS),
        "cases": cases,
    }


def run_cycle(cycle_index: int, tmp_root: Path) -> dict[str, Any]:
    started = time.perf_counter()
    cycle_root = tmp_root / f"cycle-{cycle_index}"
    cycle_root.mkdir(parents=True, exist_ok=True)
    env = FoundationPostgresEnvironment(cycle_root).create()
    owner = env.owner
    state_drift: list[dict[str, Any]] = []
    negative_cases: list[dict[str, Any]] = []
    crash_replay: list[dict[str, Any]] = []
    restore_chain: dict[str, Any] = {}
    postgres_before_destroy: dict[str, Any] = {}
    try:
        authority = persistent_authority(env)
        service, _ = env.service("foundation_source", authority)
        request = genesis_request()
        assert_rehearsal_genesis_request(request)

        genesis = service.bootstrap_genesis(request)
        identity = rehearsal_identity_summary(request, service.core_read_model())
        state_drift.append(state_checkpoint("genesis", service, authority, request.continuity_id))

        authority = restart_authority(env)
        restarted, _ = env.service("foundation_source", authority)
        regenesis = restarted.bootstrap_genesis(request)
        crash_replay.append({
            "case": "genesis_response_loss_retry",
            "status": "PASS" if regenesis.genesis_id == genesis.genesis_id else "FAIL",
            "genesis_id": str(regenesis.genesis_id),
        })
        changed_genesis = request.model_copy(update={"genesis_request_id": f"changed-{cycle_index}", "continuity_id": uuid.uuid4()})
        negative_cases.append(expect_core_error(
            "changed_genesis_after_durable_commit",
            lambda: restarted.bootstrap_genesis(changed_genesis),
            ("GENESIS_ALREADY_EXISTS", "GENESIS_CONFLICT"),
        ))

        lease = restarted.acquire_owner_lease(request.continuity_id)
        mutation = mutation_request(request, lease, f"foundation-cycle-{cycle_index}-mutation-1")
        committed = restarted.governed_mutation(mutation)
        read_after_mutation = restarted.core_read_model()
        state_drift.append(state_checkpoint("mutation", restarted, authority, request.continuity_id))
        replay = restarted.governed_mutation(mutation)
        crash_replay.append({
            "case": "mutation_response_loss_retry",
            "status": "PASS" if replay.local_commit_id == committed.local_commit_id else "FAIL",
            "local_commit_id": str(replay.local_commit_id),
        })
        changed_mutation = mutation.model_copy(update={"payload": {"kind": "changed", "cycle": cycle_index}})
        negative_cases.append(expect_core_error(
            "changed_mutation_replay",
            lambda: restarted.governed_mutation(changed_mutation),
            ("MUTATION_RETRY_CONFLICT", "MUTATION_RETRY_CONTEXT_CONFLICT"),
        ))

        authority = restart_authority(env)
        restarted_after_mutation, _ = env.service("foundation_source", authority)
        state_drift.append(state_checkpoint("restart_after_mutation", restarted_after_mutation, authority, request.continuity_id))
        if restarted_after_mutation.core_read_model().model_dump(mode="json") != read_after_mutation.model_dump(mode="json"):
            raise AssertionError("read model drift after mutation restart")

        dump_a = tmp_root / f"cycle-{cycle_index}-a.sql"
        env.dump("foundation_source", dump_a)
        trust_a = authority.export_checkpoint(request.continuity_id)
        backup_a = backup_metadata(backup_path=dump_a, source_read_model=read_after_mutation, trust_anchor=trust_a)
        verify_backup_metadata(backup_a, backup_path=dump_a, expected_read_model=read_after_mutation, expected_trust_anchor=trust_a)
        env.restore("foundation_restore_b", dump_a)
        authority = restart_authority(env)
        restored_b, _ = env.service("foundation_restore_b", authority)
        restore_b_request = build_restore_request(
            request_id=f"foundation-cycle-{cycle_index}-restore-b",
            read_model=read_after_mutation,
            target_storage_generation_id=uuid.uuid4(),
        )
        verify_b = restored_b.verify_restore(restore_b_request)
        state_drift.append(state_checkpoint("restore_b_quarantine", restored_b, authority, request.continuity_id))
        replay_verify_b = restored_b.verify_restore(restore_b_request)
        crash_replay.append({
            "case": "restore_verification_response_loss_retry",
            "status": "PASS" if replay_verify_b == verify_b else "FAIL",
            "read_only": replay_verify_b.read_only,
        })
        authority = restart_authority(env)
        restored_b_after_quarantine_restart, _ = env.service("foundation_restore_b", authority)
        state_drift.append(state_checkpoint("restart_while_quarantined", restored_b_after_quarantine_restart, authority, request.continuity_id))
        negative_cases.append(expect_core_error(
            "quarantine_rejects_lease_after_restart",
            lambda: restored_b_after_quarantine_restart.acquire_owner_lease(request.continuity_id),
            ("RESTORE_FENCE_UNPROVEN",),
        ))
        activate_b = restored_b_after_quarantine_restart.activate_restore(restore_b_request)
        replay_activate_b = restored_b_after_quarantine_restart.activate_restore(restore_b_request)
        crash_replay.append({
            "case": "reactivation_response_loss_retry",
            "status": "PASS" if replay_activate_b == activate_b else "FAIL",
            "read_only": replay_activate_b.read_only,
        })
        state_drift.append(state_checkpoint("reactivate_b", restored_b_after_quarantine_restart, authority, request.continuity_id))
        changed_restore_generation = restore_b_request.model_copy(update={"target_storage_generation_id": uuid.uuid4()})
        negative_cases.append(expect_core_error(
            "changed_restore_generation_replay",
            lambda: restored_b_after_quarantine_restart.activate_restore(changed_restore_generation),
            ("RESTORE_REQUEST_CONFLICT",),
        ))

        authority = restart_authority(env)
        restored_b_active, _ = env.service("foundation_restore_b", authority)
        state_drift.append(state_checkpoint("restart_after_reactivation", restored_b_active, authority, request.continuity_id))
        lease_b = restored_b_active.acquire_owner_lease(request.continuity_id)
        final_b = restored_b_active.governed_mutation(mutation_request(
            request,
            lease_b,
            f"foundation-cycle-{cycle_index}-mutation-after-restore-b",
            epoch=restored_b_active.core_read_model().generation["continuity_epoch"],
        ))
        state_drift.append(state_checkpoint("final_mutation_b", restored_b_active, authority, request.continuity_id))

        read_b_final = restored_b_active.core_read_model()
        dump_b = tmp_root / f"cycle-{cycle_index}-b.sql"
        env.dump("foundation_restore_b", dump_b)
        trust_b = authority.export_checkpoint(request.continuity_id)
        backup_b = backup_metadata(backup_path=dump_b, source_read_model=read_b_final, trust_anchor=trust_b)
        verify_backup_metadata(backup_b, backup_path=dump_b, expected_read_model=read_b_final, expected_trust_anchor=trust_b)
        env.restore("foundation_restore_c", dump_b)
        authority = restart_authority(env)
        restored_c, _ = env.service("foundation_restore_c", authority)
        restore_c_request = build_restore_request(
            request_id=f"foundation-cycle-{cycle_index}-restore-c",
            read_model=read_b_final,
            target_storage_generation_id=uuid.uuid4(),
        )
        verify_c = restored_c.verify_restore(restore_c_request)
        activate_c = restored_c.activate_restore(restore_c_request)
        state_drift.append(state_checkpoint("restore_of_restore_c_active", restored_c, authority, request.continuity_id))
        read_c_active = restored_c.core_read_model()
        restore_chain = {
            "status": "PASS",
            "a_to_b": verify_b.model_dump(mode="json"),
            "b_to_c": verify_c.model_dump(mode="json"),
            "c_activation": activate_c.model_dump(mode="json"),
            "identity_stable": read_c_active.identity_reference == read_after_mutation.identity_reference,
            "continuity_stable": read_c_active.identity_reference["continuity_id"] == str(request.continuity_id),
            "recovery_epoch_progression": [
                read_after_mutation.generation["continuity_epoch"],
                read_b_final.generation["continuity_epoch"],
                read_c_active.generation["continuity_epoch"],
            ],
            "trust_anchor_state_versions": [trust_a["state_version"], trust_b["state_version"]],
        }

        wrong_continuity = build_restore_request(request_id=f"wrong-continuity-{cycle_index}", read_model=read_after_mutation, target_storage_generation_id=uuid.uuid4())
        wrong_continuity = wrong_continuity.model_copy(update={"manifest": wrong_continuity.manifest.model_copy(update={"continuity_id": uuid.uuid4()})})
        negative_cases.append(expect_core_error(
            "wrong_continuity",
            lambda: restarted_after_mutation.verify_restore(wrong_continuity),
            ("RESTORE_IDENTITY_MISMATCH", "CONTINUITY_UNKNOWN"),
        ))
        wrong_trust = deepcopy(backup_a)
        wrong_trust["trust_anchor"] = {**trust_a, "audit_head_hash": "0" * 64}
        negative_cases.append(expect_core_error(
            "wrong_trust_anchor",
            lambda: verify_backup_metadata(wrong_trust, backup_path=dump_a, expected_read_model=read_after_mutation, expected_trust_anchor=trust_a),
            ("FOUNDATION_BACKUP_TRUST_ANCHOR_MISMATCH",),
        ))
        wrong_checkpoint = deepcopy(backup_a)
        wrong_checkpoint["read_model_hash"] = "0" * 64
        negative_cases.append(expect_core_error(
            "wrong_checkpoint_hash",
            lambda: verify_backup_metadata(wrong_checkpoint, backup_path=dump_a, expected_read_model=read_after_mutation, expected_trust_anchor=trust_a),
            ("FOUNDATION_BACKUP_STATE_HASH_MISMATCH",),
        ))
        wrong_canonical = deepcopy(backup_a)
        wrong_canonical["canonical_payload_sha256"] = "0" * 64
        negative_cases.append(expect_core_error(
            "wrong_canonical_hash",
            lambda: verify_backup_metadata(wrong_canonical, backup_path=dump_a, expected_read_model=read_after_mutation, expected_trust_anchor=trust_a),
            ("FOUNDATION_BACKUP_CANONICAL_HASH_MISMATCH",),
        ))
        wrong_schema = deepcopy(backup_a)
        wrong_schema["schema_version"] = "wrong-schema"
        negative_cases.append(expect_core_error(
            "wrong_schema_version",
            lambda: verify_backup_metadata(wrong_schema, backup_path=dump_a, expected_read_model=read_after_mutation, expected_trust_anchor=trust_a),
            ("FOUNDATION_BACKUP_METADATA_MALFORMED",),
        ))
        wrong_migration = deepcopy(backup_a)
        wrong_migration["restore_manifest"] = {**wrong_migration["restore_manifest"], "witness_set_version": 999}
        negative_cases.append(expect_core_error(
            "wrong_migration_or_witness_version",
            lambda: verify_backup_metadata(wrong_migration, backup_path=dump_a, expected_read_model=read_after_mutation, expected_trust_anchor=trust_a),
            ("FOUNDATION_BACKUP_RESTORE_MANIFEST_MISMATCH",),
        ))

        postgres_before_destroy = postgres_activity(env)
        elapsed = round(time.perf_counter() - started, 3)
        status = "PASS" if (
            all(item["status"] == "PASS" for item in crash_replay)
            and all(item["status"] == "PASS" and item.get("fail_closed", True) for item in negative_cases)
            and restore_chain.get("status") == "PASS"
            and restore_chain.get("identity_stable") is True
            and restore_chain.get("continuity_stable") is True
            and final_b.status == "COMMITTED"
            and identity["production_activated"] is False
        ) else "FAIL"
        return {
            "cycle": cycle_index,
            "status": status,
            "owner": owner,
            "elapsed_seconds": elapsed,
            "identity": identity,
            "state_drift": state_drift,
            "crash_replay": crash_replay,
            "negative_cases": negative_cases,
            "restore_chain": restore_chain,
            "postgres_activity_before_destroy": postgres_before_destroy,
            "authority_persistence": authority.persistence_summary(),
        }
    finally:
        env.destroy()
        # Let Docker release resources before checking labels.
        time.sleep(0.2)


def postgres_authority_scope_guard(repo_root: Path) -> dict[str, Any]:
    result = subprocess.check_output(
        ["rg", "-n", "foundation_rehearsal_authority_state|PersistentRehearsalAuthority|PostgresAuthorityStateStore", "app", "tests", "docs"],
        cwd=repo_root,
        stderr=subprocess.STDOUT,
        text=True,
    )
    lines = [line for line in result.splitlines() if line.strip()]
    forbidden_prefixes = (
        "app/control_plane/",
        "app/current_scope",
        "app/gateway",
        "app/memory",
        "app/runtime",
    )
    forbidden_hits = [line for line in lines if line.startswith(forbidden_prefixes)]
    return {
        "status": "PASS" if not forbidden_hits else "FAIL",
        "forbidden_hits": forbidden_hits,
        "allowed_usage_summary": [line for line in lines if not line.startswith("docs/evidence/")][:100],
        "classification": "rehearsal/candidate authority implementation only",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Foundation Closure long acceptance rehearsal cycles.")
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.cycles < 2:
        raise SystemExit("--cycles must be at least 2 for repetition evidence")

    repo_root = Path(__file__).resolve().parents[1]
    started_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    cycles: list[dict[str, Any]] = []
    resource_checks: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="qingyu-foundation-long-") as tmp:
        tmp_root = Path(tmp)
        for index in range(1, args.cycles + 1):
            cycle = run_cycle(index, tmp_root)
            cycles.append(cycle)
            after_destroy = owner_resource_snapshot(cycle["owner"])
            resource_checks.append({
                "cycle": index,
                "owner": cycle["owner"],
                "after_destroy": after_destroy,
                "status": "PASS" if not any(after_destroy.values()) else "FAIL",
            })
    production_guard = production_boundary_guard()
    scope_guard = postgres_authority_scope_guard(repo_root)
    global_resources = global_resource_snapshot()
    identity_values = [cycle["identity"]["qingyu_identity_id"] for cycle in cycles]
    continuity_values = [cycle["identity"]["continuity_id"] for cycle in cycles]
    result = {
        "schema_version": "qingyu-foundation-long-acceptance-v1",
        "started_at": started_at,
        "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cycles_requested": args.cycles,
        "cycles_completed": len(cycles),
        "status": "PASS" if (
            len(cycles) == args.cycles
            and all(cycle["status"] == "PASS" for cycle in cycles)
            and all(check["status"] == "PASS" for check in resource_checks)
            and production_guard["status"] == "PASS"
            and scope_guard["status"] == "PASS"
            and len(set(identity_values)) == len(identity_values)
            and len(set(continuity_values)) == len(continuity_values)
            and not any(global_resources.values())
        ) else "FAIL",
        "identity_uniqueness_between_rehearsals": len(set(identity_values)) == len(identity_values),
        "continuity_uniqueness_between_rehearsals": len(set(continuity_values)) == len(continuity_values),
        "cycles": cycles,
        "resource_checks": resource_checks,
        "global_resource_check": global_resources,
        "production_boundary_guard": production_guard,
        "postgres_authority_scope_guard": scope_guard,
    }
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": result["status"],
        "cycles_completed": result["cycles_completed"],
        "identity_uniqueness_between_rehearsals": result["identity_uniqueness_between_rehearsals"],
        "global_resource_check": result["global_resource_check"],
    }, indent=2, sort_keys=True))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())



