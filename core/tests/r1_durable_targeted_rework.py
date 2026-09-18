"""Targeted Slice04 rework probes for final-review findings.

These are executable product probes, not unit fakes: they use the same
PostgreSQL/TLS/SQLite harness as the Slice04 acceptance tests and assert the
database side effects that the final non-author review found missing.
"""
from __future__ import annotations

from pathlib import Path
import hashlib
import json
import subprocess
import sys
import time

import psycopg

from app.control_plane.r1_validation_codec import ContractError, c2, decode
from app.control_plane.r1_scoped_transport import ScopedHTTPRejected, ScopedTransportUncertain
from app.control_plane.r1_durable_transport import DurableAuthorityClient, DurableCredential
from tests.r1_durable_run import config, core, request_for, service, start_server, trust


def stop(child, output):
    if child.poll() is None:
        child.terminate()
    child.wait(timeout=15)
    output.close()


def issue_rows(config_path, operation_id, kind):
    cfg = config(config_path)
    with psycopg.connect(host=cfg["host"], port=cfg["port"], dbname=cfg["dbname"],
                         user="postgres", password=cfg["admin_password"]) as db:
        rows = db.execute(
            "SELECT issue_sequence, object_wire FROM control_plane.r1d_issues "
            "WHERE scope_id=%s AND operation_id=%s AND issue_kind=%s "
            "ORDER BY issue_sequence",
            (cfg["scope_id"], operation_id, kind),
        ).fetchall()
    return [(int(row[0]), bytes(row[1])) for row in rows]


def authority_event_count(config_path):
    authority, _ = service(config_path)
    return authority.store.transact(lambda tx: len(authority._engine(tx).authority["events"]))


def response_loss_expiry_replay(config_path):
    path = Path(config_path).resolve()
    coordinator = core(path, create=not (path.parent / "finish.sqlite").exists())
    request, source = request_for(path, coordinator, "COMMIT", "targeted-lost-grant-expiry")
    operation_id = coordinator.persist_intent(request, source)
    child, output = start_server(path, "after_grant_commit")
    try:
        try:
            coordinator.recover(operation_id)
            raise AssertionError("expected response loss")
        except ScopedTransportUncertain:
            pass
        child.wait(timeout=15)
    finally:
        stop(child, output)

    _, provider = service(path)
    first_wire = provider.query_current_issue("GRANT", operation_id)
    first = decode(first_wire)
    wait_seconds = max(0.0, (first["expires_at"] - time.time_ns() // 1_000_000 - 4_000) / 1000.0)
    time.sleep(wait_seconds)
    child, output = start_server(path)
    try:
        reopened = core(path)
        reopened.source.ensure_execution(request, source)
    finally:
        stop(child, output)
    near_expiry_wire = provider.query_current_issue("GRANT", operation_id)

    expired_wait = max(0.0, (first["expires_at"] - time.time_ns() // 1_000_000 + 250) / 1000.0)
    time.sleep(expired_wait)
    child, output = start_server(path)
    try:
        expired = core(path)
        expired.source.ensure_execution(request, source)
        try:
            expired.client.prepare(request, source)
            raise AssertionError("expired grant prepared new action")
        except ScopedHTTPRejected as exc:
            assert exc.status == 409
    finally:
        stop(child, output)
    expired_wire = provider.query_current_issue("GRANT", operation_id)
    rows = issue_rows(path, operation_id, "GRANT")
    assert first_wire == near_expiry_wire == expired_wire
    assert [seq for seq, _ in rows] == [1]
    return {
        "operation_id": operation_id,
        "first_sequence": first["grant_sequence"],
        "near_expiry_same_bytes": near_expiry_wire == first_wire,
        "expired_history_same_bytes": expired_wire == first_wire,
        "issue_rows": len(rows),
        "signed_object_sha256": hashlib.sha256(first_wire).hexdigest(),
        "expired_current_use_rejected": True,
    }


def permit_rejection_has_no_side_effect(config_path):
    path = Path(config_path).resolve()
    coordinator = core(path)
    request, source = request_for(path, coordinator, "COMMIT", "targeted-permit-reject")
    operation_id = coordinator.persist_intent(request, source)
    child, output = start_server(path, "after_terminal_commit")
    try:
        try:
            coordinator.recover(operation_id)
            raise AssertionError("expected terminal response loss")
        except ScopedTransportUncertain:
            pass
        child.wait(timeout=15)
    finally:
        stop(child, output)

    before = issue_rows(path, operation_id, "PERMIT")
    changed = decode(request)
    changed["intent"]["payload"]["value"] = "wrong-request-digest"
    changed_wire = c2(changed)
    child, output = start_server(path)
    try:
        try:
            coordinator.client.ensure_permit(operation_id, changed_wire)
            raise AssertionError("wrong digest permit accepted")
        except ScopedHTTPRejected as exc:
            assert exc.status == 409
    finally:
        stop(child, output)
    after_wrong_digest = issue_rows(path, operation_id, "PERMIT")

    child, output = start_server(path)
    try:
        try:
            coordinator.client.ensure_permit("00000000-0000-0000-0000-000000000000", request)
            raise AssertionError("wrong operation permit accepted")
        except ScopedHTTPRejected as exc:
            assert exc.status == 409
    finally:
        stop(child, output)
    after_wrong_operation = issue_rows(path, operation_id, "PERMIT")

    _, provider = service(path)
    try:
        provider.query_current_issue("PERMIT", operation_id)
        raise AssertionError("permit exists after rejected requests")
    except ContractError:
        pass
    assert before == after_wrong_digest == after_wrong_operation == []
    return {
        "operation_id": operation_id,
        "wrong_digest_rejected": True,
        "wrong_operation_rejected": True,
        "permit_rows_before": len(before),
        "permit_rows_after_wrong_digest": len(after_wrong_digest),
        "permit_rows_after_wrong_operation": len(after_wrong_operation),
        "no_committed_permit": True,
    }


def source_replay_conflict(config_path):
    path = Path(config_path).resolve()
    coordinator = core(path)
    request, source = request_for(path, coordinator, "COMMIT", "targeted-source-conflict")
    operation_id = coordinator.persist_intent(request, source)
    child, output = start_server(path)
    try:
        coordinator.source.ensure_execution(request, source)
        _, provider = service(path)
        before = provider.query_current_issue("GRANT", operation_id)
        changed = decode(source)
        changed["session_expires_at"] += 1
        changed_wire = c2(changed)
        try:
            coordinator.client.ensure_execution(request, changed_wire)
            raise AssertionError("changed source replay accepted")
        except ScopedHTTPRejected as exc:
            assert exc.status == 409
    finally:
        stop(child, output)
    _, provider = service(path)
    after = provider.query_current_issue("GRANT", operation_id)
    rows = issue_rows(path, operation_id, "GRANT")
    assert before == after
    assert [seq for seq, _ in rows] == [1]
    return {
        "operation_id": operation_id,
        "changed_source_rejected": True,
        "original_grant_unchanged": True,
        "issue_rows": len(rows),
        "signed_object_sha256": hashlib.sha256(before).hexdigest(),
    }


def worker_issue(config_path, request_path, source_path, folder, name, mutate_source):
    folder = Path(folder)
    request_wire = Path(request_path).read_bytes()
    source_wire = Path(source_path).read_bytes()
    if mutate_source == "changed-source":
        value = decode(source_wire)
        value["session_expires_at"] += 1
        source_wire = c2(value)
    (folder / f"ready-{name}").write_text("ready", encoding="ascii")
    while not (folder / "release").exists():
        time.sleep(.01)
    _, provider = service(config_path)
    try:
        issued = provider.ensure_execution(request_wire, source_wire,
            runtime_principal=config(config_path)["runtime_principal"])
        (folder / f"result-{name}").write_text(json.dumps({
            "status": "issued",
            "sha256": hashlib.sha256(issued.object_wire).hexdigest(),
            "sequence": issued.authority_sequence,
        }), encoding="ascii")
    except Exception as exc:
        (folder / f"result-{name}").write_text(json.dumps({
            "status": "rejected",
            "error": type(exc).__name__,
        }), encoding="ascii")


def wait_file(path, process, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise RuntimeError("worker exited before barrier: " + str(process.returncode))
        time.sleep(.02)
    raise RuntimeError("barrier timeout: " + str(path))


def concurrent_same_and_changed(config_path):
    path = Path(config_path).resolve()
    folder = path.parent / ("targeted-concurrent-source-" + str(time.time_ns()))
    folder.mkdir(exist_ok=False)
    coordinator = core(path)
    request_wire, source_wire = request_for(path, coordinator, "COMMIT", "targeted-concurrent")
    operation_id = decode(request_wire)["intent"]["operation_id"]
    request_path = folder / "request.wire"
    source_path = folder / "source.wire"
    request_path.write_bytes(request_wire)
    source_path.write_bytes(source_wire)
    python = sys.executable
    workers = [
        subprocess.Popen([python, "-B", "-m", "tests.r1_durable_targeted_rework",
            "issue-worker", str(path), str(request_path), str(source_path), str(folder), "original", "original"]),
        subprocess.Popen([python, "-B", "-m", "tests.r1_durable_targeted_rework",
            "issue-worker", str(path), str(request_path), str(source_path), str(folder), "changed", "changed-source"]),
    ]
    wait_file(folder / "ready-original", workers[0])
    wait_file(folder / "ready-changed", workers[1])
    (folder / "release").write_text("release", encoding="ascii")
    for process in workers:
        process.wait(timeout=30)
        if process.returncode:
            raise RuntimeError("issue worker failed: " + str(process.returncode))
    results = {name: json.loads((folder / f"result-{name}").read_text(encoding="ascii"))
               for name in ("original", "changed")}
    rows = issue_rows(path, operation_id, "GRANT")
    assert results["original"]["status"] == "issued", results
    assert results["changed"] == {"status": "rejected", "error": "ContractError"}, results
    assert [seq for seq, _ in rows] == [1]
    return {
        "operation_id": operation_id,
        "worker_results": results,
        "issue_rows": len(rows),
        "single_original_grant": True,
    }


def run(config_path):
    return {
        "response_loss_expiry_replay": response_loss_expiry_replay(config_path),
        "permit_rejection_has_no_side_effect": permit_rejection_has_no_side_effect(config_path),
        "source_replay_conflict": source_replay_conflict(config_path),
        "concurrent_same_and_changed": concurrent_same_and_changed(config_path),
    }


def negative_crash_smoke(config_path):
    path = Path(config_path).resolve()
    coordinator = core(path, create=not (path.parent / "finish.sqlite").exists())
    request, source = request_for(path, coordinator, "COMMIT", "targeted-negative-smoke")
    before = authority_event_count(path)

    cfg = config(path)
    bad_client = DurableAuthorityClient(trust=trust(cfg), ca_file=str(path.parent / "ca.pem"),
        credential_provider=DurableCredential("x" * 64), timeout_seconds=30)
    child, output = start_server(path)
    try:
        try:
            bad_client.ensure_execution(request, source)
            raise AssertionError("wrong credential accepted")
        except ScopedHTTPRejected as exc:
            assert exc.status == 409
    finally:
        stop(child, output)
    after_wrong_credential = authority_event_count(path)

    changed = decode(request)
    changed["intent"]["scope"]["authority_generation"] += 1
    changed_wire = c2(changed)
    child, output = start_server(path)
    try:
        try:
            coordinator.client.ensure_execution(changed_wire, source)
            raise AssertionError("wrong generation accepted")
        except ScopedHTTPRejected as exc:
            assert exc.status == 409
    finally:
        stop(child, output)
    after_wrong_generation = authority_event_count(path)

    operation_id = coordinator.persist_intent(request, source)
    child, output = start_server(path, "before_grant_append")
    try:
        try:
            coordinator.recover(operation_id)
            raise AssertionError("expected precommit crash")
        except ScopedTransportUncertain:
            pass
        child.wait(timeout=15)
    finally:
        stop(child, output)
    after_precommit_crash = authority_event_count(path)
    grant_exists_after_crash = True
    _, provider = service(path)
    try:
        provider.query_current_issue("GRANT", operation_id)
    except ContractError:
        grant_exists_after_crash = False

    child, output = start_server(path)
    try:
        coordinator.recover(operation_id)
    finally:
        stop(child, output)
    after_retry = authority_event_count(path)
    grant_rows = issue_rows(path, operation_id, "GRANT")
    assert before == after_wrong_credential == after_wrong_generation == after_precommit_crash
    assert grant_exists_after_crash is False
    assert [seq for seq, _ in grant_rows] == [1]
    return {
        "wrong_credential_rejected": True,
        "wrong_generation_rejected": True,
        "events_before": before,
        "events_after_wrong_credential": after_wrong_credential,
        "events_after_wrong_generation": after_wrong_generation,
        "events_after_precommit_crash": after_precommit_crash,
        "grant_exists_after_precommit_crash": grant_exists_after_crash,
        "events_after_retry": after_retry,
        "grant_rows_after_retry": len(grant_rows),
    }


if __name__ == "__main__":
    if sys.argv[1] == "issue-worker":
        worker_issue(*sys.argv[2:])
    elif sys.argv[1] == "negative-crash-smoke":
        print(json.dumps(negative_crash_smoke(sys.argv[2]), indent=2, sort_keys=True))
    else:
        print(json.dumps(run(sys.argv[1]), indent=2, sort_keys=True))
