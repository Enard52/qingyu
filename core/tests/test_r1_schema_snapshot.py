"""Migration-owned authored-DDL pin tests; no database or migration execution."""

from hashlib import sha256
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import String, text

from app.control_plane import r1_schema, r1_schema_snapshot as snapshot
from app.control_plane.r1_provisioning import VerifiedOrigin


REVISION_PATH = (Path(__file__).parents[1] / "control_plane_alembic" / "versions"
                 / "0001_control_plane_r1_initial.py")


def _revision():
    spec = spec_from_file_location("r1_initial_snapshot_test", REVISION_PATH)
    assert spec is not None and spec.loader is not None
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_snapshot_pins_all_authored_table_and_index_ddl() -> None:
    manifest = snapshot.schema_ddl_manifest()
    assert snapshot.verify_schema_snapshot() == (
        "c2176cd47c65f7143b38f651218bcf3cbe238da27c7f74ec8fff88171e4c9aef")
    assert manifest["version"] == 1
    assert manifest["scope"] == "authored_initial_ddl_not_catalog_attestation"
    assert len(manifest["table_sql"]) == 6
    assert len(manifest["index_sql"]) == 7
    ddl = "\n".join(manifest["table_sql"] + manifest["index_sql"])
    for table in ("cp_origin", "cp_receipt_keys", "cp_generations",
                  "cp_runtime_sessions", "cp_continuities", "cp_operations"):
        assert f"CREATE TABLE control_plane.{table}" in ddl
    assert "ck_cp_operations_terminal_shape" in ddl
    assert "fk_cp_continuities_runtime_session" in ddl
    assert "ux_cp_operations_one_unresolved" in ddl
    assert "WHERE state = 'PREPARED'" in ddl
    assert manifest["prefix_sql"] == list(snapshot.DDL_PREFIX)
    assert manifest["suffix_sql"] == list(snapshot.DDL_SUFFIX)


def test_live_application_metadata_drift_cannot_rewrite_history(monkeypatch) -> None:
    assert snapshot.R1_METADATA is not r1_schema.R1_METADATA
    live_column = r1_schema.origin.c.operator_root_key_id
    monkeypatch.setattr(live_column, "type", String(65))
    assert snapshot.verify_schema_snapshot() == snapshot.EXPECTED_SNAPSHOT_SHA256


def test_signed_artifact_covers_exact_transitive_migration_sources() -> None:
    assert snapshot.INITIAL_MIGRATION_ARTIFACT_VERSION == 2
    assert snapshot.INITIAL_MIGRATION_ARTIFACT_SOURCES == (
        "control_plane_alembic.ini",
        "control_plane_alembic/env.py",
        "control_plane_alembic/versions/0001_control_plane_r1_initial.py",
        "app/control_plane/r1_schema_snapshot.py",
        "app/control_plane/r1_provisioning.py",
        "app/control_plane/r1_root_pin.py",
        "app/control_plane/r1_windows_acl.py",
        "app/control_plane/r1_protocol.py",
        "app/__init__.py",
        "app/control_plane/__init__.py",
        "app/control_plane/authority.py",
        "app/canonical.py",
        "app/errors.py",
        "pyproject.toml",
        "docs/CONTROL_PLANE_R1_OWNER_CONTRACT.md",
        "docs/CONTROL_PLANE_R1_SIGNED_INTENT_CONTRACT.md",
    )
    frame = lambda part: len(part).to_bytes(8, "big") + part
    wire = b"QINGYU-CP-R1-INITIAL-MIGRATION-ARTIFACT-V2\x00"
    wire += frame(b"0001_control_plane_r1_initial")
    for name in snapshot.INITIAL_MIGRATION_ARTIFACT_SOURCES:
        wire += frame(name.encode("utf-8"))
        wire += frame((Path(__file__).parents[1] / name).read_bytes())
    expected = sha256(wire).hexdigest()
    assert snapshot.initial_migration_artifact_sha256() == expected
    assert snapshot.verify_initial_migration_artifact(expected) == expected
    assert set(snapshot.INITIAL_MIGRATION_DEPENDENCY_SOURCES).issubset(
        snapshot.INITIAL_MIGRATION_ARTIFACT_SOURCES)
    assert set(snapshot.SCHEMA_CONTRACT_SOURCES).issubset(
        snapshot.INITIAL_MIGRATION_ARTIFACT_SOURCES)


@pytest.mark.parametrize("extra", [
    b"\nfrom app import config\n",
    b"\nimport importlib\nimportlib.import_module('app.config')\n",
    b"\nimport importlib as i\ni.import_module('app.config')\n",
    b"\nfrom importlib import import_module as load\nload('app.config')\n",
    b"\nfrom builtins import __import__ as load\nload('app.config')\n",
    b"\n__import__('app.config')\n",
])
def test_unlisted_or_dynamic_first_party_import_fails_closed(monkeypatch, extra) -> None:
    target = (Path(__file__).parents[1] / "app" / "control_plane" / "r1_provisioning.py").resolve()
    original_read_bytes = Path.read_bytes

    def changed_bytes(path):
        result = original_read_bytes(path)
        return result + extra if path.resolve() == target else result

    monkeypatch.setattr(Path, "read_bytes", changed_bytes)
    with pytest.raises(RuntimeError, match="unbound first-party migration import|dynamic module import"):
        snapshot.initial_migration_artifact_sha256()


def test_package_initializer_must_remain_in_artifact(monkeypatch) -> None:
    monkeypatch.setattr(snapshot, "INITIAL_MIGRATION_ARTIFACT_SOURCES", tuple(
        source for source in snapshot.INITIAL_MIGRATION_ARTIFACT_SOURCES
        if source != "app/control_plane/__init__.py"))
    with pytest.raises(RuntimeError, match="unbound first-party migration import"):
        snapshot.initial_migration_artifact_sha256()


@pytest.mark.parametrize("name", snapshot.INITIAL_MIGRATION_ARTIFACT_SOURCES)
def test_changed_executable_source_rejects_signed_artifact_before_sql(
        monkeypatch, name) -> None:
    revision = _revision()
    expected = snapshot.initial_migration_artifact_sha256()
    root = Path(__file__).parents[1].resolve()
    target = (root / name).resolve()
    original_read_bytes = Path.read_bytes

    def changed_bytes(path):
        result = original_read_bytes(path)
        return result + b"\n# tampered after signing\n" if path.resolve() == target else result

    monkeypatch.setattr(Path, "read_bytes", changed_bytes)
    signed = VerifiedOrigin(
        intent={"canonical_initial_revision": revision.revision,
                "authority_generation": 1,
                "roles": {"owner": "control_plane_owner",
                          "migrator": "control_plane_migrator"},
                "provisioning_uuid": "p", "authority_domain_id": "d",
                "authority_instance_id": "i", "database_name": "db",
                "initial_migration_artifact_digest": expected},
        completion={"authority_generation": 1, "provisioning_uuid": "p",
                    "authority_domain_id": "d", "authority_instance_id": "i",
                    "database_name": "db",
                    "initial_migration_artifact_digest": expected},
        signed_provisioning_origin_digest="a" * 64,
    )
    monkeypatch.setattr(revision.op, "get_context", lambda: SimpleNamespace(
        config=SimpleNamespace(attributes={"r1_verified_origin": signed})))
    monkeypatch.setattr(revision.op, "get_bind", lambda: pytest.fail("bind before pin check"))
    monkeypatch.setattr(revision.op, "execute", lambda *_: pytest.fail("SQL before pin check"))
    with pytest.raises(RuntimeError, match="signed initial migration artifact digest mismatch"):
        revision.upgrade()


@pytest.mark.parametrize("part", ["column", "constraint", "index", "role_sql"])
def test_frozen_snapshot_tampering_fails_before_migration_sql(monkeypatch, part) -> None:
    if part == "column":
        monkeypatch.setattr(snapshot.origin.c.operator_root_key_id, "type", String(65))
    elif part == "constraint":
        constraint = next(c for c in snapshot.origin.constraints
                          if c.name == "ck_cp_origin_generation")
        monkeypatch.setattr(constraint, "sqltext", text("initial_authority_generation = 2"))
    elif part == "index":
        index = next(i for i in snapshot.operations.indexes
                     if i.name == "ux_cp_operations_one_unresolved")
        monkeypatch.setitem(index.dialect_options["postgresql"], "where",
                            text("state = 'COMMITTED'"))
    else:
        monkeypatch.setattr(snapshot, "DDL_PREFIX", snapshot.DDL_PREFIX[:-1])
    with pytest.raises(RuntimeError, match="authored-DDL snapshot mismatch"):
        snapshot.verify_schema_snapshot()


def test_revision_checks_snapshot_before_any_bind_or_sql(monkeypatch) -> None:
    revision = _revision()
    assert revision.R1_METADATA is snapshot.R1_METADATA
    origin = VerifiedOrigin(
        intent={"canonical_initial_revision": revision.revision,
                "authority_generation": 1,
                "roles": {"owner": "control_plane_owner",
                          "migrator": "control_plane_migrator"},
                "provisioning_uuid": "p", "authority_domain_id": "d",
                "authority_instance_id": "i", "database_name": "db",
                "initial_migration_artifact_digest": snapshot.initial_migration_artifact_sha256()},
        completion={"authority_generation": 1, "provisioning_uuid": "p",
                    "authority_domain_id": "d", "authority_instance_id": "i",
                    "database_name": "db",
                    "initial_migration_artifact_digest": snapshot.initial_migration_artifact_sha256()},
        signed_provisioning_origin_digest="a" * 64,
    )
    monkeypatch.setattr(revision.op, "get_context", lambda: SimpleNamespace(
        config=SimpleNamespace(attributes={"r1_verified_origin": origin})))
    monkeypatch.setattr(revision, "verify_schema_snapshot", lambda: (_ for _ in ()).throw(
        RuntimeError("R1 initial migration authored-DDL snapshot mismatch")))
    monkeypatch.setattr(revision.op, "get_bind", lambda: pytest.fail("bind before pin check"))
    monkeypatch.setattr(revision.op, "execute", lambda *_: pytest.fail("SQL before pin check"))
    with pytest.raises(RuntimeError, match="authored-DDL snapshot mismatch"):
        revision.upgrade()


@pytest.mark.parametrize("bad_field", [
    "authored_ddl_snapshot_digest", "initial_migration_dependency_digest",
    "schema_contract_digest",
])
def test_revision_rejects_each_wrong_signed_digest_before_bind_or_sql(
        monkeypatch, bad_field) -> None:
    revision = _revision()
    digests = {
        "initial_migration_artifact_digest": snapshot.initial_migration_artifact_sha256(),
        "authored_ddl_snapshot_digest": snapshot.verify_schema_snapshot(),
        "initial_migration_dependency_digest": snapshot.initial_migration_dependency_sha256(),
        "schema_contract_digest": snapshot.schema_contract_sha256(),
    }
    digests[bad_field] = "f" * 64
    intent = {
        "canonical_initial_revision": revision.revision,
        "authority_generation": 1,
        "roles": {"owner": "control_plane_owner", "migrator": "control_plane_migrator"},
        "provisioning_uuid": "p", "authority_domain_id": "d",
        "authority_instance_id": "i", "database_name": "db",
        **digests,
    }
    completion = {
        key: intent[key] for key in (
            "provisioning_uuid", "authority_domain_id", "authority_instance_id",
            "database_name", "initial_migration_artifact_digest")
    }
    completion["authority_generation"] = 1
    origin = VerifiedOrigin(intent=intent, completion=completion,
                            signed_provisioning_origin_digest="a" * 64)
    monkeypatch.setattr(revision.op, "get_context", lambda: SimpleNamespace(
        config=SimpleNamespace(attributes={"r1_verified_origin": origin})))
    monkeypatch.setattr(revision.op, "get_bind", lambda: pytest.fail("bind before digest check"))
    monkeypatch.setattr(revision.op, "execute", lambda *_: pytest.fail("SQL before digest check"))
    with pytest.raises(RuntimeError, match="signed initial migration digest mismatch"):
        revision.upgrade()
