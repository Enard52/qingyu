"""Acceptance tests for the durable PostgreSQL control-plane adapter.

These tests are deliberately opt-in.  A run is considered a real acceptance
run only when CONTROL_PLANE_DATABASE_URL names a freshly migrated control-plane
database.  They never infer safety from a database name and refuse the known
Gateway/Core databases before opening a write-capable connection.
"""

from __future__ import annotations

import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from inspect import signature

import pytest
from sqlalchemy import create_engine, text

from app.canonical import sha256_hex
from app.config import FORBIDDEN_DATABASE_NAMES
from app.errors import CoreError


def _database_url() -> str:
    value = os.environ.get("CONTROL_PLANE_DATABASE_URL")
    if not value:
        pytest.skip("set CONTROL_PLANE_DATABASE_URL for PostgreSQL acceptance")
    lowered = value.rsplit("/", 1)[-1].split("?", 1)[0].lower()
    if lowered in FORBIDDEN_DATABASE_NAMES or lowered in {"qingyu_core_test", "qingyu_core_acceptance"}:
        pytest.fail("CONTROL_PLANE_DATABASE_URL points at a protected Core/Gateway database")
    return value


@pytest.fixture(scope="module")
def control_plane():
    url = _database_url()
    try:
        from app.control_plane.authority import PostgresControlPlane
    except ImportError:
        pytest.fail("PostgresControlPlane is required for the Commit 1B acceptance run")

    # Keep this compatibility shim small: the public adapter may accept a URL,
    # SQLAlchemy Engine, or a keyword named after either.  Core governance code
    # remains backend-neutral.
    candidates = {
        "database_url": url,
        "control_plane_database_url": url,
        "url": url,
        "engine": create_engine(url, pool_pre_ping=True),
    }
    params = signature(PostgresControlPlane).parameters
    kwargs = {name: value for name, value in candidates.items() if name in params}
    try:
        authority = PostgresControlPlane(**kwargs)
    except TypeError:
        authority = PostgresControlPlane(url)
    yield authority
    dispose = getattr(authority, "close", None) or getattr(authority, "dispose", None)
    if dispose:
        dispose()


def _domain_ids():
    return uuid.uuid4(), uuid.uuid4(), uuid.uuid4(), uuid.uuid4()


def _enroll(authority):
    trust_domain_id, identity_id, continuity_id, storage_generation_id = _domain_ids()
    control_generation_id = uuid.uuid4()
    request_id = f"acceptance-genesis-{uuid.uuid4()}"
    manifest_hash = sha256_hex({"trust_domain_id": str(trust_domain_id), "identity_id": str(identity_id)})
    authority.prepare_genesis(
        trust_domain_id=trust_domain_id, manifest_hash=manifest_hash, request_id=request_id
    )
    authority.claim_genesis_storage(
        trust_domain_id=trust_domain_id,
        request_id=request_id,
        storage_generation_id=storage_generation_id,
    )
    authority.initialize_domain(
        trust_domain_id=trust_domain_id,
        identity_id=identity_id,
        continuity_id=continuity_id,
        storage_generation_id=storage_generation_id,
        control_plane_generation_id=control_generation_id,
        owner_principal_id="acceptance-owner",
        owner_key_fingerprint="acceptance-owner-key",
    )
    authority.record_genesis_core_commit(
        trust_domain_id=trust_domain_id,
        request_id=request_id,
        storage_generation_id=storage_generation_id,
        local_commit_id=f"core-{uuid.uuid4()}",
    )
    authority.publish_genesis_anchor(
        trust_domain_id=trust_domain_id,
        request_id=request_id,
        storage_generation_id=storage_generation_id,
        anchor_hash=manifest_hash,
    )
    authority.complete_genesis(
        trust_domain_id=trust_domain_id,
        request_id=request_id,
        storage_generation_id=storage_generation_id,
    )
    return trust_domain_id, identity_id, continuity_id, storage_generation_id


def test_control_database_is_separate_and_migrated(control_plane):
    url = _database_url()
    engine = create_engine(url, pool_pre_ping=True)
    with engine.connect() as connection:
        db_name = connection.execute(text("SELECT current_database()")).scalar_one()
        assert db_name.lower() not in FORBIDDEN_DATABASE_NAMES
        assert db_name.lower() not in {"qingyu_core_test", "qingyu_core_acceptance"}
        tables = {
            row[0]
            for row in connection.execute(
                text("SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname = 'public'")
            )
        }
    assert "alembic_version" in tables
    assert not tables.intersection({"identity_registry", "continuity_registry", "audit_ledger"})
    engine.dispose()


def test_enrollment_and_restart_persist_authority(control_plane):
    trust_domain_id, identity_id, continuity_id, storage_generation_id = _enroll(control_plane)
    checkpoint_before = control_plane.export_checkpoint(continuity_id)
    if "identity_id" in checkpoint_before:
        assert checkpoint_before["identity_id"] == str(identity_id)

    url = _database_url()
    from app.control_plane.authority import PostgresControlPlane

    params = signature(PostgresControlPlane).parameters
    kwargs = {key: url for key in ("database_url", "control_plane_database_url", "url") if key in params}
    restarted = PostgresControlPlane(**kwargs) if kwargs else PostgresControlPlane(url)
    checkpoint_after = restarted.export_checkpoint(continuity_id)
    assert checkpoint_after["continuity_id"] == str(continuity_id)
    assert checkpoint_after["storage_generation_id"] == str(storage_generation_id)
    assert checkpoint_after["epoch"] == checkpoint_before["epoch"]
    if hasattr(restarted, "close"):
        restarted.close()


def test_concurrent_recovery_has_at_most_one_winner(control_plane):
    trust_domain_id, _, continuity_id, storage_generation_id = _enroll(control_plane)
    owner_hash = sha256_hex(
        {
            "owner_version": 0,
            "owner_principal_id": "acceptance-owner",
            "owner_key_fingerprint": "acceptance-owner-key",
        }
    )
    barrier = threading.Barrier(2)

    def claim(suffix):
        barrier.wait()
        try:
            return control_plane.claim_recovery(
                request_id=f"clone-{suffix}-{uuid.uuid4()}",
                trust_domain_id=trust_domain_id,
                continuity_id=continuity_id,
                current_owner_principal_id="acceptance-owner",
                current_owner_record_hash=owner_hash,
                target_storage_generation_id=uuid.uuid4(),
                restore_manifest_hash=f"manifest-{suffix}",
            )
        except CoreError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(claim, ("a", "b")))
    assert len(outcomes) == 2
    # The database CAS must reject a second operation for the same continuity.
    # Depending on the adapter, the loser is surfaced by raising CoreError or
    # represented as an explicit non-prepared result; never two PREPARED claims.
    statuses = [item.get("status") for item in outcomes if isinstance(item, dict)]
    assert statuses.count("RECOVERY_PREPARED") <= 1
    assert sum(isinstance(item, dict) for item in outcomes) <= 1


def test_production_backend_never_silently_uses_memory(monkeypatch):
    from app.config import Settings

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setenv("CORE_CONTROL_PLANE_BACKEND", "memory")
    with pytest.raises(Exception):
        Settings()
