from __future__ import annotations

import json
import secrets
import shutil
import socket
import subprocess
import time
import uuid
from copy import deepcopy
from pathlib import Path

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.control_plane.authority import InMemoryControlPlane
from app.db import Base
from app.errors import CoreError
from app.foundation_rehearsal import (
    REHEARSAL_ENVIRONMENT,
    REHEARSAL_OWNER_PREFIX,
    RehearsalTarget,
    assert_rehearsal_genesis_request,
    assert_rehearsal_isolation,
    backup_metadata,
    build_restore_request,
    canonical_read_model,
    rehearsal_identity_summary,
    verify_backup_metadata,
)
from app.models import CoreMetadata
from app.schemas import GenesisRequest, MutationRequest
from app.services import CoreFoundationService

IMAGE = "postgres@sha256:f1c3376c26f2609ab9f29f71f824103fe2fcd8ee0346485cb6122a4f93df6f94"
ROOT = Path(__file__).resolve().parents[1]


def docker(*args: str) -> str:
    return subprocess.check_output(["docker", *args], stderr=subprocess.STDOUT, text=True).strip()


class FoundationPostgresEnvironment:
    def __init__(self, tmp_path: Path):
        self.owner = REHEARSAL_OWNER_PREFIX + secrets.token_hex(6)
        self.folder = tmp_path / self.owner
        self.folder.mkdir()
        self.label = "qingyu.foundation.owner=" + self.owner
        self.network = self.owner + "-net"
        self.volume = self.owner + "-data"
        self.container = self.owner + "-pg"
        self.password = secrets.token_urlsafe(32)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.created = False

    def create(self):
        docker("image", "inspect", IMAGE)
        docker("network", "create", "--label", self.label, self.network)
        docker("volume", "create", "--label", self.label, self.volume)
        env = self.folder / "postgres.env"
        env.write_text("POSTGRES_PASSWORD=" + self.password + "\nPOSTGRES_DB=foundation_source\n", encoding="ascii")
        docker("run", "--detach", "--name", self.container, "--label", self.label, "--network", self.network,
               "--mount", "type=volume,source=" + self.volume + ",target=/var/lib/postgresql/data",
               "--publish", "127.0.0.1:" + str(self.port) + ":5432", "--env-file", str(env), IMAGE)
        self.created = True
        inspected = json.loads(docker("inspect", self.container))[0]
        assert inspected["Config"]["Labels"]["qingyu.foundation.owner"] == self.owner
        assert inspected["NetworkSettings"]["Ports"]["5432/tcp"] == [{"HostIp": "127.0.0.1", "HostPort": str(self.port)}]
        for _ in range(80):
            try:
                import psycopg
                with psycopg.connect(host="127.0.0.1", port=self.port, dbname="foundation_source", user="postgres", password=self.password, connect_timeout=2) as connection:
                    assert int(connection.execute("SHOW server_version_num").fetchone()[0]) // 10000 == 16
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise RuntimeError("isolated PostgreSQL unavailable")
        assert_rehearsal_isolation(self.target("foundation_source"))
        self.create_database("foundation_restore")
        return self

    def target(self, database: str) -> RehearsalTarget:
        return RehearsalTarget(owner=self.owner, host="127.0.0.1", port=self.port, database=database,
                               container=self.container, network=self.network, volume=self.volume)

    def url(self, database: str) -> str:
        return f"postgresql+psycopg://postgres:{self.password}@127.0.0.1:{self.port}/{database}"

    def create_database(self, name: str) -> None:
        import psycopg
        with psycopg.connect(host="127.0.0.1", port=self.port, dbname="postgres", user="postgres", password=self.password, autocommit=True) as connection:
            connection.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
            connection.execute(f'CREATE DATABASE "{name}"')

    def service(self, database: str, authority: InMemoryControlPlane) -> tuple[CoreFoundationService, sessionmaker]:
        engine = create_engine(self.url(database), pool_pre_ping=True)
        Base.metadata.create_all(engine)
        factory = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
        with factory.begin() as session:
            if session.get(CoreMetadata, 1) is None:
                session.add(CoreMetadata(id=1, status="UNINITIALIZED"))
        return CoreFoundationService(factory, authority), factory

    def dump(self, database: str, destination: Path) -> None:
        with destination.open("wb") as output:
            subprocess.check_call(["docker", "exec", "-e", "PGPASSWORD=" + self.password, self.container,
                                   "pg_dump", "-U", "postgres", "-d", database, "--format=plain", "--no-owner", "--no-privileges"], stdout=output)

    def restore(self, database: str, dump_path: Path) -> None:
        self.create_database(database)
        with dump_path.open("rb") as source:
            subprocess.check_call(["docker", "exec", "-i", "-e", "PGPASSWORD=" + self.password, self.container,
                                   "psql", "-U", "postgres", "-d", database, "-v", "ON_ERROR_STOP=1"], stdin=source)

    def destroy(self):
        if not self.created:
            return
        for command in (("rm", "-f", self.container), ("volume", "rm", "-f", self.volume), ("network", "rm", self.network)):
            subprocess.run(["docker", *command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.created = False


def genesis_request() -> GenesisRequest:
    return GenesisRequest(
        trust_domain_id=uuid.uuid4(),
        qingyu_identity_id=uuid.uuid4(),
        continuity_id=uuid.uuid4(),
        continuity_alias="qingyu-b1-foundation-candidate",
        genesis_request_id="b1-foundation-rehearsal-genesis",
        genesis_nonce="candidate-rehearsal-nonce-0001",
        initial_owner_fingerprint="candidate-owner-fingerprint-0001",
        actor_principal_id="candidate-owner",
        governance_provenance={
            "environment": REHEARSAL_ENVIRONMENT,
            "production_activated": False,
            "requires_b2_activation": True,
            "production_activation_artifact": False,
        },
    )


def mutation_request(request: GenesisRequest, lease: uuid.UUID, mutation_id: str = "foundation-mutation-1", *, epoch: int = 0) -> MutationRequest:
    return MutationRequest(
        continuity_id=request.continuity_id,
        continuity_epoch=epoch,
        lease_id=lease,
        mutation_id=mutation_id,
        actor_principal_id="candidate-owner",
        capability="core_governance",
        payload={"kind": "foundation-closure-rehearsal", "ordinal": 1},
    )


@pytest.mark.integration
def test_phase_b1_foundation_candidate_rehearsal_end_to_end(tmp_path):
    env = FoundationPostgresEnvironment(tmp_path).create()
    try:
        authority = InMemoryControlPlane()
        source, _source_factory = env.service("foundation_source", authority)
        request = genesis_request()
        assert_rehearsal_genesis_request(request)

        genesis = source.bootstrap_genesis(request)
        read_v0 = source.core_read_model()
        identity = rehearsal_identity_summary(request, read_v0)
        assert genesis.status == "COMMITTED"
        assert read_v0.generation["state_version"] == 0
        assert identity["production_activated"] is False
        assert identity["requires_future_b2_owner_activation"] is True

        restarted_after_genesis, _ = env.service("foundation_source", authority)
        assert restarted_after_genesis.core_read_model().model_dump(mode="json") == read_v0.model_dump(mode="json")

        lease = restarted_after_genesis.acquire_owner_lease(request.continuity_id)
        mutation = mutation_request(request, lease)
        result = restarted_after_genesis.governed_mutation(mutation)
        read_v1 = restarted_after_genesis.core_read_model()
        assert result.status == "COMMITTED"
        assert result.state_version == 1
        assert read_v1.generation["state_version"] == 1
        assert read_v1.read_model_hash != read_v0.read_model_hash

        replay = restarted_after_genesis.governed_mutation(mutation)
        assert replay.local_commit_id == result.local_commit_id
        bad = mutation.model_copy(update={"payload": {"kind": "changed"}})
        with pytest.raises(CoreError, match="MUTATION_RETRY_CONFLICT|MUTATION_RETRY_CONTEXT_CONFLICT"):
            restarted_after_genesis.governed_mutation(bad)
        assert restarted_after_genesis.core_read_model().read_model_hash == read_v1.read_model_hash

        restarted_after_mutation, _ = env.service("foundation_source", authority)
        assert restarted_after_mutation.core_read_model().model_dump(mode="json") == read_v1.model_dump(mode="json")

        dump_path = tmp_path / "foundation_source.sql"
        env.dump("foundation_source", dump_path)
        trust_anchor = authority.export_checkpoint(request.continuity_id)
        metadata = backup_metadata(backup_path=dump_path, source_read_model=read_v1, trust_anchor=trust_anchor)
        verify_backup_metadata(metadata, backup_path=dump_path, expected_read_model=read_v1, expected_trust_anchor=trust_anchor)

        env.restore("foundation_restore", dump_path)
        restored, _ = env.service("foundation_restore", authority)
        restored_read_before_quarantine = restored.core_read_model()
        assert restored_read_before_quarantine.model_dump(mode="json") == read_v1.model_dump(mode="json")

        restore_request = build_restore_request(
            request_id="foundation-restore-1",
            read_model=read_v1,
            target_storage_generation_id=uuid.uuid4(),
        )
        verification = restored.verify_restore(restore_request)
        assert verification.same_identity is True
        assert verification.read_only is True
        assert verification.reason == "RESTORE_QUARANTINED_UNTIL_AUTHORITY_ACTIVATION"
        with pytest.raises(CoreError, match="RESTORE_FENCE_UNPROVEN"):
            restored.acquire_owner_lease(request.continuity_id)

        activated = restored.activate_restore(restore_request)
        assert activated.same_identity is True
        assert activated.read_only is False
        restored_read_after_activation = restored.core_read_model()
        assert restored_read_after_activation.identity_reference == read_v1.identity_reference
        assert restored_read_after_activation.generation["state_version"] == 2
        assert restored_read_after_activation.governed_state["recovery_state"] == "ACTIVE"

        restore_lease = restored.acquire_owner_lease(request.continuity_id)
        followup = restored.governed_mutation(mutation_request(request, restore_lease, "foundation-mutation-after-restore", epoch=restored_read_after_activation.generation["continuity_epoch"]))
        assert followup.status == "COMMITTED"
        assert restored.core_read_model().generation["state_version"] == 3
    finally:
        env.destroy()


@pytest.mark.integration
def test_phase_b1_foundation_restore_negatives_fail_closed(tmp_path):
    env = FoundationPostgresEnvironment(tmp_path).create()
    try:
        authority = InMemoryControlPlane()
        source, _ = env.service("foundation_source", authority)
        request = genesis_request()
        source.bootstrap_genesis(request)
        lease = source.acquire_owner_lease(request.continuity_id)
        source.governed_mutation(mutation_request(request, lease))
        read_v1 = source.core_read_model()
        dump_path = tmp_path / "foundation_source.sql"
        env.dump("foundation_source", dump_path)
        trust_anchor = authority.export_checkpoint(request.continuity_id)
        metadata = backup_metadata(backup_path=dump_path, source_read_model=read_v1, trust_anchor=trust_anchor)

        wrong_identity = build_restore_request(request_id="wrong-identity", read_model=read_v1, target_storage_generation_id=uuid.uuid4())
        wrong_identity = wrong_identity.model_copy(update={"manifest": wrong_identity.manifest.model_copy(update={"qingyu_identity_id": uuid.uuid4()})})
        with pytest.raises(CoreError, match="RESTORE_IDENTITY_MISMATCH"):
            source.verify_restore(wrong_identity)

        wrong_generation = build_restore_request(request_id="wrong-generation", read_model=read_v1, target_storage_generation_id=uuid.uuid4())
        wrong_generation = wrong_generation.model_copy(update={"manifest": wrong_generation.manifest.model_copy(update={"storage_generation_id": uuid.uuid4()})})
        with pytest.raises(CoreError, match="RESTORE_STATE_GAP"):
            source.verify_restore(wrong_generation)

        wrong_trust = deepcopy(metadata)
        wrong_trust["trust_anchor"] = {**trust_anchor, "audit_head_hash": "0" * 64}
        with pytest.raises(CoreError, match="FOUNDATION_BACKUP_TRUST_ANCHOR_MISMATCH"):
            verify_backup_metadata(wrong_trust, backup_path=dump_path, expected_read_model=read_v1, expected_trust_anchor=trust_anchor)

        incomplete = {"schema_version": "qingyu-foundation-rehearsal-backup-v1"}
        with pytest.raises(CoreError, match="FOUNDATION_BACKUP_METADATA_INCOMPLETE"):
            verify_backup_metadata(incomplete, backup_path=dump_path, expected_read_model=read_v1, expected_trust_anchor=trust_anchor)

        corrupt = deepcopy(metadata)
        corrupt["backup_sha256"] = "0" * 64
        with pytest.raises(CoreError, match="FOUNDATION_BACKUP_DIGEST_MISMATCH"):
            verify_backup_metadata(corrupt, backup_path=dump_path, expected_read_model=read_v1, expected_trust_anchor=trust_anchor)

        wrong_hash = deepcopy(metadata)
        wrong_hash["read_model_hash"] = "0" * 64
        with pytest.raises(CoreError, match="FOUNDATION_BACKUP_STATE_HASH_MISMATCH"):
            verify_backup_metadata(wrong_hash, backup_path=dump_path, expected_read_model=read_v1, expected_trust_anchor=trust_anchor)

        prod_target = RehearsalTarget(owner="production", host="127.0.0.1", port=5432, database="prod", container="prod", network="prod", volume="prod")
        with pytest.raises(CoreError, match="FOUNDATION_REHEARSAL_OWNER_REQUIRED|FOUNDATION_REHEARSAL_PRODUCTION_MARKER_FORBIDDEN"):
            assert_rehearsal_isolation(prod_target)
    finally:
        env.destroy()
