from __future__ import annotations

import ast
import builtins
from pathlib import Path

import pytest

from app.canonical import sha256_hex
from app.errors import CoreError
from app.schemas import MutationRequest
from app.value_poc import (
    GatewayEvidence,
    InMemoryDerivedStateStore,
    ReadOnlyMemoryAdapter,
    ValuePocReadChain,
    project_context,
    project_hermes,
    reject_direct_core_database_uri,
    reject_direct_gateway_database_uri,
)


class StaticCoreReader:
    def __init__(self, read_model):
        self.read_model = read_model

    def read(self):
        return self.read_model


class StaticGatewayReader:
    def __init__(self, evidence):
        self.evidence = evidence

    def read_value_evidence(self, *, limit: int = 1):
        assert limit == 1
        return self.evidence


def _evidence(read_model, *, assertion_kind="DERIVED", continuity_id=None, state_version=None):
    return GatewayEvidence(
        evidence_id="gateway-real-chain-1",
        evidence_hash=sha256_hex({"gateway": "formal-api", "state": read_model.generation["state_version"]}),
        core_read_model_hash=read_model.read_model_hash,
        core_state_version=read_model.generation["state_version"] if state_version is None else state_version,
        continuity_id=read_model.identity_reference["continuity_id"] if continuity_id is None else continuity_id,
        source_epistemic_status="USER_STATED",
        source_reference={"api": "/api/v1/evidence/conversation-observations", "item": "gateway-real-chain-1"},
        facts=[{"assertion_kind": assertion_kind, "domain": "preference", "value": "quiet workspace"}],
    )


def _mutation(genesis_request, lease, name):
    return MutationRequest(
        continuity_id=genesis_request.continuity_id,
        continuity_epoch=0,
        lease_id=lease,
        mutation_id=name,
        actor_principal_id="owner-1",
        capability="core_writer",
        payload={"kind": "value-chain-test", "name": name},
    )


def test_real_read_chain_delete_rebuild_is_logically_deterministic(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    store = InMemoryDerivedStateStore()
    chain = ValuePocReadChain(core=StaticCoreReader(read_model), gateway=StaticGatewayReader(_evidence(read_model)), store=store)

    first = chain.run()
    first_hash = first.canonical_hash
    assert store.memory_records and store.context and store.hermes

    chain.delete_derived_state()
    assert store.memory_records == [] and store.context is None and store.hermes is None

    rebuilt = chain.run()

    assert rebuilt.canonical_hash == first_hash
    assert rebuilt.context.canonical_hash == first.context.canonical_hash
    assert rebuilt.hermes.canonical_hash == first.hermes.canonical_hash
    assert rebuilt.runtime_metadata == first.runtime_metadata
    assert rebuilt.memory_records[0].assertion_kind == "DERIVED"
    assert rebuilt.memory_records[0].source_epistemic_status == "USER_STATED"
    assert rebuilt.hermes.identity_authority == "core_read_model"


def test_state_version_n_and_n_plus_one_and_stale_state_behavior(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    n = service.core_read_model()
    first = ValuePocReadChain(core=StaticCoreReader(n), gateway=StaticGatewayReader(_evidence(n))).run()
    assert first.context.core_state_version == 0

    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    service.governed_mutation(_mutation(genesis_request, lease, "value-chain-n-plus-one"))
    n1 = service.core_read_model()
    second = ValuePocReadChain(core=StaticCoreReader(n1), gateway=StaticGatewayReader(_evidence(n1))).run()

    assert n1.generation["state_version"] == n.generation["state_version"] + 1
    assert second.context.core_state_version == first.context.core_state_version + 1
    assert first.context.core_state_version == 0
    assert first.canonical_hash != second.canonical_hash

    with pytest.raises(CoreError, match="VALUE_POC_PROVENANCE_MISMATCH"):
        ValuePocReadChain(core=StaticCoreReader(n1), gateway=StaticGatewayReader(_evidence(n))).run()
    with pytest.raises(CoreError, match="VALUE_POC_CORE_STATE_VERSION_MISMATCH"):
        ValuePocReadChain(core=StaticCoreReader(n1), gateway=StaticGatewayReader(_evidence(n1, state_version=0))).run()
    with pytest.raises(CoreError, match="VALUE_POC_CONTINUITY_MISMATCH"):
        ValuePocReadChain(core=StaticCoreReader(n1), gateway=StaticGatewayReader(_evidence(n1, continuity_id="wrong"))).run()


def test_value_chain_rejects_user_stated_derived_record_and_direct_databases(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()

    with pytest.raises(CoreError, match="VALUE_POC_USER_STATED_REQUIRES_EXPLICIT_USER_SOURCE"):
        ValuePocReadChain(core=StaticCoreReader(read_model), gateway=StaticGatewayReader(_evidence(read_model, assertion_kind="USER_STATED"))).run()
    with pytest.raises(CoreError, match="VALUE_POC_DIRECT_CORE_DB_FORBIDDEN"):
        reject_direct_core_database_uri("postgresql://core")
    with pytest.raises(CoreError, match="VALUE_POC_DIRECT_GATEWAY_DB_FORBIDDEN"):
        reject_direct_gateway_database_uri("postgresql://gateway")


def test_context_and_hermes_reject_stale_or_unproven_inputs(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    records = ReadOnlyMemoryAdapter().derive(read_model, _evidence(read_model))
    bad = records[0].model_copy(update={"provenance": []})
    with pytest.raises(CoreError, match="VALUE_POC_MEMORY_PROVENANCE_REQUIRED"):
        project_context([bad])
    context = project_context(records)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    service.governed_mutation(_mutation(genesis_request, lease, "stale-hermes"))
    with pytest.raises(CoreError, match="VALUE_POC_HERMES_STATE_VERSION_MISMATCH"):
        project_hermes(context, service.core_read_model())


def test_value_chain_runtime_does_not_depend_on_current_scope(monkeypatch, foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    real_open = builtins.open

    def guarded_open(file, *args, **kwargs):
        text = str(file)
        if text.endswith("current-scope.json") or text.endswith("CURRENT_SCOPE.md"):
            raise AssertionError("CURRENT_SCOPE is not a runtime authority source")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)
    result = ValuePocReadChain(core=StaticCoreReader(read_model), gateway=StaticGatewayReader(_evidence(read_model))).run()

    assert result.hermes.content["continuity_id"] == read_model.identity_reference["continuity_id"]


def test_value_poc_architecture_boundary_has_no_direct_db_or_sql_execution():
    tree = ast.parse(Path("app/value_poc.py").read_text(encoding="utf-8"))
    forbidden_import_roots = {"sqlalchemy", "psycopg", "sqlite3", "app.db", "app.models"}
    forbidden_names = {"DATABASE_URL", "CORE_DATABASE_URL", "GATEWAY_DATABASE_URL"}
    forbidden_calls = {"execute", "executemany", "executescript"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name not in forbidden_import_roots for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden_import_roots
        elif isinstance(node, ast.Name):
            assert node.id not in forbidden_names
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            assert node.value not in forbidden_names
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in forbidden_calls
