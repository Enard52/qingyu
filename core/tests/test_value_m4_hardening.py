from __future__ import annotations

import ast
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
    trace_value_chain,
)


class StaticCoreReader:
    def __init__(self, read_model):
        self.read_model = read_model

    def read(self):
        return self.read_model


class GatewaySetReader:
    def __init__(self, evidence_items):
        self.evidence_items = evidence_items

    def read_value_evidence(self, *, limit: int = 1):
        return self.evidence_items[0]

    def read_value_evidence_set(self, *, limit: int = 128):
        return list(self.evidence_items)[:limit]


def mutation(genesis_request, lease, name):
    return MutationRequest(
        continuity_id=genesis_request.continuity_id,
        continuity_epoch=0,
        lease_id=lease,
        mutation_id=name,
        actor_principal_id="owner-1",
        capability="core_writer",
        payload={"kind": "m4-hardening", "name": name},
    )


def evidence(read_model, evidence_id, facts):
    payload = {"id": evidence_id, "facts": facts, "state": read_model.generation["state_version"]}
    return GatewayEvidence(
        evidence_id=evidence_id,
        evidence_hash=sha256_hex(payload),
        core_read_model_hash=read_model.read_model_hash,
        core_state_version=read_model.generation["state_version"],
        continuity_id=read_model.identity_reference["continuity_id"],
        source_epistemic_status="USER_STATED",
        source_reference={"api": "/api/v1/evidence/conversation-observations", "id": evidence_id},
        facts=facts,
    )


def test_contract_document_covers_public_chain_layers():
    text = Path("docs/M4_READ_CHAIN_CONTRACT.md").read_text(encoding="utf-8")
    for term in ["CoreReadModel", "GatewayEvidence", "MemoryRecord", "ContextProjection", "HermesProfileProjection"]:
        assert term in text
    assert "not an authority source" in text


def test_memory_supports_derived_inferred_and_trace(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    first = evidence(read_model, "ev-a", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "quiet", "proposition": "prefers quiet"}])
    second = evidence(read_model, "ev-b", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "focus", "proposition": "prefers focus"}])

    result = ValuePocReadChain(core=StaticCoreReader(read_model), gateway=GatewaySetReader([second, first])).run()
    inferred = [record for record in result.memory_records if record.assertion_kind == "INFERRED"]

    assert inferred
    assert inferred[0].inference_rule == "multi-evidence-domain-corroboration-v1"
    assert inferred[0].confidence and inferred[0].confidence > 0
    trace = trace_value_chain(result)
    assert trace["hermes"]["identity_authority"] == "core_read_model"
    assert any(ref["source_type"] == "gateway_evidence" for item in trace["memory"].values() for ref in item["provenance"])
    assert trace["secret_values_omitted"] is True
    lowered = str(trace).lower()
    assert "password" not in lowered and "token" not in lowered and "private-config" not in lowered


def test_memory_identity_is_stable_and_changes_on_evidence_core_or_derivation(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    fact = {"assertion_kind": "DERIVED", "domain": "preference", "value": "quiet", "proposition": "prefers quiet"}
    ev = evidence(read_model, "ev-stable", [fact])
    adapter = ReadOnlyMemoryAdapter()

    one = adapter.derive(read_model, ev)[0]
    two = adapter.derive(read_model, ev)[0]
    changed_evidence = adapter.derive(read_model, evidence(read_model, "ev-changed", [{**fact, "value": "music", "proposition": "prefers music"}]))[0]
    changed_derivation = ReadOnlyMemoryAdapter(derivation_version="memory-derivation-v3").derive(read_model, ev)[0]
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    service.governed_mutation(mutation(genesis_request, lease, "m4-state-change"))
    read_model_n1 = service.core_read_model()
    changed_core = adapter.derive(read_model_n1, evidence(read_model_n1, "ev-stable", [fact]))[0]

    assert one.record_id == two.record_id
    assert one.memory_hash == two.memory_hash
    assert changed_evidence.memory_hash != one.memory_hash
    assert changed_derivation.derivation_version == "memory-derivation-v3"
    assert changed_derivation.memory_hash != one.memory_hash
    assert changed_core.core_state_version == one.core_state_version + 1
    assert changed_core.memory_hash != one.memory_hash


def test_supersession_keeps_history_without_silent_overwrite(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    old = ReadOnlyMemoryAdapter().derive(read_model, evidence(read_model, "ev-old", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "quiet", "proposition": "prefers quiet", "conflict_key": "pref"}]))[0]
    new = ReadOnlyMemoryAdapter().derive(read_model, evidence(read_model, "ev-new", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "music", "proposition": "prefers music", "conflict_key": "pref", "supersedes": [old.record_id]}]))[0]

    context = project_context([old, new])

    assert old in context.records
    assert new in context.records
    assert new.supersedes == [old.record_id]
    assert context.status == "COMPLETE"


def test_unresolved_conflict_is_degraded_and_deterministic(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    adapter = ReadOnlyMemoryAdapter()
    left = adapter.derive(read_model, evidence(read_model, "ev-left", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "quiet", "proposition": "prefers quiet", "conflict_key": "pref"}]))[0]
    right = adapter.derive(read_model, evidence(read_model, "ev-right", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "music", "proposition": "prefers music", "conflict_key": "pref"}]))[0]

    a = project_context([right, left, left])
    b = project_context([left, right])
    hermes = project_hermes(a, read_model)

    assert a.canonical_hash == b.canonical_hash
    assert [record.record_id for record in a.records] == sorted({left.record_id, right.record_id})
    assert a.status == "DEGRADED"
    assert a.degraded_reasons == ["conflict:pref"]
    assert hermes.status == "DEGRADED"
    assert hermes.identity_authority == "core_read_model"


def test_delete_rebuild_matrix_multiple_inferred_superseded_and_restart(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    old = evidence(read_model, "ev-old", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "quiet", "proposition": "prefers quiet", "conflict_key": "pref"}])
    old_record = ReadOnlyMemoryAdapter().derive(read_model, old)[0]
    new = evidence(read_model, "ev-new", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "focus", "proposition": "prefers focus", "conflict_key": "pref", "supersedes": [old_record.record_id]}])
    explicit_inferred = evidence(read_model, "ev-inf", [{"assertion_kind": "INFERRED", "domain": "mode", "value": "low-noise", "proposition": "benefits from low noise", "inference_rule": "explicit-test-rule-v1", "confidence": 0.7}])
    store = InMemoryDerivedStateStore()
    chain = ValuePocReadChain(core=StaticCoreReader(read_model), gateway=GatewaySetReader([new, explicit_inferred, old]), store=store)
    first = chain.run()
    chain.delete_derived_state()
    restarted_chain = ValuePocReadChain(core=StaticCoreReader(read_model), gateway=GatewaySetReader([old, new, explicit_inferred]), store=InMemoryDerivedStateStore())
    rebuilt = restarted_chain.run()

    assert first.canonical_hash == rebuilt.canonical_hash
    assert first.context.canonical_hash == rebuilt.context.canonical_hash
    assert any(record.assertion_kind == "INFERRED" for record in rebuilt.memory_records)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    service.governed_mutation(mutation(genesis_request, lease, "m4-stale"))
    with pytest.raises(CoreError, match="VALUE_POC_PROVENANCE_MISMATCH"):
        ValuePocReadChain(core=StaticCoreReader(service.core_read_model()), gateway=GatewaySetReader([old])).run()


def test_failure_degraded_semantics_are_explicit(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    with pytest.raises(CoreError, match="VALUE_POC_EVIDENCE_SCHEMA_UNSUPPORTED"):
        ValuePocReadChain(core=StaticCoreReader(read_model), gateway=GatewaySetReader([evidence(read_model, "bad-schema", [{"assertion_kind": "DERIVED", "domain": "x", "value": "y"}]).model_copy(update={"schema_version": "future"})])).run()
    with pytest.raises(CoreError, match="VALUE_POC_EVIDENCE_FACTS_REQUIRED"):
        ValuePocReadChain(core=StaticCoreReader(read_model), gateway=GatewaySetReader([evidence(read_model, "empty", [])])).run()
    with pytest.raises(CoreError, match="VALUE_POC_INFERENCE_RULE_REQUIRED"):
        ValuePocReadChain(core=StaticCoreReader(read_model), gateway=GatewaySetReader([evidence(read_model, "bad-inf", [{"assertion_kind": "INFERRED", "domain": "x", "value": "y"}])])).run()


def test_value_layer_architecture_boundary_m4():
    forbidden_import_roots = {"sqlalchemy", "psycopg", "sqlite3", "app.db", "app.models", "app.services"}
    forbidden_names = {"DATABASE_URL", "CORE_DATABASE_URL", "GATEWAY_DATABASE_URL", "R1_SLICE03_PRIVATE_CONFIG"}
    for file in ["app/value_poc.py", "app/core_read_model_client.py", "app/gateway_client.py"]:
        tree = ast.parse(Path(file).read_text(encoding="utf-8"))
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
                assert node.func.attr not in {"execute", "executemany", "executescript"}

