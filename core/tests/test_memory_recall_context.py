from __future__ import annotations

import ast
from pathlib import Path

import pytest

from app.canonical import sha256_hex
from app.errors import CoreError
from app.schemas import MutationRequest
from app.value_poc import (
    ContextIntent,
    GatewayEvidence,
    MemoryRecallQuery,
    ReadOnlyMemoryAdapter,
    ValueChainResult,
    project_hermes,
    recall_memory,
    select_context,
    trace_value_chain,
)


def mutation(genesis_request, lease, name):
    return MutationRequest(
        continuity_id=genesis_request.continuity_id,
        continuity_epoch=0,
        lease_id=lease,
        mutation_id=name,
        actor_principal_id="owner-1",
        capability="core_writer",
        payload={"kind": "batch04-recall", "name": name},
    )


def evidence(read_model, evidence_id, facts):
    return GatewayEvidence(
        evidence_id=evidence_id,
        evidence_hash=sha256_hex({"id": evidence_id, "facts": facts, "state": read_model.generation["state_version"]}),
        core_read_model_hash=read_model.read_model_hash,
        core_state_version=read_model.generation["state_version"],
        continuity_id=read_model.identity_reference["continuity_id"],
        source_epistemic_status="USER_STATED",
        source_reference={"api": "/api/v1/evidence/conversation-observations", "id": evidence_id},
        facts=facts,
    )


def derive(read_model, *items):
    return ReadOnlyMemoryAdapter().derive_many(read_model, list(items))


def query(read_model, **kwargs):
    return MemoryRecallQuery(query_id="q", core_state_version=read_model.generation["state_version"], **kwargs)


def test_recall_contract_documented():
    text = Path("docs/M4_READ_CHAIN_CONTRACT.md").read_text(encoding="utf-8")
    for term in ["MemoryRecallQuery", "RecallResult", "Context Selection", "memory-recall-query-v1"]:
        assert term in text


def test_recall_deterministic_derived_inferred_and_trace(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    rm = service.core_read_model()
    records = derive(
        rm,
        evidence(rm, "ev-a", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "quiet", "proposition": "prefers quiet"}]),
        evidence(rm, "ev-b", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "focus", "proposition": "prefers focus"}]),
    )

    first = recall_memory(list(reversed(records)), query(rm, subject="preference"))
    second = recall_memory(records, query(rm, subject="preference"))
    context = select_context(rm, first, ContextIntent(intent_id="ctx", subject="preference", max_memory_items=3))
    hermes = project_hermes(context, rm)
    result = ValueChainResult(memory_records=records, context=context, hermes=hermes, canonical_hash=sha256_hex({"context": context.canonical_hash, "hermes": hermes.canonical_hash}))
    trace = trace_value_chain(result)

    assert [r.model_dump(mode="json") for r in first] == [r.model_dump(mode="json") for r in second]
    assert any(r.epistemic_type == "INFERRED" for r in first)
    assert "INFERRED" in hermes.content["selected_epistemic_types"]
    assert trace["recall"]
    assert trace["recall"][0]["selection_reason"]
    assert "password" not in str(trace).lower() and "token" not in str(trace).lower()


def test_supersession_current_and_historical_recall(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    rm = service.core_read_model()
    old = derive(rm, evidence(rm, "ev-old", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "quiet", "proposition": "prefers quiet", "conflict_key": "pref"}]))[0]
    new = derive(rm, evidence(rm, "ev-new", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "music", "proposition": "prefers music", "conflict_key": "pref", "supersedes": [old.record_id]}]))[0]
    records = [old, new]

    current = recall_memory(records, query(rm, subject="preference"))
    historical = recall_memory(records, query(rm, memory_id=old.record_id, include_superseded=True))

    assert all(r.memory_ref.source_id != old.record_id for r in current if r.memory_ref)
    assert historical[0].memory_ref.source_id == old.record_id
    assert historical[0].supersession_status == "SUPERSEDED"


def test_unresolved_conflict_is_ambiguous_and_rebuild_stable(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    rm = service.core_read_model()
    records = derive(
        rm,
        evidence(rm, "ev-left", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "quiet", "proposition": "prefers quiet", "conflict_key": "pref"}]),
        evidence(rm, "ev-right", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "music", "proposition": "prefers music", "conflict_key": "pref"}]),
    )

    a = recall_memory(records, query(rm, subject="preference"))
    b = recall_memory(list(reversed(records)), query(rm, subject="preference"))
    context_a = select_context(rm, a, ContextIntent(intent_id="ctx", subject="preference"))
    context_b = select_context(rm, b, ContextIntent(intent_id="ctx", subject="preference"))

    assert any(r.result_status == "AMBIGUOUS" for r in a)
    assert context_a.status == "AMBIGUOUS"
    assert context_a.canonical_hash == context_b.canonical_hash
    assert context_a.selected_memory_refs == []


def test_context_budget_is_deterministic_and_truncated(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    rm = service.core_read_model()
    records = derive(
        rm,
        evidence(rm, "ev-a", [{"assertion_kind": "DERIVED", "domain": "a", "value": "a", "proposition": "a"}]),
        evidence(rm, "ev-b", [{"assertion_kind": "DERIVED", "domain": "b", "value": "b", "proposition": "b"}]),
    )
    recalls = recall_memory(records, query(rm))

    one = select_context(rm, recalls, ContextIntent(intent_id="budget", max_memory_items=1))
    two = select_context(rm, list(reversed(recalls)), ContextIntent(intent_id="budget", max_memory_items=1))

    assert one.truncated is True
    assert one.status == "DEGRADED"
    assert one.canonical_hash == two.canonical_hash
    assert one.omitted_reasons


def test_recall_state_version_and_failure_semantics(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    rm = service.core_read_model()
    records = derive(rm, evidence(rm, "ev", [{"assertion_kind": "DERIVED", "domain": "preference", "value": "quiet", "proposition": "prefers quiet"}]))

    with pytest.raises(CoreError, match="VALUE_POC_RECALL_QUERY_SCHEMA_UNSUPPORTED"):
        recall_memory(records, query(rm).model_copy(update={"schema_version": "future"}))
    with pytest.raises(CoreError, match="VALUE_POC_RECALL_ALGORITHM_UNSUPPORTED"):
        recall_memory(records, query(rm).model_copy(update={"recall_algorithm_version": "future"}))
    with pytest.raises(CoreError, match="VALUE_POC_RECALL_PROVENANCE_REQUIRED"):
        recall_memory([records[0].model_copy(update={"provenance": []})], query(rm))

    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    service.governed_mutation(mutation(genesis_request, lease, "recall-stale"))
    with pytest.raises(CoreError, match="VALUE_POC_RECALL_STATE_VERSION_MISMATCH"):
        recall_memory(records, query(service.core_read_model()))


def test_context_selection_hermes_and_architecture_boundary(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    rm = service.core_read_model()
    records = derive(rm, evidence(rm, "ev", [{"assertion_kind": "INFERRED", "domain": "mode", "value": "low-noise", "proposition": "benefits from low noise", "inference_rule": "test-rule-v1", "confidence": 0.7}]))
    context = select_context(rm, recall_memory(records, query(rm, assertion_kind="INFERRED")), ContextIntent(intent_id="ctx"))
    hermes = project_hermes(context, rm)

    assert hermes.identity_authority == "core_read_model"
    assert hermes.content["selected_epistemic_types"] == ["INFERRED"]

    forbidden_import_roots = {"sqlalchemy", "psycopg", "sqlite3", "app.db", "app.models", "app.services", "tests.r1_private_config"}
    for file in ["app/value_poc.py", "app/core_read_model_client.py", "app/gateway_client.py"]:
        tree = ast.parse(Path(file).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name not in forbidden_import_roots for alias in node.names)
            elif isinstance(node, ast.ImportFrom):
                assert node.module not in forbidden_import_roots
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                assert "CURRENT_SCOPE" not in node.value and "R1_SLICE03_PRIVATE_CONFIG" not in node.value
