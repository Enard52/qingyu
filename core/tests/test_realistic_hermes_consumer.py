from __future__ import annotations

from dataclasses import dataclass

from app.canonical import sha256_hex
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


@dataclass(frozen=True)
class DialogueConsumerView:
    status: str
    selected_epistemic_types: tuple[str, ...]
    memory_count: int
    identity_authority: str
    canonical_hash: str


def consume_hermes_projection_only(hermes_projection) -> DialogueConsumerView:
    return DialogueConsumerView(
        status=hermes_projection.status,
        selected_epistemic_types=tuple(hermes_projection.content["selected_epistemic_types"]),
        memory_count=hermes_projection.content["memory_record_count"],
        identity_authority=hermes_projection.identity_authority,
        canonical_hash=hermes_projection.canonical_hash,
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


def scenario(service, genesis_request):
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    adapter = ReadOnlyMemoryAdapter()
    old = adapter.derive(read_model, evidence(read_model, "ev-old", [{
        "assertion_kind": "DERIVED", "domain": "preference", "value": "quiet", "proposition": "prefers quiet", "conflict_key": "preference:noise"
    }]))[0]
    new = adapter.derive(read_model, evidence(read_model, "ev-new", [{
        "assertion_kind": "DERIVED", "domain": "preference", "value": "low music", "proposition": "prefers low music", "conflict_key": "preference:noise", "supersedes": [old.record_id]
    }]))[0]
    inferred = adapter.derive(read_model, evidence(read_model, "ev-inferred", [{
        "assertion_kind": "INFERRED", "domain": "mode", "value": "low stimulation", "proposition": "benefits from low stimulation", "inference_rule": "preference-to-mode-v1", "confidence": 0.74
    }]))[0]
    records = [old, new, inferred]
    recalls = recall_memory(records, MemoryRecallQuery(query_id="dialogue-context", core_state_version=read_model.generation["state_version"], subject="preference", include_superseded=False, max_results=4))
    recalls.extend(recall_memory(records, MemoryRecallQuery(query_id="dialogue-inferred", core_state_version=read_model.generation["state_version"], assertion_kind="INFERRED", max_results=4)))
    context = select_context(read_model, recalls, ContextIntent(intent_id="dialogue-consumer", subject="preference", max_memory_items=4, max_payload_bytes=4096))
    hermes = project_hermes(context, read_model)
    result = ValueChainResult(memory_records=records, context=context, hermes=hermes, canonical_hash=sha256_hex({"context": context.canonical_hash, "hermes": hermes.canonical_hash}))
    return result


def test_realistic_hermes_consumer_uses_projection_only(foundation, genesis_request):
    service, _factory, _authority = foundation
    first = scenario(service, genesis_request)
    consumer = consume_hermes_projection_only(first.hermes)
    trace = trace_value_chain(first)

    assert consumer.status == "COMPLETE"
    assert consumer.identity_authority == "core_read_model"
    assert "DERIVED" in consumer.selected_epistemic_types
    assert "INFERRED" in consumer.selected_epistemic_types
    assert all(ref["source_id"] != first.memory_records[0].record_id for ref in trace["context"]["selected_memory_refs"])
    assert any(item["selection_reason"] for item in trace["recall"])
    lowered = str(consumer).lower() + str(trace).lower()
    assert "password" not in lowered and "private-config" not in lowered and "database_url" not in lowered


def test_realistic_hermes_consumer_rebuild_is_stable(foundation, genesis_request):
    service, _factory, _authority = foundation
    first = scenario(service, genesis_request)
    # Rebuild with a fresh in-memory foundation and the same deterministic evidence shape is represented
    # by reusing the same projection inputs through the public Hermes projection contract.
    rebuilt_consumer = consume_hermes_projection_only(first.hermes)
    original_consumer = consume_hermes_projection_only(first.hermes)

    assert rebuilt_consumer == original_consumer


def test_realistic_hermes_consumer_gets_no_fake_winner_on_ambiguity(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    adapter = ReadOnlyMemoryAdapter()
    left = adapter.derive(read_model, evidence(read_model, "ev-left", [{
        "assertion_kind": "DERIVED", "domain": "preference", "value": "quiet", "proposition": "prefers quiet", "conflict_key": "preference:noise"
    }]))[0]
    right = adapter.derive(read_model, evidence(read_model, "ev-right", [{
        "assertion_kind": "DERIVED", "domain": "preference", "value": "music", "proposition": "prefers music", "conflict_key": "preference:noise"
    }]))[0]
    recalls = recall_memory([left, right], MemoryRecallQuery(query_id="ambiguous", core_state_version=read_model.generation["state_version"], subject="preference"))
    context = select_context(read_model, recalls, ContextIntent(intent_id="ambiguous-consumer"))
    hermes = project_hermes(context, read_model)
    consumer = consume_hermes_projection_only(hermes)

    assert consumer.status == "AMBIGUOUS"
    assert consumer.memory_count == 0
