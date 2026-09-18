# Qingyu M4 Read Chain Contract

This document is a navigation contract for the existing Phase B1/C read chain. It does not create a new protocol and it is not an authority source.

## CoreReadModel

- Schema/version: `core-read-model-v1`.
- Boundary: `GET /api/v1/core/read-model` or an equivalent read-only service boundary.
- Authority: Core identity/governed-state authority only.
- Required binding: `identity_reference.continuity_id`, `generation.state_version`, `read_model_hash`, `read_only=true`.
- Consumers must validate schema, hash, and non-negative `state_version`.
- Failure behavior: fail closed; no caller may fabricate identity state when Core is unavailable or malformed.

## GatewayEvidence

- Schema/version: `gateway-evidence-normalized-v1`.
- Boundary: existing Gateway Evidence Query API through `GatewayEvidenceClient`.
- Required binding: `evidence_id`, `evidence_hash`, `core_read_model_hash`, optional `core_state_version`, optional `continuity_id`, `source_reference`, and `facts`.
- Evidence proves that a historical record or statement was observed. It does not by itself prove that the world fact is permanently true.
- Failure behavior: fail closed on missing, malformed, unsupported, stale, or mismatched evidence.

## MemoryRecord

- Schema/version: `memory-record-v1`.
- Boundary: normalized memory output only; no Core service internals or Gateway raw response internals.
- Required binding: `record_id`, `memory_hash`, `core_state_version`, `derivation_version`, `assertion_kind`, `provenance`.
- Allowed assertion kinds: `DERIVED` and `INFERRED` only.
- INFERRED records require an explicit `inference_rule` and confidence.
- Supersession is explicit through `supersedes`; historical records remain intact.
- Rebuild behavior: same Core state version, evidence identity set, and derivation version produce the same logical identity/hash.

## ContextProjection

- Schema/version: `context-projection-v1`.
- Boundary: consumes MemoryRecord values only.
- Required binding: `projection_id`, `core_state_version`, `canonical_hash`, `status`, `provenance`.
- Context orders records deterministically, de-duplicates identical memory IDs, rejects stale mixed Core versions, and marks unresolved conflicts as `DEGRADED`.
- Rebuild behavior: same logical memory input produces the same canonical context hash.

## HermesProfileProjection

- Schema/version: `hermes-profile-projection-v1`.
- Boundary: consumes ContextProjection + CoreReadModel only.
- Authority: projection consumer only; `identity_authority` remains `core_read_model`.
- No Core/Gateway DB handle, write capability, private config, or hidden local truth store is part of this contract.
- Rebuild behavior: projection loss does not affect Core, Gateway Evidence, Memory identity, or Context canonical state.

## Trace

`trace_value_chain` returns a non-secret provenance trace from Hermes -> Context -> Memory -> Gateway Evidence + Core Read Model state version.

## MemoryRecallQuery

- Schema/version: `memory-recall-query-v1`.
- Boundary: consumes MemoryRecord values and a Core state_version only.
- Supported deterministic filters: memory identity, evidence reference, proposition/subject, assertion kind, Core state_version, derivation version, supersession inclusion, and provenance source type.
- `recall_algorithm_version` is part of the query hash and result semantics.
- Failure behavior: unsupported query schema/algorithm and mixed/stale Core versions fail closed; no memory produces `NOT_FOUND`.

## RecallResult

- Schema/version: `memory-recall-result-v1`.
- RecallResult is a projection over existing MemoryRecord state. It is not a truth source.
- Required fields include query hash, algorithm version, matched memory reference, proposition/payload, epistemic type, provenance, Core state_version, supersession status, inference metadata, and selection reason.
- Unresolved conflicts return `AMBIGUOUS`; current recall does not arbitrarily choose a winner.

## Context Selection

- Schema/version: `context-intent-v1` input and `context-projection-v1` output.
- Boundary: consumes RecallResult values and CoreReadModel only.
- Selection is deterministic: compatible state version, non-superseded current recall, explicit proposition/subject match, provenance completeness, epistemic type, then stable memory reference tie-breaker.
- Budget fields are `max_memory_items` and `max_payload_bytes`; excluded records are recorded in `omitted_reasons`, and truncation sets `truncated=true` with `DEGRADED` status.
- Hermes consumes only ContextProjection and does not query Core, Gateway, or Memory internals.
