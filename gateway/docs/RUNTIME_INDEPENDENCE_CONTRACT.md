# Runtime Independence Contract

Qingyu Memory Gateway is runtime-neutral. Hermes and future runtimes are clients, never owners of Gateway history.

## A runtime may

- retrieve authorized Context or Evidence references;
- submit append-only runtime events through an explicit future contract;
- call models and tools under its own policy;
- cache replaceable context or derived memory;
- report reconciliation checkpoints without changing the referenced evidence.

## A runtime must not

- rewrite Raw Archive bytes, normalized revisions, source observations, provenance, parser identity, or the Node tree;
- delete committed archive or attachment evidence;
- treat its `state.db`, `MEMORY.md`, cache, transcript, prompt, or model output as Qingyu's unique history;
- force the Gateway to import Hermes/Mem0/Graphiti/provider libraries or depend on runtime availability;
- create a reverse authority path from Runtime, Context, or Derived Memory into Evidence.

## Future runtime-neutral requirements — design only

These are requirements, not Phase 3 APIs or schema:

- `continuity_id`: stable cross-session continuity identity, independent of a vendor runtime; assignment and remapping are Gateway-governed, versioned, and provenanced, never unilaterally controlled by a runtime;
- `event_id`: idempotent append identity for a runtime event;
- `runtime_session_id`: scoped execution-session correlation, never a history identity;
- context retrieval: explicit query, authorization, evidence references, version/cursor, and deterministic result metadata;
- runtime event ingest: append-only event envelope, source/runtime identity, event time plus observed time, idempotency, provenance, and explicit trust class; storing or linking the event proves only that the emitter asserted it and never promotes its payload to imported source truth;
- local journal reconciliation: monotonic checkpoint, duplicate detection, conflict reporting, and no silent overwrite;
- evidence references: immutable identifiers to Archive/Conversation/Node/Message/Revision/Attachment evidence;
- derived-memory provenance: algorithm/model/version, input evidence set, creation time, invalidation state, and rebuildability.

Any future proposal must preserve replaceability: deleting a runtime, local journal, context cache, or derived-memory store cannot destroy Gateway Evidence.
