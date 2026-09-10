# Source-of-Truth Contract

The permanent authority order is:

```text
Raw Archive
    ↓
Normalized Evidence
    ↓
Derived Memory
    ↓
Context
    ↓
Runtime
    ↓
Model
```

Derivation is allowed only downward in the diagram. No downstream or derived layer may overwrite, redefine as authoritative, or become the sole surviving source for any upstream evidence layer.

## Authority rules

1. Raw Archive is byte-exact source truth. Its content-addressed object, size, SHA-256, observation, and manifest are preserved together.
2. Normalized Evidence is a deterministic semantic reconstruction of source fragments. JSONB is not a raw-byte copy.
3. `semantic_revision_fingerprint`, `source_observation_fingerprint`, and `canonical_fragment_fingerprint` are distinct contracts. The canonical fragment fingerprint hashes a versioned canonical JSON value together with its RFC 6901 locator; it is not a byte-offset or raw-byte hash.
4. Derived Memory is replaceable. Deleting it must not prevent regeneration from Gateway Evidence.
5. Context is a transient selection from evidence and derived memory. It cannot amend provenance.
6. Runtime and Model output remain claims/events even when linked to Evidence. Recording a link proves only that a named emitter made a particular assertion; it never promotes the payload to a source fact, changes its trust class, or overwrites imported evidence. Any future durable assertion record must carry emitter identity, provenance, trust class, event time, and observed time.

Mutable convenience projections are not historical authority. In particular, `Conversation.title` is the latest convenience value, while source title history lives in `ConversationObservation`; legacy `MessageObservation.parent_message_id` and `is_current_path` are convenience fields, while real-export topology is authoritative in `ConversationNode`, `ConversationObservation`, and `MappingNodeObservation`.

## Provenance requirements

Every durable normalized fact must be traceable to an ArchiveObject and source-native locator, directly or through its import batch and observation. Parser name/version and fingerprint version are part of reproducibility. Runtime filesystem paths, attempts, leases, process IDs, database URLs, tokens, and temporary paths are never source provenance.

## Rebuild invariant

A clean compatible Gateway plus the Evidence DB, raw archive objects, manifests, schema/version metadata, and configuration metadata must be sufficient to restore and query normalized evidence without staging data, the original worker process, Hermes, Mem0/Graphiti, a model provider, or network inference.

## Evidence Query API interpretation

The Amendment #1 Evidence Query API is a read-only projection of Raw Archive and
Normalized Evidence records. Its `gateway_recorded_historical_evidence` marker is
the mandatory interpretation: returned content proves what the Gateway recorded,
not that a proposition is objectively true. Multiple observations remain distinct;
the API does not synthesize a latest truth. Convenience values such as
`Conversation.title` are not substituted for an observation's historical value.
The consistency marker `bounded_high_water_enumeration_v1` is deliberately not a
database-snapshot claim: a concurrent late commit may be absent from one pass.
Consumers periodically restart enumeration and deduplicate immutable observation
identifiers.
