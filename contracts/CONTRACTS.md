# Contract Register

## `evidence-query-v1`

### Epistemic meaning

Every successful page carries:

- `contract_version: "evidence-query-v1"`
- `meaning: "gateway_recorded_historical_evidence"`
- `consistency: "bounded_high_water_enumeration_v1"`

The result proves only that Gateway recorded the returned historical evidence.
It is not an assertion of objective world truth. Multiple observations remain
distinct; the API is not a latest-state resolver.

### Routes and DTOs

The checked DTOs mirror the Gateway allow-list:

- `GET /api/v1/evidence/conversation-observations` ->
  `ObservationPage`
- `GET /api/v1/evidence/conversation-observations/{observation_id}/nodes` ->
  `NodePage`
- `GET /api/v1/evidence/conversation-observations/{observation_id}/attachments/{attachment_id}/observations`
  -> `AttachmentObservationPage`

The public projections include `ConversationObservationSummary`,
`NodeEvidence`, `MessageRevisionEvidence`, `AttachmentEvidence`, and
`AttachmentAttemptEvidence`. They exclude ORM objects, raw source fragments,
archive locators, filesystem paths, credentials, leases, database URLs,
process identifiers, and raw exception text.

`limit` is 1..100. `next_cursor` is opaque pass-scoped continuation state. It
must be retained and replayed as an opaque string; consumers must not construct,
decode, or treat it as a durable completeness checkpoint. A consumer periodically
starts a fresh first-page enumeration and deduplicates immutable observation IDs.

### Error and cache semantics

The stable error codes are:

| HTTP | Code |
| --- | --- |
| 400 | `evidence_cursor_invalid` |
| 401 | `authentication_required` |
| 404 | `evidence_observation_not_found` |
| 404 | `evidence_attachment_not_found` |
| 422 | request-shape validation |
| 500 | `database_operation_failed` |
| 500 | `evidence_integrity_violation` |
| 500 | `evidence_operation_failed` |

The 500 codes carry a safe `request_id`; raw exception text, paths, parameters,
tokens, and tracebacks are never part of the DTO. Every success and error
response is `Cache-Control: private, no-store`.

### Capability semantics

`gateway.evidence.read` is a distinct bearer capability. It authorizes only
GET routes below `/api/v1/evidence` and cannot call Gateway import, archive,
retry, or other mutation routes. The Gateway administrative token may also read
Evidence for operations/recovery. The cursor signing key is server-only and is
not a bearer capability.

This is a logical API capability, not a claim of tenant isolation, database
row-level security, or filesystem principal isolation.

## Core identity contract

`core-identity-v1` defines a shared identity envelope:

- `qingyu_identity_id`: opaque immutable UUIDv4 root identity;
- `continuity_id`: opaque immutable UUIDv4, one-to-one with the identity in
  Phase 1;
- `continuity_alias`: human-readable lookup label only; `qingyu-main` is an
  alias and never an ID;
- `continuity_epoch`: non-negative continuity-scoped fencing generation;
- `state_version`: non-negative per-continuity monotonic state cursor;
- `contract_version`: explicit contract version.

The DTO rejects non-UUIDv4 values for Core IDs and rejects an empty alias. It
does not infer identity from the alias. Ownership, epoch issuance, GENESIS,
leases, and persistence rules belong to the Core implementation and its frozen
architecture contract.

## Gateway Evidence reference profile

`EvidenceRef` is intentionally observation-scoped and contains no generic
`object_id`. The allowed object types and required locator paths are:

| Object type | Required locator |
| --- | --- |
| `CONVERSATION_OBSERVATION` | `conversation_observation_id` |
| `MAPPING_NODE_OBSERVATION` | `conversation_observation_id` + `mapping_node_observation_id` |
| `MESSAGE_REVISION` | `conversation_observation_id` + `mapping_node_observation_id` + `message_revision_id` |
| `ATTACHMENT_OBSERVATION` | `conversation_observation_id` + `attachment_id` + `attachment_observation_id` |

The ref also carries verification material. Fingerprint-backed refs require
the relevant Gateway fingerprints and observation time. Attachment attempts
whose Gateway fingerprint is null use `IDENTITY_AND_SCOPE` and expected
attempt fields; a caller must never fabricate a fingerprint.

These refs can be re-resolved only through the Amendment #1 API. A 404 or
scope/fingerprint mismatch is not permission to fall back to a Gateway DB
connection.
