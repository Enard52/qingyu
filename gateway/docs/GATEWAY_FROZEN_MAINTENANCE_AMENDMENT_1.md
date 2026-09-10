# Gateway Frozen Maintenance Amendment #1 — Read-only Evidence Query API

Status: CLOSED / FROZEN after Qingyu Core Phase 1 Stage 0 full regression and
independent Reviewer A/B/C final gates. This amendment does not reopen Gateway
Phase 3.

## Purpose and epistemic meaning

The API lets authorized, runtime-neutral consumers retrieve normalized historical
Evidence without connecting to the Gateway database. A response means only that
the Gateway recorded the returned evidence. It is not a statement of objective
world truth. In particular, a message whose role is `user` proves that the source
recorded a user statement; the Gateway does not create a `USER_STATED` truth
classification or assert that the proposition is true.

The API accepts no `continuity_id`, continuity alias, runtime session, memory,
context, belief, or model field. Mapping Evidence to those concepts belongs to a
downstream contract and cannot amend Gateway history.

This amendment explicitly supersedes the earlier future-design sentence in
`RUNTIME_INDEPENDENCE_CONTRACT.md` that described continuity assignment and
remapping as Gateway-governed. `continuity_id` and `continuity_alias` are owned by
Qingyu Core. Gateway does not create, assign, remap, rename, merge, retire, or
compare them and does not persist a Core identity mapping.

## Authentication and read-only capability

`EVIDENCE_READ_API_TOKEN` is a distinct bearer capability. It authorizes only the
routes under `/api/v1/evidence`; it is rejected by import, archive, and retry
routes. The existing administrative `API_TOKEN` may also read Evidence for
operations and recovery. In non-test environments both tokens must be non-example
secrets and must differ.

This is a service-wide logical read capability, not a claim of tenant isolation,
database roles, row-level security, or filesystem capability isolation.

`EVIDENCE_CURSOR_SIGNING_KEY` is a separate server-only HMAC key. It is never a
bearer credential and grants no read or administrative capability. Production
configuration rejects a missing/example key or a key equal to either bearer
token; bearer tokens cannot be used to forge accepted cursors.

## Contract version and endpoints

Every success response carries `contract_version: evidence-query-v1`,
`meaning: gateway_recorded_historical_evidence`, and
`consistency: bounded_high_water_enumeration_v1`, and
`Cache-Control: private, no-store`.

### `GET /api/v1/evidence/conversation-observations`

Query parameters:

- `source_account_id`: optional Gateway UUID filter;
- `conversation_id`: optional Gateway UUID filter;
- `limit`: 1–100, default 50;
- `cursor`: opaque, integrity-protected continuation cursor.

The result performs bounded high-water keyset enumeration of committed
`ConversationObservation` records. Multiple
observations for one Conversation are returned separately and are never collapsed
into a latest-state answer. Ordering is ascending by
`ImportBatchCommit.committed_at`, then observation UUID. The first page fixes an
upper bound; all continuation cursors retain it and bind the original filters.
This is not a database snapshot or transaction-level snapshot guarantee. A
transaction that commits concurrently after the high-water key is selected can be
absent from that enumeration, including when its stored ordering key sorts below
the selected high-water key. Consumers MUST periodically begin a new enumeration
from the first page and deduplicate by immutable
`conversation_observation_id`.

The summary contains only explicit identifiers, parser contract, times and parse
statuses, snapshot current-node state, observed title, and evidence fingerprints.
`observed_title` is read from that observation's source evidence. The mutable
`Conversation.title` convenience value is never used.

### `GET /api/v1/evidence/conversation-observations/{observation_id}/nodes`

Query parameters:

- `limit`: 1–100, default 100;
- `cursor`: opaque, integrity-protected continuation cursor bound to the
  observation.

Nodes are ordered by `observation_order`, then mapping-node-observation UUID.
Each node contains immutable Gateway references, parent topology, the declared
child order resolved to immutable Gateway node references,
`message_presence`, fingerprints, the exact bound MessageRevision when present,
and a bounded allow-listed attachment projection containing only `attachment_id`,
filename, media type, and size. It never embeds attachment attempts. A null structural node retains
`message_presence: null` with no message.

### `GET /api/v1/evidence/conversation-observations/{observation_id}/attachments/{attachment_id}/observations`

This observation-scoped endpoint first verifies that the attachment belongs to a
MessageRevision bound by a node in the specified ConversationObservation and then
returns only attempts from that observation's import job. Cross-observation or
unbound attachment references return 404. Attempts use bounded high-water keyset
pagination ordered by attempt number, observed time, and immutable observation
UUID; `limit` is 1–100. Attachment availability is not collapsed to earliest or
latest state. The same concurrent-commit caveat and periodic full-rescan rule
apply, with deduplication by immutable `attachment_observation_id`.

## Privacy allow-list

The public DTOs exclude ORM objects, database and filesystem locations, source ZIP
member names, RFC 6901 pointers, raw source fragments, broad metadata/report JSON,
descriptors, checkpoints, leases, process identifiers, credentials, database
URLs, raw exception strings, and tracebacks. They also exclude raw archive and
attachment bytes. Adding any excluded evidence requires a separately reviewed,
purpose-specific DTO and authorization decision.

Message content and normalized attachment names are themselves private Evidence;
bearer credentials must therefore be protected and responses must not be placed
in shared caches or content-bearing logs.

## Downstream reference profile boundary

This amendment does not provide a generic object-by-ID resolver. A downstream
Phase 1 durable Evidence reference must therefore be scoped to a path this API
can actually re-enumerate: a conversation observation; a mapping-node
observation within it; its bound message revision; or an attachment observation
within an observation-plus-attachment scope. Archive objects, accounts, jobs,
batches, conversations, nodes, messages, message observations, and attachments
returned as provenance attributes are not independently addressable reference
types under this amendment. A downstream consumer must not compensate with a
database read.

Cursors are pass-scoped continuation state, not durable completeness
checkpoints. Consumers periodically start a fresh pass and deduplicate immutable
conversation-observation and attachment-observation IDs. Extending the durable
reference profile requires a versioned, allow-listed resolver contract and tests;
it is not implied by an identifier appearing in a response.

## Errors

- `400` with `evidence_cursor_invalid`: malformed, tampered, wrong-kind, or
  cross-filter/cross-observation cursor;
- `401` with `authentication_required`: missing or invalid Evidence credential;
- `404` with `evidence_observation_not_found`: unknown observation reference;
- `404` with `evidence_attachment_not_found`: attachment is unknown or outside
  the specified observation scope;
- `422`: FastAPI request-shape validation, including invalid UUID or limit;
- `500` with the existing safe `database_operation_failed` code and request ID for
  SQLAlchemy failures, or `evidence_integrity_violation` and request ID when a
  committed topology reference cannot be safely projected; any other unhandled
  Evidence failure returns safe `evidence_operation_failed` plus a request ID.

Every Evidence success and error response, including 400/401/404/422/500, carries
`Cache-Control: private, no-store`. No error returns raw database parameters,
exception text, paths, tokens, or stack traces.

## Verification coverage

Stage 0 target tests cover cursor high-water/filter/scope retention and bearer-key
forgery rejection; attachment scope and bounded fan-out; explicit DTO privacy;
and the 400/401/404/422/500 no-store matrix. Separate 500 cases verify stable
codes and request IDs for database, topology-integrity, and otherwise unhandled
failures, and verify that response and captured logs exclude injected secrets,
paths, parameters, and locator values.

The allowlisted `qingyu_test` PostgreSQL boundary test selects a first-page
high-water, inserts an observation whose ordering key is before the existing
continuation position, proves that it is absent from that bounded pass, and proves
that a fresh first-page rescan discovers it. The test models consumer idempotency
by unioning immutable observation IDs. These tests support review but do not by
themselves mark the final Stage 0 gate CLOSED.

## Deliberate exclusions

There is no write endpoint, attachment download, raw archive export, full-text
search, relevance ranking, latest-state resolver, continuity lookup, derived
memory, or runtime-specific dependency. The internal
`EvidenceTreeQuery.reconstruct()` remains a restore/acceptance helper and is not a
public response contract.
