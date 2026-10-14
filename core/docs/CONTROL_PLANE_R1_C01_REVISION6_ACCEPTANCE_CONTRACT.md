# R1 C01 Revision 6 — Simplified Trust Acceptance Contract

Status: DESIGN CANDIDATE / independent Reviewer A/B/C pending. DESIGN ONLY.
This is the sole Revision 6 candidate; Revision 5 is rejected history, not a
base for incremental exceptions. Product code, migration, PostgreSQL
Acceptance, Signed Migration Intent and Foundation Closure remain forbidden
until this design passes.

Normative companions:

- `CONTROL_PLANE_R1_SIMPLIFIED_TRUST_MODEL.md`
- `adr/ADR-R1-006-TRUSTED-MONOTONIC-IBCS.md`
- `CONTROL_PLANE_R1_IBCS_OPERATOR_BOUNDARY.md`
- `docs/evidence/r1-acceptance-marathon/revision6_simplified_model.py`
- `docs/evidence/r1-acceptance-marathon/revision6_model_result.md`

## 1. Inherited closed decisions

P1-A/B/D remain closed: Authority-anchored GENESIS PREPARED exists before Ack;
successful COMMITTED GENESIS receipt #1 precedes all READY/admission; fresh
locked no-success evidence is required for preactivation Force Abort. Failed
GENESIS attempts remain immutable `GENESIS_ATTEMPT_ABORTED` bootstrap events,
never canonical receipts. Only a successful COMMITTED GENESIS is canonical #1
and enters the same publication pipeline as every later canonical receipt.

## 2. One-way artifacts and signature responsibility

### 2.1 Frozen candidates

Before PREPARE, Core durably freezes canonical operation request bytes,
`local_commit_id`, payload/request digest, COMMIT and ABORT result bytes,
selected candidate Audit bytes/hashes, candidate `CoreReceiptBodyV2` bytes/hash,
state-transition digest, expected/resulting state version, epoch, storage and
control-plane generation, owner version and Authority domain/generation.

`CoreReceiptBodyV2` contains operation identity, decision-dependent candidate
result/Audit hash, canonical receipt sequence/predecessor supplied by the
Authority terminal proposal, state transition/resulting version and immutable
scope. Its canonical identity is `SHA256(prefix || canonical body bytes)`. It
does **not** contain the final Authority Terminal Certificate signature/hash or
any IBCS artifact; therefore the Authority can bind its candidate hash without
a cycle. The stored Core receipt record later contains the exact body plus the
verified Authority certificate as adjacent evidence, while the canonical body
hash remains unchanged.

### 2.2 Authority Terminal Certificate V2

Current F3 Terminal V1 directly signs Authority/identity/generation/request,
terminal decision/result/staged commit Audit candidate, sequence/predecessor
and result payload hash. It does not directly bind final Core persistence,
`local_commit_id` or transaction evidence; ABORT Audit is only indirectly
bound through the frozen abort result. Revision 6 therefore defines V2 rather
than reinterpreting V1.

`AuthorityTerminalCertificateV2` is Authority-signed and persisted with the
unique terminal in one Authority database transaction. It binds at least:

- certificate/protocol/key version, Authority domain/instance/generation;
- operation/mutation ID, continuity/identity, exact request/payload digest;
- `local_commit_id` and exact commit/abort authorization evidence digest;
- COMMITTED or ABORTED terminal decision and result hash;
- selected candidate `CoreReceiptBodyV2` hash;
- selected canonical Audit bytes hash and Audit predecessor;
- state-transition digest and expected/resulting state version;
- epoch, storage/control-plane generation, owner version;
- Authority canonical receipt sequence and predecessor terminal hash.

The Authority terminal signing key must be an already authorized deployment
key slot/pin under the frozen Root-signed origin/Signed Intent lineage. Missing,
unknown, conflicting or rotated-without-lineage key fails closed. Revision 6
does **not** add a Core self-assertion signer as a new source of truth.

### 2.3 Core persistence proof

After verifying V2, Core uses one local transaction to lock the operation and
canonical heads, verify the exact candidate bytes and terminal, apply only the
Authority-selected business outcome, append the exact receipt body/Audit row,
and update state/head/publication state. Commit outcome advances business state;
canonical ABORT advances receipt/Audit but preserves business version. Core
then performs a fresh database reload and recomputes receipt, Audit, transition,
version/generation and terminal hashes. IBCS receives the exact bytes and V2;
it recomputes all hashes itself. A Core signature or assertion cannot substitute
for exact bytes matching the Authority certificate. Any mismatch quarantines.

Normal process restart does not change historical receipt/certificate inputs.
Only durable storage generation is historical. Volatile process/session nonce
belongs solely to fresh admission and is never inside immutable receipt or
Publication Certificate. A stale clone with copied storage generation cannot
be admitted merely by self-consistency: fresh activation is scoped by IBCS
current head plus an IBCS-held singleton `CoreActivationTicketV1` and the
Authority owner/storage/lease rules. The ticket binds continuity, storage
generation, IBCS head, Authority generation/session, a fresh Core process
ephemeral public key and expiry. Its private key exists only in process memory,
not the cloneable Core DB. IBCS CAS admits one current ticket; normal restart
requires expiry/revocation plus a fresh Authority-authorized activation and
new ephemeral key. It never silently replaces a live claimant. Every admission
nonce is signed by that ephemeral key and echoed in IBCS freshness evidence;
a disk clone cannot reuse a copied historical ticket without its process key.
Host-memory snapshot/credential forgery remains outside the stated threat
model. Competing/stale incarnation is refused and logged.

### 2.4 IBCS Publication Certificate

Authenticated Authority publisher sends V2 plus exact persisted Core receipt
body/Audit/state proof to the independent IBCS append API. IBCS verifies V2,
all candidate hashes and expected predecessor and atomically append-CASes:

- protocol/certificate version, publication ID, IBCS identity/generation/key;
- IBCS sequence and previous Publication Certificate hash;
- continuity ID, canonical receipt sequence/body hash and Audit hash;
- resulting state version, storage generation;
- Authority Terminal Certificate V2 hash and Authority domain/generation.

The IBCS signing key is a pinned, preprovisioned acceptance credential under
the approved Root/Signed Intent deployment manifest; Core and Authority only
receive its public pin. Missing/conflicting/unapproved key/generation fails
closed. Certificate signed bytes are immutable. Same publication ID and exact
body returns the original byte-for-byte certificate; same ID/sequence with any
different body/hash is a fork and quarantines. Certificate includes no query
nonce, timestamp that changes on retry, Authority acknowledgement or future
admission token.

### 2.5 Freshness Attestation

For each admission/recovery check, caller sends a fresh unpredictable nonce and
query identity. IBCS returns a newly signed `FreshnessAttestationV1` binding
nonce, current IBCS sequence, current Publication Certificate ID/hash, IBCS
identity/generation, current `CoreActivationTicketV1` ID/ephemeral public key
and protocol version. Signature key is pinned by the same
approved IBCS deployment lineage. A nonce mismatch, replayed/expired challenge,
identity/generation/key conflict or unavailable IBCS rejects. Historical
certificate bytes may replay; freshness bytes for an old nonce may not.

The dependency graph is acyclic:

```text
request/result/receipt-body/Audit candidates
 -> Authority Terminal Certificate V2
 -> exact Core receipt/Audit/state persistence and reload
 -> immutable IBCS Publication Certificate
 -> nonce-bound IBCS Freshness Attestation
 -> scoped Authority/Core admission
```

No artifact hashes a later signature that also hashes it. Authority publication
acknowledgement, if stored, is non-authoritative operational metadata and is not
an admission correctness input.

## 3. Durable local decision gate and Authority terminal arbitration

Every terminal sender competes on one Core durable operation row. A local SQL
transaction locks that row/version, freshly verifies PREPARED and eligibility,
then performs exactly one transition:

- `PREPARED -> COMMIT_DISPATCHED`, persisting exact commit request/authorization;
- `PREPARED -> ABORT_PENDING`, persisting exact abort authorization and fresh
  local no-success evidence.

The transaction commits before network dispatch. No DB transaction is held
across Authority I/O. The opposite transition must fail under the same DB-level
predicate across threads, processes and restarts; Python locks, time or call
order are not evidence. Startup resumes/query-dispatches the stored decision and
cannot choose the other one.

Authority remains unique terminal arbiter. Any ambiguous POST is resolved by
authenticated GET of the same operation ID. A proven terminal transitions the
local row to `TERMINAL_RECONCILIATION(<signed winner>)`. The local finalize
transaction locks the same row and canonical heads and rechecks the decision
version/fence at commit. It is the only path that exposes staged business
effects or selected Audit/receipt. Therefore:

- `ABORT_PENDING + Authority COMMITTED` reconciles COMMITTED if exact staged
  bytes are intact; it never manufactures ABORTED.
- `COMMIT_DISPATCHED + Authority ABORTED` reconciles ABORTED and leaves business
  version unchanged.
- UNKNOWN remains fenced. A contradictory existing local effect/history is
  QUARANTINE, not overwritten.

## 4. Canonical publication state and strict fence

Core publication states are durable per canonical N:

1. `TERMINAL_RECONCILIATION`
2. `PUBLICATION_PENDING` — exact V2, persisted receipt/Audit/state, deterministic
   publication ID and expected IBCS predecessor are durable.
3. `PUBLICATION_CONFIRMED` — exact returned IBCS certificate bytes/hash are
   durable and freshly reloaded.
4. `ADMISSION_STAGED -> READY/OPEN` after a new valid IBCS nonce proof and exact
   `CoreHead == AuthorityHead == IBCSHead` hash/generation comparison plus the
   one current unexpired Core activation ticket and proof-of-possession.

Receipt N terminal/persistence immediately closes admission. Canonical mutation
N+1 cannot begin while N is `PUBLICATION_PENDING`, IBCS is unavailable or the
fresh exact-head comparison has not completed. No pipeline window exists in R1.

Automatic publication retry is permitted **only** when Core durably says
`PUBLICATION_PENDING`, V2 and exact Core bytes revalidate, fresh IBCS head equals
the stored expected predecessor, no conflicting publication exists and all
continuity/generations match. It uses the deterministic same publication ID.
If IBCS already contains the exact certificate, query returns original bytes
and Core may mark confirmed after full verification.

If Core durably says `PUBLICATION_CONFIRMED` but fresh IBCS is lower/missing or
lacks that certificate, it must QUARANTINE and cannot republish. If IBCS is
higher than Core or Authority, or Authority is behind the certificate-bound
terminal, recovery is required; no actor chooses max(sequence). Because IBCS
is the trust anchor, these rules detect external stale domains relative to it,
not IBCS self-rollback as a proven cause.

## 5. Crash, retry and race matrix

| ID | Durable observation | Required action |
| --- | --- | --- |
| S1 | PREPARED, crash before local decision | re-evaluate and atomically claim one decision; no network sender yet |
| S2 | COMMIT_DISPATCHED, crash before POST | resume/query same stored COMMIT; ABORT transition forbidden |
| S3 | ABORT_PENDING, crash before POST | resume/query same stored ABORT; COMMIT transition forbidden |
| S4 | COMMIT or ABORT POST response lost | GET same ID; established Authority terminal wins; no timeout verdict |
| S5 | concurrent thread/process COMMIT vs ABORT | same row/version CAS yields exactly one local dispatch choice |
| S6 | local ABORT_PENDING, Authority COMMITTED | row-locked exact COMMITTED reconciliation; never local ABORTED |
| S7 | local COMMIT_DISPATCHED, Authority ABORTED | row-locked ABORTED reconciliation; no business effect |
| S8 | terminal/Core persistence committed, crash before IBCS | PUBLICATION_PENDING retry rules only; N+1 denied |
| S9 | IBCS append succeeds, response lost | same ID query; exact certificate bytes; persist confirmed after verify |
| S10 | PUBLICATION_CONFIRMED, IBCS lower/missing | QUARANTINE; never retry publication to repair |
| S11 | IBCS ahead of Core | stale Core/clone; CLOSED; signed history/explicit restore only |
| S12 | IBCS ahead of Authority | Authority stale/rollback/divergence; QUARANTINE; no Core reconstruction |
| S13 | equal seq, different hash | fork/corruption; QUARANTINE |
| S14 | IBCS unavailable/identity mismatch/stale nonce | CLOSED; historical terminal remains unchanged |
| S15 | normal process restart, durable heads exact | new nonce/session/incarnation admission; historical cert unchanged |
| S16 | preactivation GENESIS ABORT | bootstrap event only; canonical receipt sequence remains empty |

## 6. Safety invariants

- **SINV-01**: canonical receipt #1 is COMMITTED GENESIS.
- **SINV-02**: pre-GENESIS abort never enters canonical receipts.
- **SINV-03**: Authority terminal uniquely determines operation terminal truth.
- **SINV-04**: Core receipt/Audit/state bytes exactly match Authority V2 bindings.
- **SINV-05**: IBCS certificate is append-only, hash-chained and immutable.
- **SINV-06**: a new write requires exact signed CoreHead = AuthorityHead = fresh IBCSHead.
- **SINV-07**: PUBLICATION_PENDING blocks the next mutation.
- **SINV-08**: local PUBLICATION_CONFIRMED with missing/lower IBCS quarantines.
- **SINV-09**: IBCS ahead of Core/Authority closes admission and requires recovery.
- **SINV-10**: COMMIT_DISPATCHED XOR ABORT_PENDING for one PREPARED operation.
- **SINV-11**: local pending decision cannot override Authority terminal.
- **SINV-12**: old FreshnessAttestation cannot satisfy a new nonce.
- **SINV-13**: IBCS unavailable means admission closed.
- **SINV-14**: no automatic max(sequence) reconciliation.
- **SINV-15**: IBCS self-rollback/global rollback detection is not claimed; any
  observed mismatch still fails closed and cannot trigger runtime repair.

## 7. Design and implementation gates

The Revision 6 executable model must cover Core/Authority/IBCS heads, durable
publication state, local decision gate, unique Authority terminal, admission,
IBCS availability, crash/response loss/duplicate, Core/Authority rollback,
stale clone, COMMIT/ABORT race, publication response loss, restart and stale
freshness. IBCS rollback is injected only to prove mismatch/unavailability
fails closed, never to claim root-cause detection.

Three independent non-authors must separately answer:

- Reviewer A: Q1 Core/Authority rollback and clone fencing remain supported
  without correctness-critical Authority confirmation; Q2 IBCS self-rollback
  limitation is honest; Q3 every IBCS anomaly fails closed.
- Reviewer B: Q4 Authority V2—not Core assertion—anchors normal receipt/Audit/
  state; exact F3 extension and digest/signature graph are sufficient/acyclic.
- Reviewer C: Q5 COMMIT/ABORT exclusion occurs durably before network; opposite
  Authority winner, crash/retry and strict publication fence converge safely.

Any P0/P1/P2/OPEN/PARTIAL means **SIMPLIFIED TRUST MODEL STILL UNSOUND** and
STOP. There will be no Revision 7. Only all three PASS permits automatic C01
implementation and later independent implementation review. Real evidence must
include independent IBCS process/storage/identity/authentication, Core durable
store, Authority test-only PostgreSQL, restart, concurrent cross-process
COMMIT/ABORT, stale Core, stale Authority, IBCS unavailable and inspector. It
remains test-only evidence, not formal PostgreSQL Acceptance/Foundation Closure.
