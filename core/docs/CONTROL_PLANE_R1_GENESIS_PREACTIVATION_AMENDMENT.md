# Control Plane R1 — GENESIS Pre-Activation Termination Contract Amendment

Status: **DESIGN REVISION 4 / independent Reviewer A/B pending**. This revision
implements the user's C01 direction and addresses four earlier P1 findings
plus two partial cross-store findings from Revision 2;
closure remains a Reviewer decision. It amends only the original R1 clauses
requiring every preactivation GENESIS force-abort to be a canonical receipt.
The original `<repo>\core` workspace is read-only. No product code,
candidate, migration or acceptance target is authorized by design review alone.

Revision 3 findings are preserved in
`docs/evidence/r1-acceptance-marathon/genesis-design-review-v3.md`:
P1-A/B/D CLOSED at design level; P1-C, new P1-E and new P1-F were not CLOSED.
Revision 4 adds §§11–18 and concrete IBCS acceptance profile; none is a
Reviewer PASS claim. **This draft is not yet accepted or implementation-ready.**

## 1. Namespaces and mandatory GENESIS opening

Before successful activation, the canonical receipt chain is **empty**:
generation 1 has sequence 0 and the verified signed-origin seed as head.
Bootstrap evidence has its own order/head, namespace, signature prefix and
validator. Every failed GENESIS attempt leaves a signed, immutable
`GENESIS_ATTEMPT_ABORTED` terminal there. It cannot consume canonical sequence
or masquerade as a canonical AuthorityReceipt/Core mutation Audit event.

The first canonical receipt remains generation 1 / sequence 1,
`AUTHORITY_GENESIS_ACTIVATION`, `COMMITTED` / `ACTIVATED`, bound to signed
provisioning origin. The existing canonical validator **continues to reject**
ABORTED GENESIS as receipt #1. Postactivation PREPARED operations still
force-abort into ordered canonical ABORTED receipts. The exceptional route is
decided from verified durable domain state under an Authority-exclusive lock,
not a caller-controlled flag. The Root never force-commits.

## 2. Concrete durable records and event order

The current `cp_operations` terminal shape requires a canonical receipt. The
reviewed schema must therefore use distinct `cp_bootstrap_attempts` and
`cp_bootstrap_events` for preactivation GENESIS. Attempt ID is an opaque,
immutable UUID/ULID, globally unique within the Authority domain. It is also
the canonical operation ID if that attempt succeeds. Same ID and exact request
returns byte-identical historical status; same ID with different bytes/scope
rejects. An ABORTED ID is never reused; a new GENESIS requires a new ID.

The attempt stores immutable original request wire/digest, claimant and
authorization identity, candidate opaque Qingyu identity/continuity/storage
IDs, signed origin/domain/instance/generation, local attempt reference,
prepare Ack exact wire/digest/key/signature, prepare timestamp and stable
bootstrap event sequence/hash. An ABORTED event additionally stores decision
identity, reason, pinned Root or creator authorization reference, revocation
proof if forced, no-local-success proof reference, terminal bytes/signature,
audit binding and previous bootstrap event hash. Terminal evidence and events
are append-only; a projection can CAS from PREPARED to ABORTED or COMMITTED and
mark deterministic cleanup completion, but may not rewrite original material.
Never DELETE/RESET an old PREPARED or terminal event.

Authority allocates `bootstrap_event_sequence` under a domain lock, starting at
1 and incrementing exactly once per durable PREPARE/ABORT/COMMIT marker. It is
disjoint from canonical `authority_sequence`. Each exact-field, versioned JCS
event is signed with a domain-separated prefix
`QINGYU-CP-R1-BOOTSTRAP-EVENT\x00` and hashes its verified predecessor;
the first predecessor derives from the signed origin/domain/instance/generation.
No gaps, forks, reused sequence, changed payload, wrong key or missing event
are admissible. A PREPARE event and attempt row are one Authority DB
transaction. An ABORT event, terminal row and barrier release are one Authority
DB transaction. COMMIT marker, receipt #1, identity/continuity and generation
transition are one Authority DB transaction (see §6).

At most one preactivation attempt can be unresolved per Authority domain.
Different IDs cannot race past the barrier; a signed failed attempt remains
queryable forever. An aborted candidate ID is only historical request data:
it cannot create a canonical identity, continuity, lease, owner or READY state.
A later attempt may propose the same candidate IDs only after exact previous
terminal/cleanup/checkpoint verification. Once receipt #1 exists, second
GENESIS is permanently rejected for that domain and identity/continuity 1:1
constraints remain enforced.

## 3. P1-A: local intent versus Authority-anchored PREPARED

`LOCAL_PREPARE_PENDING` is a durable Core local intent, not an Authority
PREPARED. The local row freezes attempt ID, full request digest, candidate
identity/continuity/storage IDs, local operation identity, origin and actor.
It grants no commit/abort/write authority and is not a bootstrap terminal.

The only route to an authoritative PREPARED is:

1. Core durably stores the immutable local intent before network submission.
2. Core submits the same ID/digest and exact wire to independent Authority.
   Authority verifies origin/actor, locks the domain and durably inserts the
   PREPARE event and attempt, then signs a versioned Ack binding attempt,
   request, candidate IDs, Authority tuple, state/generation inputs,
   bootstrap sequence/head, Ack ID/nonce/time and receipt-key identity.
3. **Before Authority may return an accepted PREPARED Ack**, its checkpoint
   client publishes that exact signed PREPARE event to the independent
   Checkpoint Service (§5). The service atomically CAS-appends the monotonic
   high-water and returns a signed, nonce-bound checkpoint proof. Authority
   verifies the proof and persists the proof ID/digest against that attempt.
   If publication fails or is ambiguous, Authority reports
   `PREPARE_ANCHOR_PENDING`, keeps the domain barrier and admits no COMMIT,
   ABORT or different attempt. It can retry publishing only the same bytes.
4. Core validates Ack, signed event, checkpoint proof and exact scope, then
   durably binds raw Ack/proof bytes and digests to the local intent under CAS.
   **Only now** Core may project `PREPARED`. Authority treats the attempt as
   anchored in step 3 but must not assume Core has bound it; terminal requests
   require exact fresh local prepared proof (§7).

Ack response loss after steps 2–3 uses same-ID read-only query: return exact
record/proof or `PREPARE_ANCHOR_PENDING`; never allocate a new sequence,
re-sign, silently erase a prepare or change ID. If Core is unavailable after
Authority anchoring, the barrier holds until deterministic local binding or an
operator reconciliation with fresh independent evidence. A local row named
PREPARED without valid Authority Ack **and checkpoint proof** is quarantined,
not accepted. Every acknowledged PREPARED is therefore externally anchored
before acknowledgement; restoring Authority DB behind the checkpoint is
detected and fences admission (§5). Before this 1–4 sequence completes, there
is no authorized GENESIS COMMIT, official bootstrap FORCE_ABORT, canonical
receipt or governance write.

## 4. Authorization and exact abort proof

GENESIS PREPARE/COMMIT require the independently authorized owner/operator
ceremony, verified signed provisioning origin and pinned Operator Root public
key. Application/runtime/migration/startup cannot auto-generate, replace or
trust-on-first-use Root/GENESIS. Authority PREPARE and terminal signers are
protected service-held keys with verified public-key history tied to signed
activation. Lost signer/history makes operations fail closed. Tests use only
synthetic keys; the real acceptance private Root is never used automatically.

The original authenticated creator may request same-ID `ABORT_PREPARED` while
its credential remains valid. After revocation, only the pinned Root-signed
`FORCE_ABORT_PREPARED` is eligible. A normal runtime identity alone has no
bootstrap abort privilege. The decision binds origin, domain/instance/
generation, attempt ID, exact request/prepare Ack/checkpoint digests, actor,
reason, current bootstrap head, unique nonce, revocation evidence if forced,
and an independently verifiable fresh local no-success proof. Versioned JCS
with distinct bootstrap decision/termination prefixes, exact-field checking,
key/pin checks and one-use nonce prevent scope replay. Root-signed authority
is necessary after creator revocation but **not sufficient** to infer failure.

Authority must not treat timeout, absent callback, stale cache, revocation,
or caller assertion alone as proof that local effects did not succeed.
The cross-store rule in §7 and the fresh Authority same-ID COMMIT query are
mandatory preconditions for either ABORT route. Unknown means QUARANTINED /
RECONCILIATION_REQUIRED, never FAILED.

## 5. P1-C: independent high-water and clone defense

R1 selects an **Independent Bootstrap Checkpoint Service (IBCS)**, a separate
operator-controlled security and storage boundary from **both** Core local
DB/VM and Authority DB/VM backup sets. It is not Gateway, a legacy Qingyu DB,
an in-process fixture, a file copied inside either VM snapshot, or a writable
worktree. Production/acceptance deployment must provision a named independent
host/service identity, dedicated durable append-only journal/volume, audited
ACL, signed origin/profile, TLS server SPKI pin and IBCS Ed25519 verification
key whose public fingerprint is Operator-Root-authorized. Its private signing
key stays in its own protected boundary, excluded from Core/Authority backups.
The service is contacted through an authenticated, pinned read/append API; its
responses are signed, versioned JCS and nonce-bound. No local config or HTTP
self-claim can become a checkpoint. **No actual IBCS instance is asserted to
exist today**; implementation and real acceptance remain BLOCKED until the
independent target is safely provisioned and its isolation verified.

The selected **R1_ACCEPTANCE_TEST_ONLY IBCS implementation target** is a
dedicated service process running under a third, separately provisioned
Windows service identity `NT SERVICE\QingyuR1IBCSAcceptance` from the
protected acceptance deployment, with its own signed endpoint/TLS SPKI and
service-held protected Ed25519 signer outside Git. Its durable journal/head
is an isolated **new** PostgreSQL instance/container with unique provisioning
UUID/cluster system ID, database `qingyu_r1_ibcs_acceptance`, dedicated
`r1_ibcs_acceptance_data` volume and `r1_ibcs_acceptance_net` network, and
roles `ibcs_owner` (NOLOGIN), `ibcs_writer` (service-only), `ibcs_reader`
(read/query), separately provisioned from the Authority acceptance database.
These are design target labels; resource names and isolation must be resolved
read-only before creation, not assumed vacant. The IBCS service is the only
normal writer: Authority publisher authenticates to its append API with a
distinct pinned mTLS/service credential and exact signed terminal/event bytes;
Core uses a separately scoped read/query credential only and cannot append,
issue/checkpoint-sign, execute DDL or obtain IBCS DB credentials. Neither
Authority nor Core connects to the IBCS DB as owner. IBCS owner/writer may
not connect to Core, Authority or Gateway databases. Runtime roles receive
no direct IBCS base-table write grant or signer access.

Acceptance preflight must record actual process PID/token/service SID,
protected executable/module digest/ACL, endpoint/SPKI/key fingerprint,
signed provisioning marker, exact container/volume/network IDs and non-overlap,
IBCS PostgreSQL `system_identifier`, database/role/search_path/owner/GRANT,
separate runtime credentials, backup-set membership and negative access tests.
None of these has happened in this **design-only** phase. A second table/schema
inside Core or Authority, a reattached Gateway volume, same database, same
service identity/key or cloned credential is an isolation failure. Targeted
Core/Authority DB snapshot tests must keep this volume outside the snapshot.
IBCS outage or discrepancy makes all writes and new GENESIS admission CLOSED.

Same-host isolation proves separation of process, credential, storage and
targeted Core/Authority DB rollback, **not** cross-host disaster tolerance.
A complete Windows/Docker host snapshot that also contains this IBCS volume
cannot be claimed detected by this test-only profile. Whole-host recovery is
QUARANTINED/UNKNOWN unless a separately retained operator-signed off-host
maximum/dossier and approved generation/restore transition are verified.
Production IBCS must run on a separate host/failure domain with its own
non-rollback operator maximum; R1 test-only Root/IBCS may never be promoted
into that production trust claim.

IBCS state is **one durable single-head register keyed solely by
`authority_domain_id`** plus an immutable domain-wide journal. Candidate
continuity/identity IDs are authenticated *payload fields*, never a register
partition key or alternate head. The one domain key is used before and after
GENESIS and through authorized restore/DR transitions; no fresh candidate ID
can start a second checkpoint branch after DB rollback. Before canonical
GENESIS the register also
binds signed origin digest, Authority instance/generation, bootstrap attempt
ID, event sequence/head, local attempt/Ack digest and checkpoint predecessor.
After GENESIS it binds canonical GENESIS operation/receipt hash, generation/
sequence/head, Core audit sequence/head, state version, continuity epoch,
storage generation, control-plane generation, owner version and current
Authority-issued activation/incarnation token identity. The exact checkpoint
wire includes checkpoint version/ID, predecessor ID/hash, expected previous
head/sequence, proposed new head/sequence, signed event/receipt/proof digests,
target profile, issue time and request nonce. Physical OID/hostname/database
name is supporting observation only, never primary clone identity.

Append is an atomic, linearizable IBCS compare-and-swap **against this one
domain head**: verify signed
Authority event and domain/origin/key; compare **both** expected predecessor
ID/hash and tuple (bootstrap sequence/head, canonical generation/sequence/head,
storage/owner/audit high-water); append the next immutable entry and sign a
proof only if current head exactly matches. Repeated identical request ID and
bytes returns the same original proof. Different bytes for the same ID reject.
Two different successors to the same predecessor cannot both commit: one CAS
wins; the other is `FORK_REJECTED` even if its DB had locally committed.
Changing the proposed continuity candidate, Authority instance or bootstrap
attempt ID cannot select a fresh high-water register. A restarted/rolled-back
Authority must query this same domain head before any new PREPARE; an older
DB origin/sequence/head mismatch fails closed. A domain with an externally
anchored PREPARED but no corresponding local/Authority DB row is
RECONCILIATION_REQUIRED, never eligible for a different candidate attempt.
Sequence cannot decrease, be reused with a different digest, or skip without
complete signed intervening events. IBCS must retain predecessor journal
history through restore; restoring its own old snapshot without matching an
independent signed operator custody/dossier maximum is forbidden and requires
manual recovery authorization. IBCS loss/unverified high-water halts domain
writes; no local store silently reconstructs it.

Every Core startup/restore performs a fresh nonce-bound signed IBCS read plus
Authority same-ID/history query. Admission requires exact domain/origin,
instance/generation, identity/continuity, bootstrap lineage, canonical
GENESIS ID/head, storage/control-plane generation, audit/state/owner tuple and
current signed activation token. Local behind IBCS, local ahead without
authenticated outstanding-publication proof, same continuity with different
GENESIS, conflicting generation/storage/owner/audit, missing predecessor, or
two claimants for the same activation token all fail closed. Different Core DB
or cloned VM names have no standing. A clone may copy a local token, so it
cannot activate from that copy: IBCS/Authority require a fresh challenge-bound
service incarnation proof and an atomic sole-active-token claim. Only an
Authority-issued token referencing the current IBCS head can enable the
current Core instance; a second clone's claim CAS fails and all local writes
remain CLOSED. The exact token scope includes domain, continuity, Authority
instance/generation, Core storage generation, continuity epoch, owner version,
service incarnation nonce, IBCS checkpoint ID/head and expiration/renewal
rules; the runtime cannot issue or extend it.

Legitimate **restore** is a separately authorized, signed recovery operation:
verify full independent lineage, reserve a new storage generation, increment
epoch, revoke the old token/lease, reconcile audit and issue a fresh sole-active
token by IBCS CAS; local READY is last. Legitimate **hardware migration** uses
the same owner/operator authorized recovery and token transfer with old
incarnation revoked; hostname never transfers authority. **Manual Authority
DR** requires the existing Operator-Root-signed DR dossier, previous maximum,
new Authority instance/generation/key and IBCS CAS lineage transition;
missing complete history stays closed. A copied old instance merely starting
cannot satisfy any of these authorization/evidence transitions. No distributed
election or R2 multi-Authority consensus is introduced.

## 6. P1-B: COMMITTED GENESIS precedes READY, with durable write fence

The successful attempt's verified PREPARED bootstrap head (including all prior
failed attempts and its own PREPARE event) is frozen under the domain lock.
`bootstrap_pre_activation_head` and sequence/count, origin digest and attempt
ID are signed inside the versioned GENESIS receipt payload. The canonical
GENESIS validator still requires COMMITTED/ACTIVATED #1 **and** recomputes the
bootstrap chain/anchor; older receipt versions without mandatory anchor cannot
silently pass the revised opening. The existing signed-origin GENESIS seed
remains independent of this dynamic bootstrap head.

Authority's activation DB transaction atomically creates canonical receipt
#1, canonical identity/continuity, the bootstrap COMMITTED marker referencing
receipt hash, and durable `GENESIS_COMMITTED_PENDING_RETENTION` domain state.
Canonical sequence becomes 1/head becomes receipt hash, but **admission stays
CLOSED**. This is a distinct reviewed schema state, not `ACTIVE`, `READY` or a
lease. No normal canonical PREPARE/COMMIT/ABORT, lease issuance, owner change,
recovery activation or mutation procedure may execute while it is pending.
Every SECURITY DEFINER mutating procedure checks the durable domain state,
signed current IBCS proof and incarnation token inside its DB transaction;
Core service performs the corresponding independent admission check. The
runtime role has no direct table capability to bypass these predicates.

After Authority COMMIT, Core same-ID query retrieves and verifies receipt #1;
Core durably binds it to local GENESIS/audit checkpoint while remaining
`PENDING_RETENTION` and write-closed. The bootstrap COMMITTED marker references
the *already computed* receipt hash and is not included in the receipt's
prior-head anchor, avoiding any hash/signature cycle. Authority/IBCS then
CAS-publish complete bootstrap head/marker, canonical receipt #1 and signed
fresh Core audit/state high-water. IBCS returns a verified retention proof.
Authority and Core both reload their own durable rows and signed IBCS proof,
compare exact head/audit/identity/owner/storage and enforce sole-active-token
claim. Core first durably stages `READY_PROOF_STAGED` with an exact signed local
audit/receipt/state proof but keeps its *effective* write predicate CLOSED.
Authority may then transition to ACTIVE with `ADMISSION_STAGED` after checking
that proof; **this transition alone grants no governance write**. Core next
re-queries ACTIVE/IBCS/token and durably publishes effective READY. Authority
only opens effective governance admission after a fresh, nonce-bound,
protected Core-local verifier attests this durable READY from a new locked DB
session, bound to the single IBCS head/current incarnation token and the
Authority staged transition. The Authority stores the verified READY-proof
digest/identity under CAS and moves to `ADMISSION_OPEN`. This prevents any
Authority-client write in the cross-store publication gap.

Every normal Authority API mutation and every reviewed SECURITY DEFINER
mutating procedure must require the **current**, request-bound READY proof
and sole-active-token claim, with an unforgeable Authority-issued admission
capability tied to the stored READY-proof digest, request ID and expiring
nonce. The runtime role cannot mint that capability or directly insert its
backing DB admission row. SQL verifies the stored domain admission state,
capability nonce/request binding, provenance and current IBCS high-water
inside the mutation transaction; stale, missing, cloned or wrong-instance
proof rejects. A client other than the attested READY Core instance has no
normal mutation route, even if Authority has seen an ACTIVE GENESIS. If Core
READY publication crashes, no READY proof exists and Authority remains
ADMISSION_STAGED/write-closed; if Authority ADMISSION_OPEN response is lost,
same-ID query and fresh proof renewal preserve exactly one release.

Only after the staged/READY/open handshake has been independently verified
may governance writes occur. If IBCS fails/timeout/unknown, already COMMITTED
GENESIS remains real, cannot be rolled back or reattempted as new, and both
sides stay CLOSED pending same-ID reconciliation. If Authority opens but Core
READY publication crashes, Core startup remains CLOSED until fresh match.

The signed opening receipt binds the **prior** bootstrap head; the COMMITTED
marker and IBCS postcommit checkpoint bind receipt hash **after** it exists.
Each verifier checks both links. Aborted attempts remain permanently retained
outside canonical cursor. Missing/tampered bootstrap history, receipt anchor,
external checkpoint or local audit mismatch quarantines, not auto-heals.

## 7. P1-D: fresh local result verification before Force Abort

Before Authority ABORT terminalization, Core durably CAS-fences the exact local
attempt as `ABORT_PENDING` under a fresh serializable/locked local DB read.
All GENESIS finalization/local receipt/identity publication paths must check
this durable fence under the same local transaction lock. A Core
`COMMIT_RESERVED` transition and a Core `ABORT_PENDING` transition compete by
conditional CAS on **the same local attempt row/version**; neither may follow
the other without an Authority-signed cancellation or terminal winner proof
under §14. The corresponding Authority terminal proposal, reservation,
cancellation, COMMIT and ABORT compete under the same ordered domain/operation
row lock and one terminal CAS. A protected **read-only local result verifier**, distinct from
the requesting runtime, then reloads persistent Core state in a new session:
exact attempt/wire, local terminal, canonical receipt #1, local audit terminal,
identity/continuity metadata, READY/ACTIVE publication and pending
reconciliation. It also queries Authority exact operation/receipt state and
fresh IBCS high-water. The verifier signs a nonce-bound, short-lived proof
with row/transaction-snapshot identity and scoped digests; no cache, caller
input or process memory is a proof. The proof binds the durable ABORT_PENDING
fence ID/version and current Authority PREPARED Ack/checkpoint, preventing a
different attempt or stale session from borrowing it.

`SUCCESS` (any matching COMMITTED Authority/local receipt, audit or published
identity) means ABORT MUST REJECT. `UNKNOWN/AMBIGUOUS` (DB unavailable,
in-flight transaction, missing signed lineage, local ahead/behind Authority,
unverified checkpoint, uncertain callback or partial success) means
QUARANTINE/RECONCILIATION_REQUIRED, no ABORT, no new attempt. Only fresh
`NOT_COMMITTED` with exact locked local fence, absence of success in both
lineages and deterministic no-business-commit attestation is eligible for
abort authorization. This is an authenticated claimant/local-inspector
attestation, not a claim of Objective World Truth; Authority independently
checks same-ID terminal absence and terminal CAS under domain lock.

Order: fresh Authority PREPARE/Ack/IBCS proof → fresh Core locked local result
and ABORT_PENDING fence → exact scope/no-success proof → fresh Authority
terminal query → creator or Root signature authorization → Authority domain
lock/CAS recheck of PREPARED, head and proof freshness → one signed bootstrap
ABORT event/terminal DB commit → IBCS CAS external retention → Core same-ID
ABORT record/audit binding → deterministic transient cleanup → verified
UNINITIALIZED/NOT_ACTIVATED, admission CLOSED. No new GENESIS until IBCS and
both sides agree on terminal/cleanup; use a new attempt ID. If crash occurs
after local fencing but before Authority ABORT, local remains write-closed and
reconciles the same ID; ABORT_PENDING is never automatically treated as
ABORTED. If an earlier Authority COMMIT won, late ABORT rejects and Core
converges to COMMITTED from the exact signed terminal under §14; a local
ABORT_PENDING projection is not itself an ABORTED truth. Barrier release is atomic with terminal
Authority ABORT but **admission of a new attempt** requires external retention
and Core cleanup proof. Revocation evidence alone never turns UNKNOWN into
failure.

## 8. State transitions (write admission and new GENESIS are explicit)

State names here are durable projections; an independent Authority/IBCS fact
always prevails over an inconsistent local name. Actor is named in each row.
“Writes” means governance writes, leases, owner transfer and mutation; all
rows except READY deny them. Authority bootstrap PREPARE/terminal procedures
are narrowly separately authorized, not normal governance writes.

| From → to | Actor / prerequisite | Core durable effect | Authority durable effect | IBCS evidence / retry and crash rule | Writes / new GENESIS |
| --- | --- | --- | --- | --- | --- |
| UNINITIALIZED → LOCAL_PREPARE_PENDING | Authorized Core ceremony; verified origin; no active/pending attempt | Immutable local intent | None | Read fresh maximum first; same ID only on ambiguity | DENY / same ID only |
| LOCAL_PREPARE_PENDING → PREPARE_ANCHOR_PENDING | Authority verifies exact request under domain lock | Local intent remains | Signed attempt + PREPARE event/sequence, exclusive barrier | Publish exact event by CAS; loss queries same ID, no terminal | DENY / DENY |
| PREPARE_ANCHOR_PENDING → PREPARED | Authority checkpoint proof + Core validation/binding | Store exact Ack/proof, CAS PREPARED | Proof ID/digest durably bound | Ack must be externally anchored before return; reload on crash | DENY / DENY |
| PREPARED → COMMIT_RESERVED or ABORT_PENDING | Core same-row/version CAS; exact signed local proof; no proven local success permits ABORT | One immutable reservation/fence outcome | Authority records matching proposal under same op row lock; opposite decision blocked until signed cancellation | Unknown/lost reservation stays fenced; same-ID query | DENY / DENY |
| ABORT_PENDING → ABORTED_PENDING_RETENTION | Creator/Root auth + fresh no-success proof + Authority terminal CAS | Fence retained until same-ID query | Signed ABORT terminal/event and barrier release | CAS-publish terminal; unknown blocks new attempt | DENY / DENY |
| ABORTED_PENDING_RETENTION → UNINITIALIZED | Exact terminal/proof, deterministic cleanup and local audit binding | Immutable aborted history + cleanup proof, no canonical object | ABORTED historical row retained | Verify IBCS high-water; crash resumes cleanup | DENY / new ID permitted |
| COMMIT_RESERVED → GENESIS_COMMITTED_PENDING_RETENTION | Exact reserved COMMIT authorization/version; same operation/domain lock/CAS; no abort cancellation; signed bootstrap head | Same-ID receipt fetch/bind; local pending audit, never READY | Atomic receipt #1/identity/continuity/COMMITTED marker, pending domain admission | CAS-publish marker/receipt/local audit; unknown cannot roll back success | DENY / DENY permanently |
| GENESIS_COMMITTED_PENDING_RETENTION → READY_PROOF_STAGED / ACTIVE_ADMISSION_STAGED | Exact IBCS proof, fresh local/Authority audit match, sole active token | Stage signed local proof, effective writes remain closed | ACTIVE, admission staged/closed | Re-query/reload; no release on lost proof | DENY / DENY |
| READY_PROOF_STAGED / ACTIVE_ADMISSION_STAGED → READY / ADMISSION_OPEN | Core publishes effective READY, fresh protected verifier attests it, Authority CAS stores proof/opens admission | Durable READY; every write still needs fresh Authority/IBCS token check | ADMISSION_OPEN only after attested local READY; SQL/API require per-request proof/capability | Lost response resolves same ID; no second release/receipt | ALLOW only with fresh bound proof / DENY |
| Any uncertain state → RECONCILIATION_REQUIRED | Missing response, unverified max, transient DB/IBCS outage | Persist read-only reason and exact ID | No invented terminal or sequence | Same-ID query, IBCS proof and fresh reload; no automatic timeout verdict | DENY / DENY |
| Any contradictory state → QUARANTINED | Fork/rollback/tamper, two claimants, differing GENESIS, missing proof | Freeze local publication | Freeze domain admission; preserve evidence | Manual evidence comparison/recovery only, never silent repair | DENY / DENY |

Local-only intent with provably absent Authority PREPARE can retry same ID. A
failed attempt never reverts to an empty-history system: UNINITIALIZED is an
admission projection with permanent bootstrap ledger/high-water. `ABORT_PENDING`
is not an authoritative terminal. GENESIS success may exist before READY; it
cannot be “undone” to allow another GENESIS. Every startup independently
revalidates current proof before treating READY as effective.

## 9. Crash/retry matrix (all reads are same-ID and fresh)

| Event / uncertainty | Query and deterministic recovery | Terminal result | Admission |
| --- | --- | --- | --- |
| 1. Local intent persisted, Authority PREPARE not observed | Query Authority + IBCS by same ID; only proven absence permits same-ID PREPARE, no implicit new ID | None; LOCAL_PREPARE_PENDING | CLOSED |
| 2. Authority PREPARE persisted, response lost | Query same event/IBCS CAS proof; publish same bytes if anchor pending; Core binds exact Ack | PREPARED only after proof/binding | CLOSED |
| 3. Core bound PREPARED then crash | Reload local Ack, Authority event and IBCS maximum; same ID resumes | PREPARED | CLOSED |
| 4. Local ABORT proof/fence set, crash before Authority ABORT | Keep fence, fresh re-verify success absence and Authority PREPARED; new nonce/proof if stale | ABORT_PENDING, never inferred ABORTED | CLOSED |
| 5. Authority ABORT persisted, response lost | Query exact terminal; CAS-publish identical bytes/checkpoint if needed; local cleanup idempotent | ABORTED bootstrap evidence, no receipt | CLOSED until cleanup/retention |
| 6. Authority COMMIT persisted, Core unaware | Same-ID query returns receipt #1; Core verifies bootstrap anchor and binds local audit | COMMITTED GENESIS real | CLOSED pending retention |
| 7. Core receipt #1 persisted, retention failed | IBCS status query/re-publish same signed marker/proof; never retry GENESIS under new ID | COMMITTED GENESIS real | CLOSED |
| 8. Retention succeeded, READY publication or Authority OPEN crashed | Re-query staged state/IBCS; no mutation before durable local READY attestation and Authority CAS OPEN; same-ID renewal | COMMITTED receipt #1 unchanged | CLOSED until fresh bound proof |
| 9. Old ABORTED attempt late message | Same-ID ABORTED terminal lookup before effects; reject late finalize | Old ABORTED unchanged | New ACTIVE unaffected |
| 10. Old cloned DB/VM starts behind new maximum | Nonce-bound IBCS and Authority check detects stale head/token/generation; only signed restore/DR path can advance | Existing canonical history unaffected | Clone CLOSED/quarantined |

Additional races: two distinct PREPARE requests share the domain barrier;
abort/commit compete by exact attempt CAS; a cloned token cannot win a second
IBCS active-claim; a restored IBCS old snapshot requires signed external
operator maximum before any write. No uncommitted local session or identity-map
cache is accepted as a terminal verdict.

## 10. Validators, audit and regression obligations

Add strict bootstrap PREPARE/event/termination/checkpoint/activation-token
validators with exact field sets, versions, prefixes, JCS byte equality,
signatures, predecessor/order and full scope checks. Canonical receipt
validator keeps COMMITTED GENESIS #1 and rejects bootstrap ABORTED. Core audit
records the successful canonical GENESIS only after receipt #1 verification;
bootstrap audit/evidence remains independently queryable with signed origin,
event chain and IBCS proof, not grafted into mutation receipt cursor.

Opening GENESIS receipt #1 binds the verified **prior** bootstrap head; the
bootstrap COMMITTED marker and IBCS checkpoint reference the receipt hash
**after** receipt creation. This is the unique R1 rule; no circular signing
dependency. Same-ID POST non-200 resolves by read-only query. All unknown or
inconsistent receipt/Ack/checkpoint/token versions fail closed. None of these
rules allows Core direct Gateway DB access or rewrites Gateway evidence.

Existing F1/F2/F3/F4/F9 and Windows Identity Gate are frozen historical PASS;
this revision does not retract them. Actual schema, protocol, trust/admission,
Coordinator and Core service changes require affected-range regression plus
synthetic-key tests T1–T22 from the user attachments. Production PostgreSQL
role/SECURITY DEFINER/procedure tests, real IBCS isolation and checkpoint/clone
negative tests are needed for implementation and later Acceptance. No previous
F3 test-only SQL becomes a production migration by inference.

## 11. P1-E: one strict lifecycle for every canonical terminal receipt

The domain-wide IBCS register is not only a GENESIS anchor. R1 requires
**strictly serial publication** after every canonical terminal receipt:
COMMITTED mutation, canonical ABORTED operation, lease/owner/recovery terminal
and later authorized DR generation opening. No receipt N+1 can be allocated
while receipt N is unconfirmed at IBCS. Through C01 acceptance R1 admits one
continuity per Authority domain; a second continuity remains fail-closed
pending the separately reviewed Phase 4 scope constraint. This makes the
single Core audit sequence/head in one IBCS record unambiguous. Multi-
continuity audit vectors/global synchronization are not silently assumed.

For operation ID X and ordered receipt `(generation G, sequence N, hash H)`:

1. Existing authenticated PREPARED Ack has no canonical sequence. Exact
   terminal authorization and frozen request/staged/abort result/audit hashes
   are checked under the existing F3 lock order and §14 terminal rule.
2. Authority commits exactly one signed `COMMITTED` or canonical `ABORTED`
   receipt, head/sequence and business/governance effect in a **single DB
   transaction**. That transaction also durably sets
   `CANONICAL_TERMINAL_PENDING_CHECKPOINT`, closes all normal write/lease
   admission and stores deterministic publication ID and predecessor IBCS
   checkpoint ID/head. Signed receipt N exists even if the HTTP response is
   lost. A canonical ABORTED advances Authority sequence and Core Audit but
   not business state version; a COMMITTED applies its frozen effect.
3. Core same-ID query obtains receipt N, verifies signature/previous head,
   origin, scope and frozen result, and durably appends the appropriate
   immutable local receipt/Audit/checkpoint in one transaction. Local write
   eligibility remains CLOSED. A Core crash or missing local projection
   cannot cause Authority to presume an abort or reopen admission.
4. Authority is the **only publisher** to IBCS. It sends exact signed receipt
   N, immutable Authority terminal row and fresh signed Core local Audit/
   state/owner/storage evidence to the IBCS append API. IBCS CAS requires
   the verified previous checkpoint to represent exactly receipt N-1 (or
   signed GENESIS/DR predecessor), the old Audit/head/state tuple and the
   same domain/identity/continuity/instance. It atomically appends successor
   N, signs a versioned proof and updates the single high-water. No skipped
   sequence, changed hash or out-of-order pipelining is accepted.
5. Authority and Core reload signed IBCS N, signed Authority N and durable
   local Audit N. They compare the complete tuple, renew/revoke the sole
   activation token so it binds **new** checkpoint N, and perform the
   staged READY / Authority ADMISSION_OPEN proof handshake from §6.
   Normal write admission reopens only after the actual N checkpoint and
   current token/proof are independently verified. The next PREPARE/terminal
   cannot use proof for N-1.

Every mutating SECURITY DEFINER routine rechecks the durable pending/open
state and current verified publication capability under its DB transaction.
Authority API verifies fresh IBCS/READY proof before requesting the routine;
the runtime role cannot insert a forged admission proof row. A service
constructor, cached READY flag, terminal HTTP 200 or locally incremented
sequence cannot bypass this fence. Publication failure, timeout, unknown
result or lost proof leaves a real signed terminal N but denies N+1.

## 12. IBCS high-water record and monotonic publication rule

The exact signed `IBCSCheckpointV1` contains: record ID; deterministic
publication operation ID; publisher identity/key ID; Authority domain,
instance/generation and signed origin/DR transition digest; canonical
identity/continuity and successful GENESIS operation ID; bootstrap event
sequence/head; canonical `(generation, sequence, receipt_hash/head)`;
Core Audit sequence/head, committed business state version, continuity epoch,
active storage/control-plane generation and owner version; current/revoked
activation-incarnation token identity; previous IBCS record ID/hash and full
expected previous tuple; signed Authority event/receipt hash and signed
Core evidence digest; target/profile marker, issue nonce/time and IBCS
signature/key ID. Pre-GENESIS records use canonical sequence 0 and the
signed-origin seed, null canonical GENESIS ID and frozen pre-genesis zero/
null business fields; they never fabricate a canonical receipt.

JCS exact bytes, domain prefix, Ed25519 and SHA-256 identify the record.
The publication ID is deterministic from domain, operation/attempt ID,
generation, canonical or bootstrap sequence and exact terminal/event hash;
timestamp/nonce is evidence metadata, not a second candidate identity.
IBCS derives successor only from signed Authority and Core inputs; it does
not let a caller choose head/sequence. CAS compares previous record hash **and
complete previous tuple**. Same publication ID/exact bytes returns original
proof byte-for-byte. Same ID/different bytes or same sequence/different hash
is a fork, not a retry. Generation change requires signed existing DR dossier,
verified prior generation maximum/head and sequence-1 committed DR opening;
no numeric `max(seq)` substitutes for lineage. A rollback of Core/Authority
behind IBCS is detected by the hash/tuple mismatch. IBCS behind a proven
Authority pending terminal can be published only through §11's same-ID
protocol, never by locally resetting high-water.

Bootstrap PREPARE and `GENESIS_ATTEMPT_ABORTED` publish only bootstrap event
sequence/head with canonical 0/seed; GENESIS COMMITTED publishes bootstrap
marker **and** canonical receipt #1 with local Audit #1. A post-GENESIS
canonical ABORTED receipt publishes its new canonical receipt/Audit high-
water even though business state version is unchanged. A post-GENESIS
COMMITTED receipt publishes its new receipt/Audit and frozen effect fields.
All three are successor records in the same domain-wide IBCS journal, with
distinct event kind and exact signed predecessor. No bootstrap ABORT becomes
a canonical receipt.

## 13. Startup/recovery classification (never take a numeric maximum)

On every startup, restore, Authority restart, owner change and pending
publication retry, independently read fresh local canonical/Audit head,
Authority generation/receipt/head/terminal-pending row and nonce-bound signed
IBCS maximum. Check exact operation identity, receipt hash, predecessor,
Audit head, state/owner/storage/epoch and active token, not just sequence.

| Classification | Exact evidence | Result / recovery |
| --- | --- | --- |
| EXACT_MATCH | All three tuples and signed lineage equal; no pending terminal, current token/READY proof | Admission can open by §6/§11 fresh proof; no byte repair. |
| LOCAL_BEHIND | Authority and IBCS agree N; local N-1 with verified complete receipt/Audit N and no fork | Keep CLOSED; same-ID replay exact receipt and idempotent local Audit, recompare. Missing audit/staged proof quarantines. |
| LOCAL_AHEAD | Local and Authority agree signed terminal N, IBCS N-1, Authority is durably `PENDING_CHECKPOINT` and exact predecessor is known | Keep CLOSED; publish **the same** N by IBCS CAS only after fresh local/Authority proof. Otherwise quarantine. |
| AUTHORITY_BEHIND | IBCS and local show verified later N but Authority DB is older/missing terminal | QUARANTINE; prove restore/DR from independent dossier. IBCS/Core do not reconstruct Authority ledger. |
| IBCS_BEHIND | Authority and local agree signed terminal N, IBCS N-1 | Same as LOCAL_AHEAD **only** with durable pending-publication ID, exact signed proof and CAS predecessor; an unexplained gap is QUARANTINE. |
| DIVERGENT | Equal sequence with different hash, two GENESIS IDs, wrong generation/storage/owner/audit, forked predecessor or two current token claims | QUARANTINE; preserve evidence, manual signed recovery only. |
| UNKNOWN | Any source unavailable, unsigned, stale nonce, incomplete history or indeterminate local business effect | Read-only RECONCILIATION_REQUIRED; no terminal invention, no write/lease/new GENESIS. |

Never use `max(sequence)`, cache, DB name, hostname, Core clone contents or
test fixture to select the winner. A legitimate restore/hardware migration
changes storage generation/epoch and sole token only through signed Authority
recovery + IBCS CAS; manual Authority DR uses Root-signed dossier/new
instance/generation/key. A stale clone has no such authorization and cannot
self-activate. Whole-host test-only snapshot uncertainty is explicitly
outside the same-host isolation claim in §5 and remains CLOSED pending
off-host operator maximum.

## 14. P1-F: one atomic terminal and a two-sided local decision reservation

`ABORT_PENDING` is a **request to stop local success and reconcile**, not an
ABORTED terminal. `COMMIT_RESERVED` is a durable local fence reserving the
same exact attempt/version for COMMIT; neither alone is Authority truth.
For both preactivation GENESIS and postactivation canonical operations, Core
must serialize these decisions on the same durable local attempt row with a
conditional transition from PREPARED. A proven local business COMMIT makes
ABORT ineligible; an unknown local result stays fenced. Core fresh verifier
signs exact attempt/wire, local row version, decision reservation/fence ID,
committed-result/no-success proof, Audit candidate, Authority Ack and IBCS
predecessor. It never treats memory/caller assertions as proof.

To request COMMIT, Core first durably CAS-reserves `COMMIT_RESERVED` under its
local row lock; a concurrent ABORT_PENDING CAS from PREPARED must fail. It
submits signed reservation/version and exact frozen COMMIT authorization to
Authority. Authority locks generation/head → continuity → operation, checks
same-ID PREPARED/receipt absence and current state, and durably records a
matching `COMMIT_RESERVATION` **without allocating terminal sequence**. The
same Authority operation row lock serializes reservation, cancellation,
COMMIT proposal/finalize and ABORT. Authority COMMIT proposal/finalize
requires that unrevoked reservation ID/version, exact local proof and current
eligibility; the terminal transaction conditionally changes that row to
COMMITTED, signs/persists the sole terminal and closes admission pending IBCS.

If ABORT is requested while COMMIT_RESERVED exists, Core **cannot** simply
set ABORT_PENDING. It queries Authority under the same ID. If Authority
COMMITTED, Core reconciles COMMITTED. If Authority remains PREPARED with
matching reservation, an authenticated cancellation request must first
atomically invalidate the Authority COMMIT_RESERVATION under its operation
lock, with an exact signed cancellation proof; it is rejected if COMMIT has
already won or a terminal proposal is in progress. Only after verifying
that proof can Core CAS its matching local reservation version to
ABORT_PENDING, complete §7's fresh no-success check and send Root/creator
ABORT authorization. Authority ABORT under the **same** operation row lock
checks cancellation version, PREPARED, no COMMITTED terminal, full scope/
generation/epoch and authorization, then conditionally writes one ABORTED
bootstrap terminal or canonical receipt. A stale COMMIT reservation cannot
be reused after cancellation. If cancellation/proposal/DB result is UNKNOWN,
both sides remain fenced and query same ID; no time-based release.

An ABORT_PENDING acquired *first* from PREPARED prevents local COMMIT
reservation. Authority can ABORT only after fresh signed local proof and its
own same-row CAS; a stale COMMIT without a valid reservation fails. If
COMMIT or ABORT wins Authority's one terminal CAS, historical same-ID lookup
returns **the exact signed winner**. Core convergence rules:

- COMMITTED winner: validate receipt/bootstrap marker and frozen effect;
  never publish ABORTED. If local ABORT_PENDING is observed because an
  earlier response was lost or a legacy/inconsistent projection exists,
  clear it **only** under exact signed winner proof and locked local audit/
  state reconciliation. A contradictory already committed local abort
  projection is QUARANTINED, not overwritten.
- ABORTED winner: never perform/publish a local business COMMIT. Pre-GENESIS
  publish signed bootstrap ABORT and IBCS bootstrap head; post-GENESIS
  publish canonical ABORTED receipt/Audit and IBCS canonical head. If a
  local business COMMIT is actually proven, this is a contract violation and
  QUARANTINED; do not pretend the business effect vanished.
- UNKNOWN/unreachable: local fence stays durable, Authority admission and
  Core writes remain CLOSED. Query both Authority terminal and IBCS; no
  second terminal ID, auto-abort or assumption that timeout means failure.

Authority uses the existing F3 single-transaction signer/proposal/finalize
pattern under the operation lock; only one terminal row/receipt hash can be
committed. A proposal or reservation is not a terminal. Connection loss
before DB commit consumes no sequence; response loss after commit is resolved
by exact same-ID query. `COMMIT_RESERVED` changes internal eligibility but
does not alter the frozen request/authorization bytes or authorize an
unauthenticated runtime to force a decision.

## 15. F race outcomes (terminal truth and local convergence)

| Race | Authority atomic winner | Core result / IBCS publication |
| --- | --- | --- |
| F1 ABORT_PENDING first; Authority PREPARED | ABORT after fresh no-success proof and op-lock CAS; stale COMMIT reservation absent | Local ABORTED historical state; bootstrap or canonical ABORT high-water per namespace; admission CLOSED until confirmed. |
| F2 local ABORT_PENDING observed but Authority already COMMITTED | Signed COMMITTED terminal is verified; ABORT CAS rejects | Reconcile COMMITTED under locked local proof; contradictory prior local ABORTED quarantines. Publish COMMIT high-water. |
| F3 concurrent, COMMIT obtains operation lock/terminal CAS first | COMMITTED only | Exact receipt/marker replay; no ABORTED evidence; pending checkpoint fence. |
| F4 concurrent, ABORT cancellation/terminal CAS first | ABORTED only | COMMIT reservation invalid; no business COMMIT; namespace-specific IBCS successor. |
| F5 terminal response lost | Same-ID signed winner returned, never re-sign | Idempotent local replay/IBCS republish exact publication ID; no new operation. |
| F6 Core crashes in ABORT_PENDING, Authority COMMITTED | COMMITTED historical winner | Restart queries same ID, verifies winner and local proof, converges or quarantines contradiction. |
| F7 Core ABORT_PENDING, Authority unavailable/UNKNOWN | None inferred | Stay fenced/read-only; no auto-abort, new GENESIS or canonical N+1. |

If a cancellation and COMMIT finalization race, the same Authority operation
lock yields one signed reservation-cancel or one terminal COMMIT. Only the
former permits local ABORT_PENDING; only the latter permits COMMITTED replay.
No two-sided “both eventually win” path is admitted. A randomized race test
must inspect both DB terminal row/receipt and Core/IBCS state, not merely HTTP
errors.

## 16. Ordinary receipt crash/retry matrix

| Case | Authority/local/IBCS observed facts | Recovery and admission |
| --- | --- | --- |
| E1 Authority COMMIT succeeds, Core response lost | Authority signed terminal N and `PENDING_CHECKPOINT`; local N-1 | Same-ID read signed N; append local receipt/Audit once. CLOSED. |
| E2 Core receipt/Audit N persisted, crash before IBCS | Authority/local N, IBCS N-1 | Same deterministic publication ID/CAS; no N+1. CLOSED. |
| E3 IBCS CAS N succeeded, response lost | IBCS signed N; Authority/local N pending | Read by publication ID/nonce and verify exact bytes; no second append; reopen only after fresh match. |
| E4 IBCS publish fails/UNKNOWN | Signed Authority/local N, IBCS unverified/N-1 | Terminal N remains real; same-ID query/republish; CLOSED. |
| E5 IBCS N confirmed, Core READY/admission update fails | Three heads N but local readiness/publisher state pending | Replay staged READY/Authority OPEN proof handshake; CLOSED until fresh effective proof. |
| E6 receipt N confirmed, terminal N+1 local, IBCS still N | Authority/local N+1 with durable pending ID | Publish exact N+1 in order; N+2 denied. |
| E7 Core local N, IBCS N+1 | Authority/IBCS N+1 must agree by signed lineage | LOCAL_BEHIND: same-ID replay exact N+1/Audit; if missing stage proof, quarantine. |
| E8 Core local N+1, IBCS N | Authority signed N+1 and pending ID required | IBCS_BEHIND: CAS-publish exact successor; unexplained gap quarantines. |
| E9 same sequence, different receipt/head | Any two sources disagree on hash/GENESIS/scope | DIVERGENT QUARANTINE; no publication or write. |
| E10 republish same signed terminal | Deterministic publication ID/exact bytes | IBCS returns byte-identical prior proof; no new record/sequence. |

Each case includes normal canonical COMMITTED **and** canonical ABORTED
terminal receipts. A bootstrap GENESIS ABORT uses the same exact-ID
publication/response-loss rule but moves bootstrap event head while canonical
sequence remains 0. If neither Authority nor local result is provable,
UNKNOWN stays fenced and is not resolved by a numeric maximum.

## 17. Unified state transitions after canonical receipt #1

| From → to | Actor / prerequisite | Durable Authority/Core/IBCS effect | Retry/crash and write eligibility |
| --- | --- | --- | --- |
| READY/ADMISSION_OPEN → OPERATION_PREPARED | Authenticated creator, current lease/owner/token/IBCS proof; frozen INTENT | Authority PREPARED Ack, Core durable INTENT/Ack; no terminal N yet | Same-ID PREPARED replay; normal writes still subject unresolved-operation barrier. |
| OPERATION_PREPARED → COMMIT_RESERVED or ABORT_PENDING | Core same-row CAS, fresh local result and signed proof | Authority matching reservation/cancellation under same op lock; no sequence yet | UNKNOWN stays fenced; no opposite decision until signed cancellation. |
| Reserved/fenced → AUTHORITY_TERMINAL_PENDING_CHECKPOINT | Exact authorization and one Authority terminal CAS | Signed COMMITTED/ABORTED receipt N, head/sequence/effect, durable domain admission CLOSED in one transaction | Lost POST same-ID query; N+1 DENIED. |
| AUTHORITY_TERMINAL_PENDING_CHECKPOINT → LOCAL_RECEIPT_PERSISTED | Verified signed terminal and frozen Audit candidate | Core Audit/receipt/checkpoint N idempotently appended, write-closed | Crash resumes exact receipt; no new terminal. |
| LOCAL_RECEIPT_PERSISTED → IBCS_HIGH_WATER_PENDING | Authority publisher/previous checkpoint N-1 | Exact deterministic publication ID and signed successor proof requested | IBCS outage leaves CLOSED; no pipelining. |
| IBCS_HIGH_WATER_PENDING → IBCS_HIGH_WATER_CONFIRMED | IBCS one domain-wide CAS, Authority/Core verify same N | Immutable signed IBCS N, renewed sole token scoped to N | Lost response reads same ID; no second publication. |
| IBCS_HIGH_WATER_CONFIRMED → ADMISSION_CONTINUES | Fresh Core READY, Authority/IBCS/local exact match and current request-bound proof | Authority staged/open CAS; effective Core READY gate revalidated | Only now N+1 eligible, if operation-specific owner/lease/recovery fence also passes. |
| Any stage → RECONCILIATION_REQUIRED / QUARANTINED | Missing/ambiguous or contradictory proof | Preserve actual terminal and local facts; never synthesize alternate state | Read-only same-ID proof recovery or manual signed recovery; writes DENIED. |

An ABORTED canonical terminal progresses through the same N checkpoint
states, preserving business state version but advancing Audit/Authority head.
Governance recovery may keep ADMISSION CLOSED after IBCS confirmation until
its separately signed owner/storage/epoch activation requirements pass. R1
checkpoint publication is necessary, not sufficient, for a lease or write.

## 18. Directed signature dependency and test obligations

The dependency is strictly directed:

```text
signed origin / Root-authorized keys
  -> Authority bootstrap PREPARE event/Ack
  -> IBCS bootstrap PREPARE checkpoint proof
  -> Core locally bound PREPARED
  -> Authority terminal COMMITTED receipt #1 (binds prior bootstrap head)
  -> bootstrap COMMITTED marker (references already computed receipt hash)
  -> Core local receipt/Audit #1
  -> IBCS canonical/bootstrap successor proof
  -> current incarnation/READY admission proof
  -> next canonical PREPARE/terminal receipt N
  -> Core local immutable receipt/Audit N
  -> IBCS successor proof N
  -> refreshed admission proof for N+1
```

The bootstrap COMMITTED marker is persisted in the same Authority terminal
transaction as receipt #1 but computed **after** that hash; neither the
receipt nor its seed requires the final marker/IBCS future hash. Ordinary
receipt N binds predecessor N-1 and frozen PREPARE; Core Audit N is derived
from verified receipt/effect, IBCS N signs both, and admission proof references
IBCS N. No receipt is asked to sign its own later checkpoint; no future
IBCS proof is needed to calculate the already committed receipt hash.

Design-to-implementation tests include T1–T40 from the user approvals:
real test-only IBCS process/credential/store/endpoint isolation; targeted
Core DB clone without IBCS; outage/rollback/tamper; strict N/N+1 fence;
idempotent lost-response republish; same sequence/different hash quarantine;
all E1–E10, F1–F7, 100+ randomized COMMIT/ABORT races with **one** terminal
truth; bootstrap ABORT leaves canonical empty; canonical ABORTED and
COMMITTED both advance IBCS; legitimate signed new storage generation and
manual DR lineage; exact receipt #1 remains COMMITTED GENESIS. Unit synthetic
keys may validate primitives but do not substitute for actual isolated
process/PostgreSQL/role/clone/negative evidence after Design PASS.

## 19. Independent review and implementation gate

At least two independent Reviewers, neither an author of Revision 4, must
separately inspect (A) IBCS/trust/high-water/clone/recovery and (B) terminal
COMMIT–ABORT race/admission/ledger namespaces. Both must mark OLD P1-C,
NEW P1-E and NEW P1-F CLOSED, confirm P1-A/B/D did not regress, confirm no
receipt #1 relaxation or hash/signature cycle, and check F1/F2/F3/F9,
Coordinator and signed-intent compatibility. P0/P1/P2/OPEN/PARTIAL keeps
DESIGN BLOCKED. Design PASS means a reviewed, testable **contract**, not a
fabricated claim that an IBCS process already exists. This division follows
the user's explicit rule that actual test-only IBCS process/storage/identity
evidence is required in implementation, after Design Gate PASS.

If Design PASS, the user's existing authority allows product implementation
without another request. Code must implement actual protected IBCS adapter/
deployment profile and preflight, local intent/locked proof, schema and narrow
SQL procedures, bootstrap validators, canonical anchor, admission fence,
ordinary N checkpoint publication, the COMMIT reservation/ABORT CAS protocol,
startup recovery, T1–T40 tests and docs. If no independently provisioned
test-only IBCS target exists at implementation time,
actual implementation/acceptance remains blocked rather than using a cloned
local substitute. Implementation then receives independent A/B/C review and
at most two targeted rework rounds. `R1-MARATHON-C01` closes only after DESIGN,
IMPLEMENTATION, reviewer and relevant test gates PASS. Signed final Migration
Intent, formal PostgreSQL Acceptance and Foundation Closure remain separate
later gates.
