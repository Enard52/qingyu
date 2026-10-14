# Control Plane R1 C01 — GENESIS / IBCS / Canonical Receipt Contract, Revision 5

Status: **DESIGN CANDIDATE / independent Reviewer A/B/C pending**. Revision 5
is a formal replacement candidate for the C01 high-water/terminal portions of
Revision 4, not an implemented IBCS, a migration authorization, production
disaster-tolerance claim, or R1 Implementation Gate PASS. Prior P1-A/B/D and
F1/F2/F3/F4/F9/Windows Identity frozen scoped PASS remain inherited. In any
conflict this candidate cannot silently rewrite a proven historical artifact;
actual implementation must be separately reviewed.

Normative model inputs, read **before** this contract:
`docs/evidence/r1-acceptance-marathon/revision5_formal_model_spec.md`,
`revision5_state_model.py`, `revision5_model_result.md`. Reviewers must first
accept the four-domain fault boundary; a model PASS alone is not proof.

## 1. Fault boundary and exact security claim

Trust domains are (A) cloneable Core Local DB/process, (B) Authority signed
terminal/confirmation PostgreSQL ledger, (C) isolated IBCS service/DB/read
signer, and (D) protected Operator/Root domain holding pins and a **distinct,
non-Root IBCS certificate issuer maximum/active-instance witness**. Each A–C
may crash, lose response, partition, become stale or suffer a **single-domain**
snapshot rollback/clone while the other trust domains retain observations.
The protected service credentials and Operator witness are not in the A/C
cloneable volumes. A rollback of the entire host, all four domains, or forged
Operator/SCM identity is **OUT OF R1 THREAT MODEL**. Test-only same-host
isolation proves targeted IBCS/Core/Authority volume/process independence,
not production off-host resilience; production requires a separate protected
Operator/off-host witness and ceremony, never promotion of acceptance Root.

R1 refuses ACTIVE/write on any pairwise mismatch, unavailable fresh proof,
unknown terminal, copied Core incarnation or competing IBCS process. For
IBCS N behind independently recorded issuer maximum N, the protocol detects
a **dangerous divergence** and quarantines, but cannot identify whether the
certificate was issued then lost before IBCS persistence or persisted then
rolled back. It must not call that state proved rollback or safely re-create
N. Authority `PUBLICATION_CONFIRMED(N)` with IBCS fresh N-1 **does** prove
IBCS rollback/divergence after completed confirmed publication. If the user
requires exact historical classification of an unconfirmed cross-store
issuance gap, no such guarantee is claimed by this design; the gap is fenced
and needs an independently authorized recovery dossier. No R1 action picks
the largest numeric sequence or reconstructs Authority history from Core.

## 2. Fixed identities, signers and artifact schemas

All artifacts use versioned canonical encoding, pinned domain/profile/key IDs,
exact UUID continuity/operation IDs, key rotations only by separately signed
lineage, signature verification before state use, and no caller-controlled
origin or self-claimed role. `continuity_alias` never grants identity. Secret
key bytes, passphrase and DSNs are absent from reports/Git/Core.

| Artifact | Required immutable or challenged fields | Signing identity and semantics |
| --- | --- | --- |
| `AuthorityTerminalV1` | Actual F3 direct scope, request hash, result/staged hash, commit Audit candidate, receipt sequence/predecessor, state/result; ABORT selected Audit indirect via frozen abort_result/result hash | Existing Authority receipt key; immutable, exact historical replay. Do **not** claim it directly signs final Core state/Audit sequence, `local_commit_id` or transaction evidence. |
| `AuthorityTerminalBindingV2` companion | hash of complete signed V1; domain/generation/identity/continuity/op/receipt seq; exact selected COMMIT **or ABORT** pre-frozen Audit record hash and expected/new state version; result/state transition hash; local_commit_id and authorization/transaction evidence hash; relevant owner/storage/epoch generations | Preprovisioned Authority terminal-binding signer. Signed/persisted in the **same Authority terminal transaction** after V1 hash computation and before final commit. No final Core receipt/IBCS/confirmation hash. Missing V2 means C01 publication DENIED, not guessed from V1. |
| `CorePersistedBindingAttestationV1` | query nonce/identity; V1/V2 hash, exact persisted signed receipt bytes hash, selected immutable Audit row bytes/hash/sequence/head, state version/result, DB cluster/continuity/storage/owner generation, process incarnation, timestamp/expiry | Protected Core service observation signer; fresh challenged read of committed local rows. It establishes *which bytes Core now holds*, not independent canonical Authority truth. IBCS verifies exact bytes against V2 and signed Authority predecessor before accepting it. |
| `CoreBindingSnapshotV1` | stable canonical tuple of the attestation's persistence fields **excluding** nonce/signature/time; selected Audit/state/receipt hashes, DB generation/incarnation | Deterministic hash from verified challenged attestation and local bytes. Certificate binds this stable hash, so retry with a new nonce does not mutate a historical certificate. |
| `PublicationCertificateV1` | deterministic publication_id; Authority domain/generation; continuity/receipt seq/hash/head; terminal V1/V2 hashes; selected Audit seq/hash and Core snapshot hash; state/owner/storage generations; active Core incarnation; predecessor cert hash; IBCS seq/generation, key ID/version | **One** preprovisioned `IBCS CertificateKey` held by protected Operator issuer service, invoked only by authenticated IBCS runtime. Ed25519 signed canonical body; complete signed bytes are immutable. No issue nonce/time, witness-record hash or future Authority confirmation is inside certificate. |
| `IssuerMaximumV1` | IBCS domain/generation, publication ID/seq, SHA-256 of **complete signed PublicationCertificate bytes**, previous issuer-record hash, issuer key ID | Distinct Operator witness-ledger key. Issuer signs cert first, then record/hash, append + `FlushFileBuffers` before returning cert. Same ID returns original exact bytes; conflicting hash/seq quarantines. |
| `FreshnessAttestationV1` + `ServiceInstanceAttestationV1` | same caller nonce/query ID, current publication ID/IBCS seq/cert hash, IBCS generation; witness issuer seq/hash, SCM service process incarnation/session and current singleton status | IBCS read signer + independent Operator witness signer respectively. Both freshly sign same challenge; old nonce, expiry, generation, process mismatch or competing claimant rejects. Never substituted by immutable certificate bytes. |
| `AuthorityPublicationConfirmationV1` | publication_id, IBCS seq/cert hash, continuity/canonical seq/head, predecessor confirmed hash, Authority domain/generation and verification time | Durable Authority ledger record under Authority owner, externally signed when consumed by Core. Only after exact cert + fresh pair verification; immutable monotonic confirmation. |
| `AdmissionTokenV1` | nonce/request/session, exact confirmed/certificate/issuer tuple, one Core+IBCS active incarnation, identity/owner/storage/lease/epoch, short expiry | Authority-signed current capability, not historical evidence; Core READY and Authority OPEN use staged handshake and fresh per-request checks. |

Certificate signing dependency is strictly:

```text
frozen operation/request/Audit candidates
 -> Authority V1 signed terminal
 -> Authority V2 companion referencing final V1 hash
 -> Core locally persisted selected receipt/Audit/state
 -> challenged Core observation and stable snapshot hash
 -> IBCS signed PublicationCertificate
 -> Operator signed IssuerMaximum record (hashes finished cert bytes)
 -> IBCS immutable DB persistence
 -> Authority Publication Confirmation
 -> fresh IBCS/Operator read attestation -> scoped admission
```

V2 may be signed in an open Authority terminal transaction, but Core network
read/publish occurs **after** that Authority commit. No earlier artifact hashes
a later signature. V1's legacy ABORT Audit candidate remains the commit
candidate; V2 explicitly binds the *selected* abort Audit hash. This is an
extension for C01, not reinterpretation of current F3 V1.

## 3. Concrete independent witness / IBCS target (design, not deployed)

IBCS: protected `NT SERVICE\QingyuR1IBCSAcceptance`, distinct pinned
TLS/SPKI endpoint, IBCS read signing credential and separate PostgreSQL
instance/container/network/volume `r1_ibcs_acceptance_data` outside Core,
Authority, Gateway and legacy; DB/owner/runtime/read roles distinct and
least-privileged. Authority publishes through authenticated append API; Core
queries through read-only API. Neither receives IBCS owner/key/DB credential.

Operator issuer: separate protected
`NT SERVICE\QingyuR1IBCSIssuerAcceptance`, dedicated non-Root certificate
signer/witness signer keys, append-only signed journal under
`C:\ProgramData\QingyuR1IBCSIssuerAcceptance`, outside Git and all Docker
volumes. Exact file/SID/ACL/ownership/flush/restart/protected backup, no
accidental Root custody access, system/volume markers and hostile role tests
must be proven in real implementation. The issuer witness owns a singleton
IBCS **active-process incarnation register**: protected SCM process identity,
image pin, fresh startup challenge/session; second claimant durably records a
fork and quarantines. Every fresh IBCS read needs same-nonce witness-signed
instance evidence; a same-watermark cloned IBCS DB/read key alone cannot gain
admission. Whole-host or forged Operator identity is out of the single-domain
claim. Missing issuer/witness proof fails closed; acceptance host never
trust-on-first-use generates any Root or production key.

## 4. Bootstrap and canonical state machines

Bootstrap attempt ledger and canonical receipt ledger are separate. `GENESIS
PREPARED` is anchored externally before Ack. A valid failed attempt becomes
`GENESIS_ATTEMPT_ABORTED` in the immutable ordered bootstrap ledger and never
occupies canonical receipt #1. New GENESIS attempt uses a **new opaque attempt
ID** only after bootstrap abort retention and single domain admission
reconciliation. A successful GENESIS terminal creates **COMMITTED GENESIS
receipt #1**, identity/continuity 1:1 and the bootstrap COMMITTED marker in
one Authority terminal transaction; Core and IBCS publication then follow
the **same canonical pipeline** as every later receipt.

For ordinary mutation, Authority `PREPARED -> one signed COMMITTED | ABORTED`
under same operation-row terminal CAS. Canonical ABORTED after GENESIS is a
real receipt N: advances Authority/Audit/IBCS head but not business version.
No PREPARE/timeout/HTTP error allocates a terminal sequence. An immutable
terminal is never rewritten or re-signed. Admission is closed atomically with
terminal N and cannot reopen before `PUBLICATION_CONFIRMED(N)` plus fresh
reconciliation. Strict serial fence: no new canonical mutation N+1 while N
terminal exists but publication is pending/unconfirmed. No pipeline window.

| State | Durable fact / only allowed successor | Crash/retry admission |
| --- | --- | --- |
| `PREPARED` | exact frozen INTENT/Ack and bootstrap or active predecessor; local decision gate may claim COMMIT or ABORT once | CLOSED for unresolved operation; same ID only |
| `COMMIT_DISPATCHED` | same-row Core CAS persists exact COMMIT auth bytes; Authority same-ID terminal query/dispatch; may converge either Authority winner | no opposite local choice; CLOSED |
| `ABORT_PENDING` | same-row Core CAS persists exact ABORT auth bytes/no-success proof; Authority same-ID query/dispatch; may converge either winner | not an ABORTED fact; CLOSED |
| `TERMINAL_RECONCILIATION` | signed Authority terminal/V2 winner verified, one local row-locked selected Audit/state/receipt finalize | UNKNOWN keeps CLOSED; no synthesized winner |
| `AUTHORITY_TERMINAL_PENDING_PUBLICATION(N)` | V1/V2 and sequence/head durable in one Authority txn, domain admission CLOSED | N+1 denied; POST non-200 -> GET same ID |
| `CORE_BINDING_PERSISTED(N)` | exact selected local Audit/receipt/state and signed challenged read, stable snapshot digest | N+1 denied; same ID replay |
| `ISSUER_RECORDED(N)` | complete signed immutable certificate hash in independently flushed witness | if IBCS N-1 after restart: ambiguous QUARANTINE; no auto manufacture |
| `IBCS_CERTIFICATE_PERSISTED(N)` | IBCS predecessor CAS stores original certificate bytes, no duplicate sequence | lost response queries cert by ID + new nonce freshness pair |
| `AUTHORITY_PUBLICATION_CONFIRMED(N)` | exact cert hash/seq and predecessor durable in Authority ledger | Core/Authority/IBCS/issuer fresh comparison still needed |
| `ADMISSION_STAGED -> READY/OPEN` | Core effective READY last; Authority OPEN CAS based on fresh protected proof/token | only then N+1 eligible; lease/owner/storage predicates still needed |
| `UNKNOWN` / `QUARANTINED` | no inferred FAILED/current or local reconstruction | CLOSED, inspector reason preserved; authorized manual dossier only |

IBCS bootstrap PREPARE/ABORT events also use the one domain-wide signed
append/head with a separate bootstrap high-water dimension. They do not enter
canonical sequence. A bootstrap or canonical event cannot bypass signed
Authority origin, protected publisher or IBCS predecessor CAS.

## 5. Atomic Core local decision / business-effect gate

All COMMIT senders, Force Abort paths, local business-effect finalize and
selected Audit/receipt publication compete on the **same durable operation
row**, version and lock order. COMMIT dispatch transaction:

1. Lock exact operation row in Core local DB; fresh verify still PREPARED,
   frozen request/result/Audit/lease/owner/admission evidence and no terminal.
2. Compare-and-swap `PREPARED -> COMMIT_DISPATCHED`; persist exact commit
   authorization/transaction identity and decision version.
3. Commit this local transaction. **Only then** may network code POST COMMIT.

Abort transaction uses the identical row/lock/predicate, a fresh signed
no-local-success observation and explicit authorized scope, CAS
`PREPARED -> ABORT_PENDING`, persists exact abort bytes/version, then commits
before POST ABORT. A winner blocks the opposite local CAS even across
processes/restarts; Python locks/timestamps/call order are not proofs. Never
hold a Core DB transaction across a network request.

An Authority signed terminal is the unique final winner, including when it
opposes Core's claimed dispatch. Core GETs the exact ID after any ambiguous
POST; it transitions under the same local row lock into
`TERMINAL_RECONCILIATION(winner)`. Only that row-locked finalize transaction
may turn invisible staged business bytes into a committed effect, and only
for a verified Authority **COMMITTED** V1/V2 outcome with exact frozen Audit
and expected state. It rechecks decision version/fence at **commit time**;
`ABORT_PENDING` is never a permission for an independent COMMIT sender but
may be superseded by already-established signed Authority COMMITTED truth in
this single reconciliation transaction. For Authority ABORTED, selected abort
Audit is published and business state version remains unchanged, even if
local choice was COMMIT_DISPATCHED. A contradictory later local effect or
Audit/receipt fork quarantines; local projection never overwrites terminal.

Current F3 already performs one local row-locked finalize but has no same-row
pre-network decision gate, and its `requested_decision` check rejects opposite
Authority outcome. Revision 5 implementation **must explicitly change that
bounded behavior** with impact regression; it must not claim current F3 code
already satisfies D5/D6 or silently relax existing authentication/immutability.

## 6. Publication, confirmation, rollback and admission algorithm

For every COMMITTED/ABORTED canonical N (GENESIS #1 included):

1. Authority terminal V1/V2 commits and closes domain admission in one txn.
2. Core row-locked finalize persists exact signed terminal, selected immutable
   Audit/state and returns a protected challenge-signed observation; Authority
   publisher and IBCS independently verify bytes against V2 and predecessor.
3. IBCS validates immutable publication body/predecessor, asks protected
   issuer to sign the exact deterministic certificate. Issuer records full
   signed cert hash/seq in its **independent flushed maximum** before return.
4. IBCS CAS persists those **unchanged** signed bytes against one domain-wide
   predecessor; same publication ID/exact bytes reads the original cert.
   Unknown response -> query original cert ID with a **new** nonce; never
   require old FreshnessAttestation bytes to replay.
5. Authority fresh-verifies certificate, IBCS/Operator same-nonce attestations,
   signed terminal/Core binding and exact predecessor; Authority durable
   `PUBLICATION_CONFIRMED(N)` ledger CAS. Response loss -> same-ID query; no
   second confirmation or certificate.
6. Core obtains fresh Authority confirmed read, fresh IBCS/Operator paired
   nonce read and its own protected local state. Compare exact identity,
   generations, head hashes, certificate/witness/confirmation hashes and
   sole incarnations. Stage READY/OPEN then publish effective Core READY last,
   Authority OPEN via bound proof. Every later request rechecks token/current
   heads, not a one-time booleans. Any failure leaves CLOSED.

| Observed facts | Classification / action |
| --- | --- |
| issuer N-1, IBCS N-1, Authority confirmed N-1, terminal N pending | **NEVER ISSUED / incomplete publication**, no claim that a network attempt proved absence; exact signed terminal/ID may be retried only after fresh predecessor and no issuer N proof |
| issuer >=N, IBCS N-1, confirmed N-1 | **ISSUANCE GAP OR UNCONFIRMED ROLLBACK / QUARANTINE**; no automatic certificate recreation, even same ID |
| issuer N, IBCS N, confirmed N-1 | IBCS success/response-loss before confirmation; fetch **original** cert, new fresh query proof, verify; idempotently confirm N |
| issuer N, IBCS N-1, confirmed N | **CONFIRMED IBCS ROLLBACK / QUARANTINE**; never CAS-restore from local head |
| confirmed N, IBCS N with different hash or same seq different cert | **FORK / QUARANTINE** |
| IBCS or issuer N > Authority terminal/confirmed N-1 | **AUTHORITY ROLLBACK/DIVERGENCE / QUARANTINE**; no numeric repair |
| Authority/IBCS/issuer confirmed N, Core N-1 or stale Core incarnation | **CORE ROLLBACK/CLONE / CLOSED or QUARANTINE**; exact signed history/read-only recovery only |
| all heads/hash/generations/incarnations exact N, paired nonce proofs valid | eligible to stage admission, never automatically grants lease/owner rights |
| unavailable/missing/stale proof | **UNKNOWN / CLOSED**, not FAILED or CURRENT |

Case 1 is an issuer fact, not a proof that no unsigned network attempt ever
occurred. Case 2 is irreducibly ambiguous without an atomic cross-store commit;
the safety guarantee is denial, not historical classification. Operator
manual recovery requires a separately signed dossier with exact immutable
history, signed witness maximum and new lineage; no Core state manufactures
Authority truth. Authority rollback can be identified against independent
IBCS/issuer head; globally consistent four-domain rollback is excluded.

## 7. Crash/retry/decision matrix

| ID | Interruption/race | Required restart/reconciliation |
| --- | --- | --- |
| D1 | PREPARED -> local COMMIT_DISPATCHED committed, crash before POST | GET exact ID, resume **same stored COMMIT bytes** if no terminal; ABORT choice forbidden |
| D2 | PREPARED -> ABORT_PENDING committed, crash before POST | GET exact ID, resume **same stored ABORT bytes** if no terminal; COMMIT choice forbidden |
| D3 | COMMIT POST terminal succeeds, response lost | GET signed COMMITTED same ID; no second terminal |
| D4 | ABORT POST terminal succeeds, response lost | GET signed ABORTED same ID; no second terminal |
| D5 | local ABORT_PENDING but Authority already COMMITTED | signed winner reconciled under same row lock; exact COMMIT effect only if no fork; no independent stale sender |
| D6 | local COMMIT_DISPATCHED but Authority already ABORTED | signed winner reconciled, selected ABORT Audit, unchanged business version |
| D7 | two Core threads claim COMMIT vs ABORT | same SQL operation-row CAS: exactly one choice; losing thread queries winner |
| D8 | two processes/restart claim opposite decisions | same persisted row/version/transaction predicate: exactly one; no Python lock proof |
| E1 | Authority terminal N committed, Core finalize crashes | signed terminal real, admission CLOSED; exact Core same-ID replay |
| E2 | Core binding N committed, issuer not called | N+1 DENY; fresh predecessor and deterministic publish request |
| E3 | issuer N durable, IBCS persist crashes | issuer ahead => ambiguous QUARANTINE on startup, no auto manufacture |
| E4 | IBCS N persists, response lost before Authority confirm | exact cert bytes by ID + new nonce fresh pair; idempotent confirm |
| E5 | confirmation N persists, response lost | exact confirmation GET; no double seq; fresh reconciliation |
| E6 | IBCS N rolls back after confirmed N | signed confirmed vs fresh IBCS head => proved rollback QUARANTINE |
| E7 | IBCS N rolls back before confirmed N after issuer N | issuer ahead => suspected rollback/issuance gap QUARANTINE |
| E8 | Authority N rolls back, independent IBCS/issuer N remains | Authority divergence QUARANTINE, no Core-to-Authority rebuild |
| E9 | Core N rolls back/clone while others N | head/immutable binding/incarnation mismatch; CLOSED/QUARANTINE |
| E10 | network partition/UNKNOWN/duplicate/reorder | CLOSED; same-ID query/retry only with signed proof; no timeout verdict |

Historical replay of terminal/certificate/confirmation is immutable and need
not revalidate an expired write lease to re-state history; a **new** write
does require fresh eligible lease/admission. Bootstrap ABORT retention stays
separate and canonical seq unchanged; post-GENESIS canonical ABORT uses E1–E10.

## 8. Numbered safety invariants

- **INV-01**: canonical receipt #1 is COMMITTED GENESIS, exact immutable ID.
- **INV-02**: preactivation `GENESIS_ATTEMPT_ABORTED` never creates a canonical receipt/identity.
- **INV-03**: each operation has at most one Authority-signed immutable terminal and same ID never re-signs.
- **INV-04**: canonical N+1 cannot start before exact Authority-confirmed IBCS publication N and fresh admission.
- **INV-05**: PublicationCertificate ID/seq/full signed bytes are immutable; duplicate query returns identical bytes.
- **INV-06**: Freshness/ServiceInstance attestations bind current caller nonce and are non-replayable across nonces.
- **INV-07**: Authority confirmed head vs fresh IBCS/issuer/head or any pairwise mismatch closes admission.
- **INV-08**: same IBCS sequence with different certificate hash or predecessor is QUARANTINE.
- **INV-09**: `COMMIT_DISPATCHED` and `ABORT_PENDING` are exclusive same-row local SQL decisions.
- **INV-10**: local pending choice never overrides signed Authority terminal; local effect only via row-locked winner reconciliation.
- **INV-11**: UNKNOWN/lost response is neither FAILED nor CURRENT; same-ID queries preserve history.
- **INV-12**: Core local state alone cannot detect/approve rollback/clone; independent head and sole-incarnation proof required.
- **INV-13**: issuer-ahead/IBCS-behind unconfirmed ambiguity quarantines, never automatically recreates certificate.
- **INV-14**: signed terminal -> Core binding -> certificate -> confirmation -> fresh admission dependency has no hash/signature cycle.

## 9. Executable model scope and mandatory implementation evidence

The stdlib model/results named at top abstract A/B/C/D heads, local decision,
issuer maximum, two canonical receipts, bootstrap ABORT, admission, Core/IBCS
clone incarnations, fresh nonce, loss/partition/duplicate/restart/rollback and
INV-01–12. Its PASS is necessary design exploration, **not** proof of Windows
SCM uniqueness, flushed witness durability, PostgreSQL row locks, Ed25519,
signed deployment pins or actual volume separation. Reviewers must inspect
both its transition guards and what it omits. `INV-13/14` require directed
dependency/ambiguity review in addition to model assertions.

After Design PASS only, implementation acceptance must run real protected
test-only IBCS and Operator issuer processes with independent credentials,
IBCS storage, Core durable store, Authority test-only PostgreSQL, actual
same-row cross-process COMMIT/ABORT races, crash/restart, targeted single
IBCS-volume rollback, same-head IBCS clone negative claim, Core clone, exact
ACL/ownership/grants/search_path/default privilege negatives, and per-request
nonce replay negatives. Mocks/synthetic keys may supplement, never replace
these. This is **not** formal PostgreSQL Acceptance or migration execution.

Required tests: R5-01 immutable cert replay; 02 different valid freshness
nonces same cert hash; 03 old nonce reject; 04 confirmed IBCS rollback; 05
never-issued vs issuer-ahead ambiguity; 06 lost cert response/confirm; 07
Authority rollback; 08 same seq/different hash; 09 terminal selected
Audit/state mismatch; 10 Core persisted bytes altered; 11 thread and 12
process decision race; 13/14 pre-network crash decision persistence; 15/16
opposite Authority winner convergence; 17 unconfirmed N denies N+1; 18
exact confirmed/fresh N admits N+1 only with other predicates; 19 stale Core
clone; 20 IBCS outage. Add witness flush-failure, issuer-before-IBCS crash,
same-watermark IBCS clone, signer-key isolation and cryptographic signature
negative tests. Full existing regression and separate independent
implementation Review A/B/C are required after implementation.

## 10. Independent Design Gate

Three independent reviewers who did not author this Revision 5 or its model:

- A: fault model/IBCS certificate vs freshness, issuer/confirmation rollback,
  cloned IBCS process and actual test-only boundary.
- B: actual F3 V1 fields, V2 selected Audit/state trust chain, protected Core
  observation vs Authority truth, exact bytes and acyclic signing.
- C: Core same-row decision/business finalize, Authority terminal arbitration,
  D1–D8/E1–E10, strict N+1 publication fence.

Each first accepts or rejects §1 fault model, then independently reads schema,
tables, executable source/result and source F3 contracts. OLD P1-C and NEW
P1-E/F must be CLOSED; P1-A/B/D remain CLOSED; any P0/P1/P2/OPEN/PARTIAL
means **DESIGN BLOCKED / STOP / no product code**. Only A/B/C all PASS permits
automatic C01 implementation, tests and separate implementation Review. Even
C01 implementation PASS is not R1 Gate/Foundation Closure; resume Marathon
next DAG phase only after independent implementation evidence closes C01.
