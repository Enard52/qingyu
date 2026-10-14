# Control Plane R1 Minimal Trust Model

Status: **DESIGN CANDIDATE** / independent Reviewer A/B/C pending. This is the
R1 scope pivot in ADR R1-007, not Revision 7. Revision 1–6 remains immutable
failed-design evidence and has no runtime correctness role. Product code,
migrations, Candidate Freeze and PostgreSQL Acceptance remain blocked until all
design reviewers report PASS with no P0/P1/P2, OPEN or PARTIAL finding.

## 1. Claim and non-claim

R1 claims only: a verified `AuthorityTerminalCertificateV2` is canonical
operation truth; Core cannot replace it with local inference; an immutable
authorized terminal decision is durable before PREPARE; a versioned CAS on one
durable Core operation row selects COMMIT or ABORT dispatch exactly once before
the network call; finalization validates identity, owner, lease, epoch, state
version and both generation fences; exact request/authorization/effect/Audit/
state semantics are Authority-bound; same-ID crash/retry is deterministic;
UNKNOWN stays fenced; and every service process start requires explicit operator
re-admission before write authority is enabled.

R1 does **not** claim automatic clone, Core rollback or Authority rollback
detection, snapshot auto-activation, cross-machine monotonicity, Byzantine
rollback detection or multi-domain consensus. R1 has no IBCS, witness-consensus
or transparency-log runtime dependency. Those properties are deferred beyond
R1; a later phase must first evaluate a mature external transparency log,
consensus-backed witness, managed monotonic service or append-only ledger.

## 2. Canonical primitives and rejection rules

| Alias | Exact accepted value |
|---|---|
| `UUID` | lowercase RFC 4122 canonical text |
| `H256` | exactly 64 lowercase hexadecimal characters |
| `B64U` | unpadded canonical base64url; decode/re-encode identical |
| `U53` | JSON integer `0..9007199254740991`; boolean is not integer |
| `POS` | JSON integer `1..9007199254740991` |
| `TEXT256` | Unicode scalar string, 1–256 UTF-8 bytes, no NUL |
| `TIME` | UTC RFC3339 `YYYY-MM-DDTHH:MM:SS.ffffffZ` |
| `DECISION` | exactly `COMMIT` or `ABORT` |
| `TERMINAL` | exactly `COMMITTED` or `ABORTED` |

Every wire object has exactly the declared fields. Missing, additional or
duplicate names reject. Null, floats, NaN, Infinity, invalid Unicode and binary
JSON values reject. Nested objects obey their exact schema; arrays have the
declared length/order. `JCS(x)` is existing `rfc8785.dumps(x)`: RFC 8785 UTF-8
bytes without BOM. Object source order is irrelevant; JCS order is authoritative.

```text
DS(P,x)   = ASCII(P) || 0x00 || JCS(x)
HASH(P,x) = lowercase_hex(SHA-256(DS(P,x)))
SIGN(P,x) = unpadded_base64url(Ed25519.Sign(private_key, DS(P,x)))
```

Exact prefixes:

```text
QINGYU-R1-AUTHORIZED-DECISION-V2
QINGYU-R1-OPERATOR-OVERRIDE-SCOPE-V1
QINGYU-R1-OPERATOR-OVERRIDE-V1
QINGYU-R1-EFFECT-CANDIDATE-V2
QINGYU-R1-AUDIT-SEMANTIC-V2
QINGYU-R1-STATE-TRANSITION-V2
QINGYU-R1-RECEIPT-BODY-V2
QINGYU-R1-AUTHORITY-TERMINAL-V2
QINGYU-R1-AUDIT-RECORD-V2
QINGYU-R1-FINAL-RECEIPT-V2
QINGYU-R1-LINKED-HEAD-V2
QINGYU-R1-RECOVERY-ADMISSION-V1
```

Unknown protocol/version/domain or wrong field set fails closed. Historical V1
objects retain only their frozen V1 verification rules; no reinterpretation as
V2 is allowed. `ZERO_H256` is exactly 64 ASCII `0` characters and is used only
for the absent predecessor/head at sequence zero; no other sentinel is allowed.

## 3. Exact immutable inputs before PREPARE

Core freezes the request with the existing exact command schema and existing
domain-separated request/payload digests. It commits one operation row holding
the request and following objects before any PREPARE network call.

### 3.1 `AuthorizedDecisionV2`

| Field | Type/value | Field | Type/value |
|---|---|---|---|
| `protocol` | `QINGYU_R1_AUTHORIZED_DECISION` | `version` | integer `2` |
| `decision_id` | `UUID` | `operation_id` | `UUID` |
| `mutation_id` | `TEXT256` | `authorized_decision` | `DECISION` |
| `authorization_kind` | `CALLER_INTENT` or `OPERATOR_RECOVERY_OVERRIDE` | `authorization_principal` | `TEXT256` |
| `authorization_scope_digest` | `H256` | `request_digest` | `H256` |
| `decision_version` | `POS` | `created_at` | Core-observed `TIME` |

The row stores exact JCS bytes and
`HASH(QINGYU-R1-AUTHORIZED-DECISION-V2, object)`. Reusing operation or mutation
ID with different bytes conflicts. Once `prepare_attempted_at` is recorded,
bytes/hash/version/branch are immutable.

Normal calls use `CALLER_INTENT`. An override never edits the original. It adds
a new decision object with a new decision ID, incremented decision version,
kind `OPERATOR_RECOVERY_OVERRIDE`, and this signed authorization:

`OperatorOverrideScopeV1` is the exact JCS array:

```text
["QINGYU_R1_OPERATOR_OVERRIDE_SCOPE",1,operation_id,
 supersedes_decision_digest,new_authorized_decision,reason,
 authority_domain_id,authority_generation,expected_authority_terminal_hash,
 issued_at,expires_at,operator_key_id]
```

Its hash uses `QINGYU-R1-OPERATOR-OVERRIDE-SCOPE-V1`. That hash is the new
decision object's `authorization_scope_digest`; this scope contains no decision
digest, so the construction is acyclic.

### 3.2 `OperatorOverrideAuthorizationV1Unsigned`

| Field | Type/value | Field | Type/value |
|---|---|---|---|
| `protocol` | `QINGYU_R1_OPERATOR_OVERRIDE` | `version` | integer `1` |
| `override_id` | `UUID`, equals new decision ID | `operation_id` | `UUID` |
| `supersedes_decision_digest` | `H256` | `new_authorized_decision_digest` | `H256` |
| `new_authorized_decision` | `DECISION` | `reason` | `TEXT256` |
| `authority_domain_id` | `UUID` | `authority_generation` | `POS` |
| `expected_authority_terminal_hash` | `H256` | `issued_at` | `TIME` |
| `expires_at` | `TIME`, later than issued | `operator_key_id` | `TEXT256` |

The signed object has exactly that field set plus
`operator_signature:B64U = SIGN(QINGYU-R1-OPERATOR-OVERRIDE-V1, unsigned)`.
Core and Authority verify the frozen Root pin, time window, current Authority
head/generation, both decision digests, and absence of terminal/business effect.
They also recompute the §3.2 scope hash and require exact equality with the new
decision's `authorization_scope_digest`. Same override ID is idempotent only for
identical bytes.

### 3.3 `EffectCandidateV2`

Exactly one candidate corresponds to the effective decision. A valid override
adds a new candidate and never edits the old one.

| Field | Type/value | Field | Type/value |
|---|---|---|---|
| `protocol` | `QINGYU_R1_EFFECT_CANDIDATE` | `version` | integer `2` |
| `operation_id` | `UUID` | `mutation_id` | `TEXT256` |
| `local_commit_id` | `UUID` | `authorized_decision` | `DECISION` |
| `request_digest` | `H256` | `payload_digest` | `H256` |
| `expected_state_version` | `U53` | `resulting_state_version` | `U53` |
| `effect_code` | `APPLY_GOVERNED_MUTATION` or `NO_BUSINESS_EFFECT` | `effect_value_digest` | `H256` |
| `epoch` | `U53` | `storage_generation_id` | `UUID` |
| `control_plane_generation_id` | `UUID` | `owner_version` | `U53` |
| `lease_id` | `UUID` | `lease_generation` | `POS` |
| `session_id` | `UUID` | `canonical_identity_digest` | `H256` |
| `authority_domain_id` | `UUID` | `authority_generation` | `POS` |

COMMIT requires result version = expected + 1, APPLY, and an effect digest
deterministically derived from the frozen request. ABORT requires equal versions,
NO_BUSINESS_EFFECT, and the fixed digest of the exact empty-effect object.
Overflow rejects.

### 3.4 `AuditSemanticCandidateV2`

Exactly one Audit candidate corresponds to the same decision/candidate revision.

| Field | Type/value | Field | Type/value |
|---|---|---|---|
| `protocol` | `QINGYU_R1_AUDIT_SEMANTIC` | `version` | integer `2` |
| `operation_id` | `UUID` | `mutation_id` | `TEXT256` |
| `decision_id` | `UUID` | `authorized_decision` | `DECISION` |
| `terminal_candidate` | `TERMINAL`; COMMIT→COMMITTED, ABORT→ABORTED | `request_digest` | `H256` |
| `payload_digest` | `H256` | `effect_candidate_digest` | `H256` |
| `audit_predecessor_hash` | `H256` | `expected_audit_sequence` | `POS` |
| `expected_state_version` | `U53` | `resulting_state_version` | `U53` |
| `epoch` | `U53` | `storage_generation_id` | `UUID` |
| `control_plane_generation_id` | `UUID` | `owner_version` | `U53` |
| `lease_id` | `UUID` | `lease_generation` | `POS` |
| `session_id` | `UUID` | `actor_principal_id` | `TEXT256` |
| `capability` | `core_governance` | `canonical_identity_digest` | `H256` |

Candidates contain no Authority sequence/predecessor/time/signature, final
Audit digest or final receipt digest.

## 4. Authority semantic validation

PREPARE receives exact request, authorization, effect candidate and Audit
candidate. Authority never signs opaque Core hashes. Under its canonical lock it
exact-schema parses/authenticates; recomputes all domain digests; derives
operation/mutation/identity/continuity/owner/lease/session/epoch/generations,
expected state and Core Audit high-water from its trusted prepared-state record;
derives the only permitted effect/result from frozen command semantics; and
rejects every mismatch, stale fence, unsupported capability, invalid transition
or value it cannot independently validate. It stores exact validated bytes and
digests in PREPARED.

Authority maintains the Core Audit high-water deterministically derived from
the last terminal certificate;
it does not trust a caller head merely because its hash is well-formed. Any
disagreement leaves PREPARE UNKNOWN/fenced for operator investigation.

## 5. Acyclic terminal construction

On terminal dispatch Authority locks the same prepared row/heads, repeats §4
and validates current fences. Terminal normally matches the immutable effective
decision. A different terminal is legal only if already durable before this
Core dispatch or authorized by a valid §3.2 override before terminal/effect.
Authority allocates its sequence/predecessor, then constructs these objects in
one terminal transaction.

### 5.1 `UnsignedReceiptBodyV2`

| Field | Type | Field | Type |
|---|---|---|---|
| `protocol` | `QINGYU_R1_RECEIPT_BODY` | `version` | `2` |
| `authority_domain_id` | `UUID` | `authority_instance_id` | `UUID` |
| `authority_generation` | `POS` | `qingyu_identity_id` | `UUID` |
| `continuity_id` | `UUID` | `operation_id` | `UUID` |
| `mutation_id` | `TEXT256` | `decision_id` | `UUID` |
| `authorized_decision` | `DECISION` | `terminal_decision` | `TERMINAL` |
| `request_digest` | `H256` | `payload_digest` | `H256` |
| `authorized_decision_digest` | `H256` | `local_commit_id` | `UUID` |
| `effect_candidate_digest` | `H256` | `audit_semantic_candidate_digest` | `H256` |
| `expected_state_version` | `U53` | `resulting_state_version` | `U53` |
| `epoch` | `U53` | `storage_generation_id` | `UUID` |
| `control_plane_generation_id` | `UUID` | `owner_version` | `U53` |
| `lease_id` | `UUID` | `lease_generation` | `POS` |
| `session_id` | `UUID` | `canonical_identity_digest` | `H256` |
| `authority_sequence` | `POS` | `previous_authority_terminal_hash` | `H256` |
| `decided_at` | Authority `TIME` | `terminal_key_id` | `TEXT256` |

`receipt_body_digest = HASH(QINGYU-R1-RECEIPT-BODY-V2, body)`.

### 5.2 `StateTransitionTupleV2`

Exact JCS array:

```text
["QINGYU_R1_STATE_TRANSITION",2,operation_id,terminal_decision,
 expected_state_version,resulting_state_version,effect_candidate_digest,
 epoch,storage_generation_id,control_plane_generation_id,owner_version]
```

Its digest uses `QINGYU-R1-STATE-TRANSITION-V2`.

### 5.3 `AuthorityTerminalCertificateV2Unsigned`

| Field | Type | Field | Type |
|---|---|---|---|
| `protocol` | `QINGYU_R1_AUTHORITY_TERMINAL` | `version` | `2` |
| `authority_domain_id` | `UUID` | `authority_instance_id` | `UUID` |
| `authority_generation` | `POS` | `qingyu_identity_id` | `UUID` |
| `continuity_id` | `UUID` | `operation_id` | `UUID` |
| `mutation_id` | `TEXT256` | `decision_id` | `UUID` |
| `authorization_kind` | §3.1 enum | `authorized_decision` | `DECISION` |
| `terminal_decision` | `TERMINAL` | `request_digest` | `H256` |
| `payload_digest` | `H256` | `authorized_decision_digest` | `H256` |
| `local_commit_id` | `UUID` | `effect_candidate_digest` | `H256` |
| `audit_semantic_candidate_digest` | `H256` | `receipt_body_digest` | `H256` |
| `state_transition_digest` | `H256` | `expected_state_version` | `U53` |
| `resulting_state_version` | `U53` | `epoch` | `U53` |
| `storage_generation_id` | `UUID` | `control_plane_generation_id` | `UUID` |
| `owner_version` | `U53` | `lease_id` | `UUID` |
| `lease_generation` | `POS` | `session_id` | `UUID` |
| `canonical_identity_digest` | `H256` | `authority_sequence` | `POS` |
| `previous_authority_terminal_hash` | `H256` | `decided_at` | Authority `TIME` |
| `terminal_key_id` | `TEXT256` |  |  |

Signed certificate = exact unsigned fields plus `terminal_signature:B64U`,
calculated with `SIGN(QINGYU-R1-AUTHORITY-TERMINAL-V2,unsigned)` using the
preprovisioned Authority receipt-key slot. Authority recomputes body/state
digests, then atomically persists certificate, body, terminal, state/head,
sequence, then derives and stores the deterministic Audit record/high-water and
final receipt digest before committing the same transaction. These later
digests are not members of the certificate and therefore do not change its
signature input.
`authority_terminal_hash = HASH(QINGYU-R1-AUTHORITY-TERMINAL-V2,signed_cert)`.

```text
request -> durable authorization -> exact effect/Audit candidate
 -> PREPARED -> Authority sequence/predecessor/time
 -> receipt body/state digest -> signed terminal certificate
 -> deterministic Audit record -> final receipt
```

No body/certificate contains a final Audit or envelope digest. No later hash is
signed into an earlier node, so the graph is acyclic.

## 6. Exact Core Audit and final receipt

`AuditRecordV2` exact fields:

| Field | Type/value |
|---|---|
| `protocol` | `QINGYU_R1_AUDIT_RECORD` |
| `version` | integer `2` |
| `semantic_candidate` | exact §3.4 object |
| `authority_sequence` | `POS` |
| `decided_at` | exact certificate `TIME` |
| `authority_terminal_hash` | `H256` |
| `receipt_body_digest` | `H256` |
| `state_transition_digest` | `H256` |

`audit_record_digest = HASH(QINGYU-R1-AUDIT-RECORD-V2,audit_record)`. Candidate
binding plus deterministic certificate-derived values prevent Core replacement.

`FinalReceiptEnvelopeV2` exact fields:

| Field | Type/value |
|---|---|
| `protocol` | `QINGYU_R1_FINAL_RECEIPT` |
| `version` | integer `2` |
| `receipt_body` | exact §5.1 object |
| `authority_terminal_certificate` | exact signed §5.3 object |
| `audit_record` | exact Audit record above |

`final_receipt_digest = HASH(QINGYU-R1-FINAL-RECEIPT-V2,envelope)`. Fresh reload
re-parses/recomputes every byte, digest and projection before success returns.

The exact linked head is this JCS array:

```text
["QINGYU_R1_LINKED_HEAD",2,authority_domain_id,authority_generation,
 continuity_id,authority_sequence,authority_terminal_hash,operation_id,
 final_receipt_digest,audit_record_digest,resulting_state_version,epoch,
 storage_generation_id,control_plane_generation_id,owner_version]
```

Its digest uses `QINGYU-R1-LINKED-HEAD-V2`. R1 compares Authority fields with
Core's projection; unlike hashes are never asserted equal. This is local
consistency, not an external monotonic witness and never auto-activates startup.

## 7. Same-row atomic dispatch and finalization

The durable operation row contains immutable request/authorization/candidate
bytes/hashes, `row_version:POS`, and one state:

```text
AUTHORIZED -> PREPARE_DISPATCHED -> PREPARED
PREPARED -> COMMIT_DISPATCHED | ABORT_PENDING
COMMIT_DISPATCHED | ABORT_PENDING -> TERMINAL_RECONCILIATION -> FINALIZED
unresolved verification -> UNKNOWN_FENCED
proven local inconsistency -> QUARANTINED
```

PREPARE requires committed authorization. Core CASes AUTHORIZED to
PREPARE_DISPATCHED before network; loss queries same ID. Verified Ack CASes to
PREPARED. One transaction locks that same row/version and CASes PREPARED to only
the authorized dispatch state, stores selected exact digests, increments the
row version, and commits before the terminal network request. The loser cannot
send the opposite request. Python locks/open network transactions do not count.

Dispatch state is not terminal truth. Error/timeout/duplicate/restart queries
Authority by same ID. A verified Authority terminal wins even when different
from local pending projection; that difference requires an already-existing
terminal or valid override and is recorded for reconciliation, never inferred
from HTTP. Missing/invalid Authority evidence means UNKNOWN_FENCED.

Finalization locks the same operation plus state/head rows. One transaction
validates every exact artifact/fence, applies only certified effect, appends
exact Audit/receipt, advances heads and CASes to FINALIZED. Before commit none
is visible; after commit replay is identical. Conflicting local effect/receipt/
head quarantines rather than overwrites.

## 8. Restart and explicit recovery admission

Every service process start, including ordinary restart, begins effective
`RECOVERY_REQUIRES_OPERATOR_ADMISSION` before write traffic. Governance, owner,
normal writes and lease/session issuance are denied. Same-ID terminal/history
inspection is read-only. Stored READY never suffices.

Before an admission may be staged, every nonterminal durable operation is
resolved under recovery authority. Recovery may query Authority by the same ID,
resend only the exact already-CASed dispatch bytes/branch, and locally finalize
only an exact verified terminal. These are completion of a previously authorized
operation, not new write admission. Recovery cannot choose the opposite branch,
mint a new operation, issue a lease/session or use the future storage generation.
If no exact resolution is provable, admission remains blocked/UNKNOWN. Thus an
operation bound to the old generation is settled before the generation changes.

After that resolution barrier, operator admission verifies snapshot provenance,
current Authority state/chain,
full local receipt/Audit chain, canonical identity/continuity/owner/epoch/state/
generations, allocates a new random storage generation UUID and runtime
incarnation UUID, and signs this exact object:

### `RecoveryAdmissionV1Unsigned`

| Field | Type/value | Field | Type/value |
|---|---|---|---|
| `protocol` | `QINGYU_R1_RECOVERY_ADMISSION` | `version` | `1` |
| `recovery_id` | `UUID` | `reason` | `TEXT256` |
| `old_storage_generation_id` | `UUID` | `new_storage_generation_id` | different `UUID` |
| `new_runtime_incarnation_id` | `UUID` | `qingyu_identity_id` | `UUID` |
| `continuity_id` | `UUID` | `authority_domain_id` | `UUID` |
| `authority_generation` | `POS` | `authority_sequence` | `U53`; zero only before the first terminal |
| `authority_terminal_hash` | `H256` | `local_linked_head_digest` | `H256` |
| `expected_state_version` | `U53` | `epoch` | `U53` |
| `control_plane_generation_id` | `UUID` | `owner_version` | `U53` |
| `issued_at` | `TIME` | `expires_at` | later `TIME` |
| `operator_key_id` | `TEXT256` |  |  |

Signed object = exact fields plus
`operator_signature:B64U = SIGN(QINGYU-R1-RECOVERY-ADMISSION-V1,unsigned)`.
Core and Authority verify frozen HKLM Root pin, recovery ID, time window, exact
current Authority/local tuple and old generation. Recovery is a fail-closed,
same-ID staged handshake: Authority first persists `RECOVERY_STAGED` with the
new storage generation/incarnation but cannot issue a lease/session; Core then
persists the same signed admission and new local generation/incarnation while
remaining closed; Authority verifies Core's exact persisted-admission digest,
CASes to `ADMISSION_OPEN` and returns a fresh session; Core queries the same
recovery ID after response loss, verifies the session and both persisted sides,
then publishes ACTIVE last. This ceremony does not silently rotate
`authority_generation` or `control_plane_generation_id`. Any crash or ambiguity
before the last step remains closed and resumes by the same recovery ID.

Stale/expired/wrong Root/signature/tuple/identity/head/generation rejects. A
reused recovery ID returns the stored state only for byte-identical signed
admission and acknowledgement; different bytes conflict. The procedure never
decides whether storage is a clone, never repairs Authority from Core, and every
restart follows it. Acceptance Root remains test-only; private key/passphrase
never enter arguments, logs, Git or Codex.

## 9. Key and pin lineage

Revision 6 IBCS keys are absent. V2 reuses the existing protected Authority
receipt-key slot and TLS/SPKI contract. Acceptance Operator Root fingerprint:

```text
e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1
```

This pivot does not rotate it. Receipt/TLS rotation requires a Root-signed exact
Signed Intent binding old/new key IDs and public digests, Authority generation
transition and activation boundary. Historical public keys/generation scopes
remain verifiable; old private keys do not regain current authority. Missing or
conflicting pins and unsigned rotation fail closed. No new key slot is added.

## 10. Crash/retry and Gate

Pre-PREPARE crash reloads authorization; PREPARE/terminal response loss queries
same ID; PREPARED crash can CAS only its authorized branch; restart resumes
stored bytes and cannot switch; Authority produces one terminal/sequence and
exact duplicate returns original bytes; local finalize is atomic/idempotent;
proven Authority terminal controls projection; UNKNOWN/invalid evidence stays
fenced; every restart invokes §8 even when local storage says READY.

Reviewer A verifies Authority semantics and receipt/Audit/state binding.
Reviewer B verifies exact schemas, golden bytes, ordering and no cycle.
Reviewer C verifies authorization, same-row CAS, reconciliation and manual
admission. Automatic clone/rollback detection is out of scope and cannot
reintroduce IBCS.

Any P0/P1/P2, OPEN or PARTIAL means **R1 MINIMAL MODEL UNSOUND / STOP**. Three
PASS decisions authorize implementation and M1–M15, then three new independent
implementation reviewers. Only after both gates PASS is C01 recorded
`DEFERRED / REMOVED FROM R1 REQUIRED SCOPE` and Marathon resumed at Candidate
Freeze. Foundation Closure requires separate user authorization.
