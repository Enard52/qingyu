# Control Plane R1 Remediation Plan

Status: **R1 reliability design and Baseline Resolution Amendment DESIGN APPROVED — no implementation authorized by this document**

This plan reopens only the Control Plane reliability contract for Qingyu Core
Phase 2, Commit 1B. It does not close Core Foundation Commit 1, authorize the
next Core stage, or change the frozen Gateway boundary.

## 1. Baseline and auditable dirty state

- Core committed HEAD: `5d4133a71df69d6c7c51644cfb54b9e410e4ab11`.
- Contracts HEAD: `3318d4b458a3b922a93b30d1d17aa3ff68b09002`.
- Gateway HEAD: `08ab990aeb2fdd69ff41e6f09ed5bfaefef43c0c`.
- Pre-plan dirty diff object hash: `9594b6b6f5374094a88bcb068d5bcd7afd875d18`.
- Pre-plan dirty state contains nine modified files, 281 insertions and 19
  deletions. It must not be reset, force-checked-out, stashed and forgotten, or
  committed as a closure change.

The later read-only baseline investigation established **CASE D — UNPROVEN
LEGACY ACCEPTANCE ARTIFACT** for the existing `qingyu_control_acceptance`
database. It exists in the `gateway-db-1` PostgreSQL 16.15 cluster on the
existing `gateway_qingyu_postgres` volume, alongside the
`qingyu_control_app` role. Its `alembic_version` row says
`0001_control_plane`; the observed tables include `cp_witnesses` and
`cp_quorum_acks` with real rows. Its catalog structure resembles the current
uncommitted draft DDL. None of those facts proves canonical Authority
provenance: no independent committed Control Plane `0001` revision, signed
provisioning manifest, stable provisioning/domain/cluster marker, or frozen
historical schema fingerprint was found. The observed catalog fingerprint is
retained as forensic evidence, not an adoption credential. OIDs support object
identification only and do not establish ownership history after restore or
recreation. The legacy database and role remain untouched and forensic-only.

This baseline amendment supersedes only the former assumption that an already
committed canonical Control Plane `0001_control_plane` exists. It does not
change the approved R1 Authority protocol, security boundary, or R2 deferral.
The normative provenance decision is in
`adr/CONTROL_PLANE_R1_BASELINE_PROVENANCE.md`.

The original P0 existed because the implementation represented three witness
labels and two acknowledgements inside the same PostgreSQL Authority database.
Those rows are copied by an Authority backup and are written by the Authority
process itself. They provide neither independent failure domains nor an
external election boundary, so they cannot prevent two restored Authority
copies from self-acknowledging and becoming active.

## 2. Reliability profiles and threat models

### R1 — Personal Production

R1 is the current Foundation v1 target. It provides one independently durable
PostgreSQL Authority deployment for an `authority_domain_id`. Core data and
Authority data have separate databases, credentials, migrations, and backup
lifecycle. Every supported Core instance for the domain connects to that same
Authority endpoint.

R1 guarantees:

1. Core backup and restore never copy or create Authority state.
2. Multiple Core clones compete at one PostgreSQL linearization boundary.
3. At most one storage generation holds current writer authority for a
   continuity.
4. Epoch, storage generation, owner version, lease generation, and operation
   scope fence stale writers.
5. Governance operations are durable, idempotent, queryable, and terminate as
   `COMMITTED` or `ABORTED` after `PREPARED`.
6. An indeterminate response is reconciled by the same operation ID; it never
   authorizes a replacement operation or an assumed abort.
7. Authority process or connection restart does not lose authoritative state.
8. Authority unavailability makes all governance writes fail closed. Read-only
   Core behavior may continue where the frozen Core contract permits it.
9. Manual DR is supported only when the operator can prove an externally
   verifiable **complete Authority head**. Planned replacement from a quiesced,
   readable Authority can meet that condition. Unexpected permanent loss of
   the Authority database is recoverable only if separately deployed recovery
   storage proves that it contains every acknowledged terminal commit. R1 does
   not require such zero-RPO storage; without that proof, permanent loss is
   deliberately unrecoverable and remains fail closed.

R1 assumes the operator does not expose two Authority database deployments for
the same domain at the same time. Network routing, credentials, deployment
inventory, and the DR ceremony enforce this operational single-Authority
assumption. R1 does not claim automatic election if that assumption is broken.

### R2 — High Availability / Multi-host

R2 is deferred. It covers independently failed Authority nodes, automatic
failover/election, independent rollback witnesses, quorum membership, and
automatic prevention of split brain between cloned Authority databases.
Implementation must integrate a mature linearizable consensus system such as
etcd or Consul. Qingyu Core must not implement its own Raft, Paxos, or
single-database pseudo-quorum.

The following is therefore not an R1 acceptance scenario: clone the Authority
database into Authority A and B, expose both concurrently, and expect automatic
quorum election. It remains an R2 feature. R1 documentation and code must not
claim that guarantee.

### R1 execution and network trust boundary

R1 freezes an independent **Control Plane Authority Service** as the only
writer of Authority state. Core does not receive the Control Plane database DSN
and does not execute Authority SQL. It uses a versioned authenticated HTTPS API;
the existing backend-neutral Core authority interface becomes a client adapter.
The service alone holds the runtime database credential and Ed25519 receipt
private key.

Core authenticates with a continuity-scoped service credential over TLS 1.3.
The Core trust pin binds the canonical HTTPS origin, server certificate SPKI
fingerprint, Authority domain/instance/generation, API version, and receipt
public-key fingerprint. Remote deployment requires normal hostname validation
plus the pin; loopback deployment still requires TLS and the same identity
checks. The Authority database stores a domain marker UUID and cluster-binding
fingerprint verified at runtime and before migration, so an allow-listed
database name on another cluster is not sufficient.

The service database role has no direct DML on authoritative base tables or
sequences. It may execute only reviewed `SECURITY DEFINER` procedures and read
restricted status/receipt views. Procedure owners are `NOLOGIN`, procedures
pin a safe `search_path`, revoke `PUBLIC` execution, validate the authenticated
request scope, and perform CAS/sequence/ledger changes. Within one open database
transaction, `propose_terminal(operation_id, target_state)` locks the exact
operation, continuity, generation counter and head, validates the CAS, stores a
transaction-local proposal, and returns its immutable canonical bytes. The
service signs those exact bytes and locally verifies the signature, then calls
`finalize_terminal(operation_id, signature)`. Finalize accepts no semantic
fields, re-derives the digest from the still-locked proposal, persists the
signature/result/head, and the service commits.

PostgreSQL is not claimed to verify Ed25519. Possession of only the service DB
credential can create at most invalid-signature state that every Core rejects
and reconciliation quarantines; it cannot create an accepted Authority receipt.
The trusted Authority Service is the joint holder of the constrained procedure
credential and signing capability. Missing signature, service self-verification
failure, proposal drift, or transaction loss rolls back. Core cannot bypass
this path, and the database owner/migrator is an offline administrative trust
boundary whose compromise is outside R1 automatic recovery.

## 3. Authority identity and generation

R1 defines three separate identifiers:

- `authority_domain_id`: opaque immutable UUID identifying the logical
  Authority domain across process restarts and authorized manual DR.
- `authority_instance_id`: opaque UUID generated outside the restored database
  for one deployment instance. It changes on manual DR. Historical instance
  IDs remain in backed-up receipts, but a restored historical ID is never by
  itself a serving credential or activation decision.
- `authority_generation`: positive monotonic integer for authorized deployment
  generations within the domain. Normal process restart retains it; manual DR
  advances it exactly once.

Core stores a trust pin containing the domain ID, current instance ID,
generation, receipt verification public key fingerprint, endpoint identity,
immutable offline operator-root public key/fingerprint, and pin version. The
initial pin is installed only by the owner-authorized GENESIS ceremony; runtime
configuration cannot replace the operator root. Every governance request and receipt binds these values plus
`qingyu_identity_id` and `continuity_id`. Receipts from a different or older
instance/generation fail closed. `continuity_alias` never participates.

R1 generation monotonicity is operator-authorized rather than consensus
elected. The external source of truth is an operator-signed DR generation
record retained in a protected change-management/secret-store boundary,
separate from the Authority database backup. It records the last accepted
domain, generation, instance/key fingerprints, terminal Authority sequence/head
and a stable `dr_operation_id`. Activation uses the maximum of the verified
database lineage and this external record; if either lineage or its maximum
cannot be proven, R1 remains fail-closed. The complete tuple `(domain,
instance, generation, receipt key)` is the fence; generation is never trusted
alone.

## 4. Authority receipt contract

Every state-changing operation has one canonical request envelope and one
durable operation record keyed by `(authority_domain_id, operation_id)`. The
envelope hash covers operation type, identity/continuity scope, expected
authority generation, expected epoch/state/owner version, actor or owner key
identity, operation-specific payload, reason, and schema version.

The protocol distinguishes a durable `AuthorityPrepareAck` from a terminal
`AuthorityReceipt`. A prepare acknowledgement contains the full identity and
scope, operation ID, request envelope hash, state `PREPARED`, `prepared_at`,
and keyed authentication. It does not allocate `authority_sequence`, advance
the receipt head, or claim a business result. Only the terminal transaction
creates the following Authority receipt:

```text
receipt_version
schema_version
authority_domain_id
authority_instance_id
authority_generation
qingyu_identity_id
continuity_id
operation_id
operation_type
request_envelope_hash
result_state                 # COMMITTED | ABORTED
result_code
actor_or_owner_identity
continuity_epoch
storage_generation_id
control_plane_generation_id
owner_version
lease_generation             # when applicable
authority_sequence
previous_receipt_hash
result_payload_hash
staged_result_hash
core_audit_predecessor_hash
core_audit_candidate_hash
decided_at
receipt_key_id
receipt_signature
```

R1 uses an asymmetric Ed25519 Authority receipt key. The private key is
generated and retained in the Authority secret boundary and is excluded from
database/Core backups. Core receives only the public key/fingerprint through
the trust pin. Manual DR generates a new instance key and explicitly rotates
the pin. Canonical serialization and signature verification are versioned;
unknown versions, key IDs, instance IDs, or generations fail closed.

R1 canonical encoding is RFC 8785 JSON (JCS), UTF-8, with domain-separation
prefix `QINGYU-CP-R1-AUTHORITY-RECEIPT\x00`; SHA-256 produces receipt/request
digests and Ed25519 signs the exact prefix plus canonical bytes excluding the
`receipt_signature` field. `receipt_key_id` is the lowercase SHA-256 fingerprint
of the raw public key. Initial key creation occurs during an operator-signed
Authority activation, never migration or service startup.

`AuthorityPrepareAck` uses the same JCS/SHA-256/Ed25519 key and key ID but the
separate prefix `QINGYU-CP-R1-PREPARE-ACK\x00`. Its signed fields are
`ack_version`, Authority domain/instance/generation, identity/continuity,
operation ID/type, canonical request digest, caller/runtime/storage identity,
expected epoch/owner/state versions, staged-result hash, Core audit predecessor
and candidate hash, state `PREPARED`, and `prepared_at`. Core verifies the full
pin, signature and request digest before persisting it. Unknown fields/version,
wrong prefix/key/pin, or signature failure quarantines and cannot be upgraded to
a terminal request.

The concrete R1 local signer provider is a DPAPI LocalMachine-protected Ed25519
key blob stored outside the repository/database/backup and ACL-restricted to the
dedicated Authority Service SID and administrators. The service decrypts it
only into its process memory; no API returns private key material. This is an
OS-protected server-side key, not a claim of hardware non-exportability. A file
containing plaintext key material is not supported. Normal process restart
reloads the same versioned protected blob. Immutable
public-key history, activation authorization, revocation reason/time, and key
transition are stored in Authority evidence and the external DR dossier. Key
rotation requires an operator-root-signed transition binding old/new key,
instance and generation. Suspected compromise, missing key, missing public-key
history, or secret-store ACL failure makes writes fail closed and requires
manual DR; logs and backups contain fingerprints only. The offline operator
root is immutable for R1: it is pinned during authorized Authority-domain
GENESIS and in every Core trust pin. R1 defines no online root replacement;
loss or suspected compromise stops the domain pending a separately approved
future recovery amendment rather than accepting a newly configured root.

The database persists the prepare record and exact terminal result snapshot,
receipt payload, signature, and envelope hash. Same operation ID plus identical
envelope returns the current phase: the same prepare acknowledgement while
`PREPARED`, then the same terminal receipt after `COMMITTED` or `ABORTED`.
Terminalization allocates exactly one Authority sequence and advances the head;
no sequence is reserved at prepare. Same ID with any different scope or payload
is a precondition rejection, not an operation state or receipt, and has no
governance side effect.

## 5. Authority sequencing and Core Audit

The terminal order is the lexicographic tuple `(authority_generation,
authority_sequence)`. `authority_sequence` is strictly monotonic only within
one generation and resets to its frozen initial value after an authorized DR
generation transition. The generation-opening terminal receipt always receives
sequence `1`; subsequent terminal receipts increment by exactly one. For the
new canonical generation `1`, there is no previous Authority generation. Its
head is seeded with
`SHA-256("QINGYU-CP-R1-GENESIS-HEAD\x00" || JCS({authority_domain_id,
authority_instance_id, authority_generation: 1, provisioning_uuid,
signed_provisioning_origin_digest, receipt_key_id,
operator_root_key_id}))`. The generation-1 opening terminal receipt is an
operator-authorized `AUTHORITY_GENESIS_ACTIVATION` with
`previous_receipt_hash` equal to that seed, sequence `1`, and explicit binding
to the signed provisioning origin; it imports no legacy state. For every
later DR generation, the new generation's seed is the verified previous
generation's terminal receipt hash, and its opening receipt binds the previous
generation/sequence/head and operator-signed DR artifact. The seed is a chain
predecessor, not a terminal receipt or an extra allocated sequence.
The caller cannot supply either component. A PostgreSQL transaction locks
the domain sequence/head, validates the expected governance state, allocates
the next sequence, applies the authoritative state transition, stores the
terminal operation result and receipt hash, and advances the Authority head.
The transaction commit is the R1 linearization point.

`previous_receipt_hash` must equal the current generation's seeded or terminal
Authority head. Generation `1` opens from the signed-origin genesis seed;
later generations open from the verified previous-generation terminal head.
Equal sequence
with a different digest, sequence reuse, and rollback are rejected. A failed
transaction consumes no committed sequence. An `ABORTED` governance decision
is itself a terminal, ordered receipt when an authoritative prepare already
exists.

The terminal receipt hash chain therefore contains only `COMMITTED` and
authoritative `ABORTED` decisions. Durable PREPARED records are queryable and
block conflicting operations, but do not enter the terminal sequence/head until
resolved.

Core Audit remains the Core governance history; it is not a competing global
sequencer. Core records `operation_id`, `authority_sequence`, the complete
Authority receipt or immutable receipt hash, and the Core audit predecessor.
Reconciliation compares the Authority operation result with the Core mutation
receipt and audit entry. Caller-supplied `audit_seq` is removed from Authority
truth.

No claim is made that a numeric sequence missing from every retained Authority
backup/external dossier/Core receipt can be rediscovered. R1 instead refuses DR
when the previous accepted generation/head cannot be proven. Within the proven
lineage, the tuple order never regresses or reuses an accepted position.

## 6. Operation and recovery state machines

Authority operation state is exactly:

```text
PREPARED -> COMMITTED
PREPARED -> ABORTED
```

No terminal state is reopened or overwritten. A retry of an `ABORTED`
operation returns the same abort receipt; a new authorized attempt requires a
new operation ID. A partial unique constraint permits at most one unresolved
writer/recovery operation for a continuity, while completed historical claims
do not block a later legitimate recovery.

Mutation, owner transfer, lease-changing governance, and restore activation use
the same operation envelope/result discipline. Recovery scope additionally
binds trust domain, identity, continuity, source and target storage generation,
current owner record hash/version/key, restore manifest hash, expected epoch,
Authority instance/generation, reason, and owner authorization signature.

For a Core storage restore, `RECOVERY_PREPARE` atomically reserves the target
generation. `RECOVERY_COMMIT` atomically advances active storage generation and
epoch, revokes the previous lease, records the terminal receipt, and releases
the unresolved-operation barrier. `RECOVERY_ABORT` records a terminal abort and
releases the barrier without changing the active writer.

R1 uses one exclusive per-continuity governance barrier. GENESIS domain
activation, mutation, lease issuance/revocation, owner transfer, and recovery
cannot have overlapping unresolved PREPARED operations for the same continuity.
Read-only status/query calls are compatible with the barrier. A transition that
needs to supersede another operation first enters `DRAINING`, blocks new
prepares, and resolves each existing operation with its own authenticated
same-ID COMMIT or ABORT receipt; blanket status updates are forbidden.

Operation effects are normative:

| Operation | COMMITTED effect | ABORTED effect |
| --- | --- | --- |
| Mutation | CAS expected epoch/storage/lease/state version; advance state version and revoke the one-shot permit as applicable. | No domain version/epoch/storage effect; staged Core data stays invisible. |
| Lease change | Bind/revoke the exact runtime, storage generation, epoch and lease generation. | Existing valid lease state is unchanged. |
| Owner transfer | CAS current owner record/version; increment owner version and epoch; revoke old lease. | Owner, epoch and lease are unchanged. |
| Recovery | CAS source generation/epoch/owner; activate exact target generation; increment epoch; revoke old lease. | Active generation, epoch and lease are unchanged. |

Only the authenticated caller that created the exact PREPARED envelope may ask
to continue it, except owner transfer/recovery which also require the frozen
current-owner signature, or an operator-root-signed recovery decision during
manual DR. There is no time-based auto-commit, auto-abort, or lease-expiry
shortcut. `COMMIT` requires the exact operation/envelope and operation-specific
local commit attestation. `ABORT` requires the same scope and authenticated assertion
that no local business commit exists; when that proof cannot be established,
the operation remains PREPARED and the continuity remains read-only pending
operator reconciliation. A stale runtime cannot change a PREPARED operation
after its runtime/storage/epoch credential is revoked.

The PREPARED envelope freezes `staged_result_hash`, Core audit predecessor and
candidate hash, runtime/storage identity and expected governance versions.
`COMMIT_PREPARED` supplies an authenticated caller attestation binding the local
commit ID/transaction evidence to exactly those frozen hashes; it cannot add or
change payload/result/audit material. Authority records this as claimant
evidence, not as independently observed objective database truth, and copies
the hashes unchanged into the terminal receipt. `ABORT_PREPARED` is likewise an
authenticated governance decision while state is exactly PREPARED, not an
objective claim inferred from timeout.

An operator-root-signed `FORCE_ABORT_PREPARED` is defined for every operation
type and is the only resolver after the original credential is revoked. It can
never force commit. Its envelope binds the Authority tuple, exact operation ID,
request/envelope hash, PREPARED acknowledgement hash, revocation evidence,
reason and operator ID. The CAS requires state still PREPARED and no terminal
receipt, then emits an ordered signed `ABORTED` receipt. `DRAINING` is only a
domain admission projection, not an operation state: operator/owner-authorized
entry blocks new prepares; exit occurs only after every listed PREPARED has a
terminal receipt. All force-aborts are individually auditable.

## 7. Uncertain commit and cross-database reconciliation

Core local receipt states distinguish an indeterminate transport outcome from
an authoritative abort. `RECONCILIATION_REQUIRED` is a Core-local condition,
not a fourth Authority terminal state.

Protocol:

1. Core generates the stable operation ID and canonical envelope, then durably
   records a local `INTENT` before any Authority request. The intent contains
   enough scope to rediscover/query the operation after a crash but exposes no
   business data.
2. Core sends that exact envelope; unknown operation is safe to submit again.
3. Authority durably records or returns the same `PREPARED` acknowledgement.
4. Core atomically records its local staged projection plus the authenticated
   Authority prepare acknowledgement in its local `PREPARED` record;
   staged business data remains invisible.
5. Authority commits or aborts and returns a signed terminal receipt.
6. Core verifies the receipt, finalizes the local mutation and Audit entry, and
   stores the receipt binding.
7. If the response is lost or any result is uncertain, Core does not call
   abort and does not mark the local receipt `ABORTED`. It marks the local
   continuity `RECONCILIATION_REQUIRED`, blocks new governed writes, and queries
   by the same operation ID.
8. Authority `COMMITTED` causes idempotent Core finalize; `ABORTED` causes
   idempotent local abort; `PREPARED` is resolved only by the defined same-ID
   authenticated commit/abort policy in Section 6. An Authority `UNKNOWN`
   response for a persisted local `INTENT` permits resubmitting only the same
   envelope/ID; any scope disagreement quarantines. Core never guesses an epoch,
   generation, or outcome.

Startup and request-path reconciliation scan non-terminal local receipts before
allowing writes. Owner transfer and restore also persist local operation
receipts, so a crash after Authority commit cannot repeat the governance
transition or append a conflicting Audit entry.

Core-local state transitions are:

```text
INTENT -> PREPARED -> FINALIZED_COMMITTED
                   -> FINALIZED_ABORTED
INTENT|PREPARED -> RECONCILIATION_REQUIRED
RECONCILIATION_REQUIRED -> PREPARED|FINALIZED_COMMITTED|FINALIZED_ABORTED
```

One local finalize transaction validates the Authority signature/pin and exact
operation scope, applies or neutralizes staged data, inserts exactly one Core
Audit entry, stores the terminal receipt/hash/sequence, and advances the local
projection. Unique constraints on operation ID and `(authority_domain_id,
authority_generation, authority_sequence)` make finalize and Audit append
idempotent. Reads exclude INTENT/PREPARED data. A conflicting terminal receipt,
duplicate sequence with another hash, or missing staged proof quarantines the
continuity rather than manufacturing a local outcome.

## 8. Dual Core clone guarantee

The R1 acceptance creates one valid Core backup and restores Clone A and Clone
B with identical identity, continuity, GENESIS, and history but distinct
runtime/storage instance identities. Both connect through independent clients
to the same PostgreSQL Authority and concurrently submit differently scoped
recovery/writer operations.

The winner is decided by one conditional Authority transaction over the exact
continuity head, active storage generation, epoch, owner version, and unresolved
claim constraint. Its database commit allocates the next Authority sequence and
stores the signed `COMMITTED` receipt. The loser receives a deterministic
conflict/stale result and remains read-only. The result must be explainable from
the Authority operation ledger, receipt, Core mutation receipt, and Core Audit;
process locks, sleeps, and test ordering are not admissible evidence.

## 9. R1 manual Authority DR

Authority loss immediately places governance writes in fail-closed mode.
Manual DR is an activation procedure for an already-proven complete recovery
source; it is not a mechanism for reconstructing missing Authority truth from
Core projections. The operator-signed external generation record is a fencing
high-water for generations and activation transitions. It is not updated by
each normal governance transaction and is not a completeness witness for the
latest terminal sequence.

An Authority recovery source is admissible only when one of these conditions is
proved before activation:

1. **Planned replacement:** the serving Authority is placed in read-only
   admission, all in-flight governance operations are reconciled, its exact
   signed terminal head and PostgreSQL recovery position are recorded, and the
   isolated backup/restore is verified to contain that same head and position;
   or
2. **Separately provisioned complete recovery boundary:** independently durable
   PostgreSQL recovery evidence proves an unbroken zero-RPO recovery chain
   through the last externally acknowledged terminal commit and the restored
   signed head matches it. This capability is optional deployment
   infrastructure, not an R1 availability guarantee.

A base backup, periodic snapshot, external generation record, or collection of
Core receipts is not by itself completeness proof. In particular, if a
terminal commit may have succeeded but its response was lost before any Core
persisted the receipt, and the Authority database and complete recovery chain
are then lost, the latest head is unknowable. That domain is unrecoverable under
R1: do not activate the older backup, do not infer an abort, do not mint a new
generation, and do not reconstruct Authority state from Core. A future recovery
policy would require a separately approved contract.

Once a complete source has been proved, manual recovery requires this operator
ceremony:

1. Declare and record the old deployment unavailable and decommissioned.
2. Disable its endpoint and revoke its application credentials using network,
   secret-store, and database controls under change-management authorization.
3. Select and verify the admissible complete recovery source's Authority
   identity, domain ID, schema/head,
   latest receipt chain, identity/continuity/GENESIS binding, owner state,
   epoch, storage generation, and audit reconciliation checkpoint. Compare it
   with the operator-signed external generation record and all retained signed
   receipts/pins from every supported Core deployment. If any valid surviving
   receipt is beyond the restored head, the backup is not activatable; Core
   projection is evidence of loss, not authority data from which to rebuild.
   Missing or disagreeing high-water evidence, or any inability to prove source
   completeness under the rules above, remains fail-closed.
4. Restore into an isolated database and keep it non-serving.
5. Verify a canonical DR activation envelope signed by the pinned offline
   operator root. It binds stable `dr_operation_id`, Authority domain, exact
   previous generation/sequence/head/key, backup ID, new instance ID,
   `new_generation = max(database lineage, external signed generation record,
   all verified Core pins/receipts) + 1`, new receipt-key fingerprint, revoked
   endpoints/credentials, reason and operator identity. The new key cannot
   authorize itself.
6. Generate the candidate `authority_instance_id` and Ed25519 key in the secret
   boundary. Historical instance IDs/public keys remain immutable evidence;
   restoring them does not reactivate their serving identity.
7. In one serializable activation transaction, CAS the exact prior activation
   head and stable DR operation ID, install the new instance/key/generation,
   persist the signed authorization/key transition, and return the same result
   on retry. A different envelope under the same ID conflicts. A crash is
   reconciled by querying that ID, never by allocating another generation.
8. Record the resulting operator-authorized DR activation receipt, including
   old/new instance and generation, backup identity, reason, operator identity,
   verification results, and credential revocations.
9. Provision new least-privilege runtime credentials and publish exactly one
   Authority endpoint.
10. Update each supported Core trust pin only after it verifies the operator-
    signed activation artifact against the offline root. Until pin and receipt
    reconciliation succeed, each Core remains read-only.
11. Run a first-write canary and reconcile its Authority receipt and Core Audit.
12. Atomically replace the external signed generation record with the terminal
    activation result. A retry uses the same DR ID and result.
13. Retain the old deployment and recovery evidence offline for investigation.

Because PostgreSQL and the external DR record cannot share one transaction, the
ceremony is a durable same-ID saga. Before database activation, the external
store records signed `DR_INTENT`. After the database CAS, the signed activation
receipt advances it to `DB_ACTIVATED`; only then may endpoint publication and
Core pin updates occur. They advance it through `PUBLISHED` to `COMPLETED`.
Every retry reads both stores by the same `dr_operation_id`: external intent plus
no DB result retries the exact DB CAS; a DB result plus stale external intent
copies the already signed result into `DB_ACTIVATED`; mismatched envelopes or
two terminal results fail closed. External-store unavailability blocks
publication. Thus a crash can pause the ceremony but cannot allocate a second
generation or expose an unrecorded activation.

The safety assumption is explicit: operators must not run two Authority
deployments for one domain. R1 does not automatically defeat an operator who
violates it. After an authorized switch, correctly updated Core clients reject
the old instance/generation/key if it reappears.

## 10. Witness implementation disposition

The current uncommitted `cp_witnesses`, `cp_quorum_acks`, `_quorum()` calls,
`quorum_threshold`, and documentation that calls them a production 2-of-3
security mechanism are **DROP**. They are not retained as diagnostic metadata
because quorum-shaped names would continue to misrepresent the R1 guarantee.
This is a disposition for the **future canonical R1 implementation**, not an
instruction to mutate the existing CASE D acceptance database. Its actual
`cp_witnesses`, `cp_quorum_acks`, version marker, rows, and grants remain
untouched forensic evidence until separately authorized disposition.

Any future R2 schema is added only when backed by real independent consensus
infrastructure. R1 may expose neutral operational metadata such as receipt
verification status, but it must not call local rows witnesses or quorum.

## 11. Dirty worktree disposition

| Dirty file | Disposition | Rationale / next action |
| --- | --- | --- |
| `app/config.py` | KEEP + REWORK | Keep explicit DB allow-list and Core/Authority separation. Replace username deny-list with verified role/capability checks and stable R1 production configuration. |
| `app/control_plane/authority.py` | REWORK | Keep identity checkpoint intent and stable request ID, then replace ad-hoc return values with the versioned operation/receipt interface. |
| `app/control_plane/migration.py` | DROP + REWORK | Remove hard-coded pseudo-Alembic heads/current/check. Replace with an independent real Alembic environment and secret-safe configuration. |
| `app/control_plane/postgres.py` | REWORK | Keep genuine cursor fix, DB identity guard, basic PostgreSQL CAS, and compatible identity checks. Drop all fake witness/quorum code; redesign operations, sequence, receipts, barriers, and reconciliation. |
| `app/services.py` | KEEP + REWORK | Keep request ID propagation and Authority identity comparison. Redesign uncertain-result handling, local receipts, startup reconciliation, and operation replay. |
| `docs/CONTROL_PLANE_BOUNDARY.md` | DROP + REWORK | Remove the claim that same-DB witness slots satisfy production quorum. Replace with the honest R1/R2 profile boundary and manual-DR assumption. |
| `docs/CONTROL_PLANE_POSTGRES.md` | REWORK | Keep independent DB/role direction; fix inconsistent DB name, secret-bearing CLI, migration procedure, identity pinning, and R1 limitations. |
| `tests/test_control_plane_postgres.py` | REWORK | Keep real restart/CAS/stale-writer ideas. Drop the quorum-row assertion and altered-scope replay expectation; add full R1 receipts, dual-clone, failure, and reconciliation acceptance. |
| `tests/test_safety_boundary.py` | KEEP + REWORK | Keep unknown DB rejection. Add actual current-user/privilege/separation checks and production configuration cases. |

No disposition rewrites Git history. Implementation applies the choices as a
normal forward remediation change after separate authorization.
Because the nine-file dirty state is an uncommitted legacy draft, a future R1
implementation starts from clean HEAD in an independent Git worktree. The
dirty main worktree is retained as reference evidence; the canonical R1 diff
must not be layered onto it or silently absorb its pseudo-`0001` marker.
This design Gate creates no worktree and changes none of the nine files.

Three already committed documents are also in the implementation remediation
scope even though they are not part of the nine-file dirty diff:
`CONTROL_PLANE_BACKUP_RESTORE.md`, `CONTROL_PLANE_RUNBOOK.md`, and
`CONTROL_PLANE_RECONCILIATION.md`. Their witness-store and automatic restored-
Authority fencing claims must be rewritten to match R1 manual DR and the R2
deferral. This is a forward documentation correction, never history rewriting.

## 12. Roles, provisioning, and secrets

Production uses at least:

- `control_plane_owner`: `NOLOGIN` owner of the Control Plane database, schema,
  and objects.
- `control_plane_migrator`: dedicated `NOINHERIT` migration job identity; may
  assume only
  `control_plane_owner` for the migration job, is `NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS`, and is unavailable to Core runtime.
- `control_plane_app`: dedicated `NOINHERIT` Authority-service runtime identity;
  `NOSUPERUSER NOCREATEDB
  NOCREATEROLE NOREPLICATION NOBYPASSRLS`, does not own the database, schema,
  or tables, cannot execute DDL or direct base-table/sequence DML, and receives
  only database connect, schema usage, reviewed procedure execute, and
  restricted status/receipt-view select.
- operator/DR identity: separate break-glass workflow identity; not embedded in
  Core and not interchangeable with either database role.

A versioned provisioning script/runbook must create/grant/revoke/default-
privilege state idempotently and verify `current_user`, database owner, schema
owner, table owners, `rolsuper`, `rolcreatedb`, `rolcreaterole`, and effective
DDL capability. `PUBLIC` loses database/schema create, temporary privileges
unless explicitly required, and all function execution; the app role is not a
member of owner, migrator, operator, or other privileged roles. Acceptance
proves it cannot create/alter/drop objects, directly insert/update/delete base
tables, manipulate sequences, `SET ROLE`, replace functions, or exploit an
attacker-controlled `search_path`, while every supported procedure still works.

Database/TLS credentials come from a named secret-store reference injected into
the owning process; a protected environment variable containing the DSN is an
allowed local R1 compatibility input, but is never passed in command arguments.
The Authority receipt private key is supported only as the DPAPI-protected,
service-SID-restricted key blob defined in Section 4, never as an environment
value or plaintext file. Logs expose only
database name, role class, Authority IDs, key ID/fingerprint, and redacted
endpoint identity.

The Authority domain manifest pins an offline operator authorization root public
key whose private key is held outside Authority and Core. The database and
external DR dossier retain immutable Authority public-key history and signed key
transitions. Core verifies the operator-root signature over each new
instance/generation/key activation before changing its trust pin. Missing,
revoked, or inconsistent operator root/key history is fail-closed.

Production configuration is split by process. Core accepts only
`CORE_CONTROL_PLANE_API_BASE_URL`, client-credential secret reference, TLS CA
reference/SPKI pin, Authority domain ID, expected instance ID/generation, API
version, receipt public key/key ID, and immutable operator-root fingerprint.
`CORE_CONTROL_PLANE_STORE` is removed from the Core production configuration;
no compatibility setting may give Core an Authority DSN. The Authority Service
alone accepts the database secret reference, signed provisioning target/cluster
identity, DPAPI signer handle/path metadata, operator-root public key, TLS
certificate/key references, client-auth policy, and expected Authority tuple.

Each owning process validates its complete settings and trust pins before
becoming ready. Missing, extra-conflicting, malformed, unresolvable or mismatched
identity/secret/TLS settings keep readiness false and governance writes fail
closed; there is no fallback. Safe logs contain setting names, redacted origins,
IDs and fingerprints only, never credentials, DSNs, tokens, private material or
authorization envelopes.

## 13. Migration P2 disposition

Migration execution coverage remains a genuine **OPEN P2**. The current
embedded DDL plus manually populated `alembic_version`, hard-coded `--heads`,
and pre-migrated acceptance fixture are not a supported migration system.

Remediation creates an independent Control Plane Alembic environment outside
Core `0001_core_foundation`. Git history contains no committed independent
Control Plane `0001_control_plane` revision. The same string in the old
acceptance database is a hand-written legacy marker, **not a canonical parent**.
The new R1 lineage begins at the formally reviewed and committed base revision
`0001_control_plane_r1_initial` with `down_revision = None`. There is no
`0002_control_plane_r1` child of legacy `0001_control_plane`, no stamp/adoption
route, and no upgrade of the CASE D database. The canonical initial revision
contains no pseudo-witness or same-database quorum structures.

Freeze the new, clearly isolated acceptance database name as
`qingyu_control_r1_acceptance`. It is newly provisioned in an Authority
acceptance deployment separate from the Gateway volume; it does not reuse
`qingyu_control_acceptance`, its marker, data, role, or grants. Acceptance must
cover empty-to-canonical-head, concurrent migrator serialization, repeat
no-op, and legacy/unknown/future/multiple-head rejection. It must verify
`SELECT current_database()`, run real Alembic `heads`, `current`, `history`, and
`check` using the migration role, prove no identity was auto-created, run the
runtime suite as the restricted service role, and verify negative privileges.
No old acceptance cleanup is part of this acceptance flow. Reviewer C may
close the P2 only from real migration and privilege evidence.

**Before any new cluster/database/role/key provisioning action**, the operator
signs a versioned provisioning intent outside the database. It binds a
one-time `provisioning_uuid`, Authority domain/instance IDs, initial generation
`1`, environment/profile, intended isolated deployment and database name,
planned TLS origin, role names/policies, receipt-key slot/reference and
creation policy, immutable operator-root identity, canonical initial revision
ID, and expected versioned schema fingerprint. Values not yet observable,
including server system identifier, database/owner OIDs, creation-event
timestamp, and generated receipt public-key fingerprint, are **not invented**
in the intent. After creation but before schema migration, the operator signs
a completion manifest binding those observed values, including the
provisioner's timestamp for the creation event, to the same intent ID and
target, with database name/OID and owner OID as supporting identity checks.
The verified intent plus completion form the immutable signed provisioning
origin. Its exact digest, named `signed_provisioning_origin_digest`, is
`SHA-256("QINGYU-CP-R1-PROVISIONING-ORIGIN\x00" ||
JCS({"intent": full_signed_intent_envelope,
"completion": full_signed_completion_envelope}))`, including each envelope's
version, key ID and signature. Neither a completion-only digest nor unsigned
payload digest is interchangeable. No key or object creation is allowed before
the intent.

Signing-root and signed-origin-digest verification precede the initial migration.
That migration atomically creates the schema plus immutable
provisioning/domain/cluster marker and records
`signed_provisioning_origin_digest`.
Provisioning then verifies the actual complete catalog fingerprint (including
owners, columns, constraints, indexes, functions, grants and default
privileges) against the signed expectation and records an external signed
**initial migration completion attestation**. The origin manifest remains an
immutable genesis anchor, not a promise that every later revision has the same
fingerprint. Each later migration requires a new signed, versioned migration
authorization binding the exact prior revision, attested fingerprint and
authorization-chain head to the target revision, expected fingerprint and
migration artifact digest. Preflight verifies the prior state; after the
migration, a signed completion attestation binds the actual target fingerprint
and new chain head. Readiness stays false until that attestation exists; a
crash retries verification under the same migration authorization ID rather
than stamping or inventing a new transition. Every startup verifies the
immutable origin, complete signed migration-attestation chain, current
revision/fingerprint, marker, cluster and key identity. Legacy marker,
unexpected object, unauthorized jump or mismatch fails closed. Manual DR to
a new cluster is authorized only by the operator-root-signed DR artifact;
ordinary migration cannot rotate the cluster binding.

## 14. Acceptance database cleanup status

Read-only investigation confirmed `qingyu_control_acceptance` and
`qingyu_control_app` **EXIST** (observed OIDs `92770` and `92842`) in the
existing Gateway PostgreSQL cluster. Their canonical Authority provenance is
**NOT PROVEN**. The database, its legacy marker, witness/acknowledgement rows,
other control data, and the role's direct base-table grants are
**LEGACY / UNPROVEN / FORENSIC-ONLY**. Neither name nor OID licenses adoption,
upgrade, grant repair, deletion, or reuse. The old database and role remain
unchanged; future cleanup requires a separate explicit authorization and a
provenance-safe plan. R1 implementation and acceptance do not clean them up.

The future new R1 acceptance environment has its **own** signed provisioning
UUID, markers, manifest, OID observations, dependencies, and lifecycle. Its
eventual cleanup is also outside this amendment and requires exact identity,
ownership, dependency, and separate authorization. No production, Gateway,
Core, legacy, system, wildcard, or ambiguous database/role may be touched.

## 15. Severity reclassification under R1

| Prior finding | R1 classification |
| --- | --- |
| Authority database clone automatic split-brain prevention | R2 deferred, not an R1 P0, only after all R1 claims of automatic quorum are removed and the manual single-Authority assumption is explicit. |
| Same-database witness/quorum implementation | R1 P1 until excluded from the new canonical implementation; the CASE D legacy database remains unchanged as forensic evidence. |
| Dual Core clone against one Authority | R1 P1 until real acceptance proves one committed writer. |
| Authority/Core uncertain commit contradiction | R1 P1; unchanged and blocking. |
| Missing terminal operation receipts/idempotent query | R1 P1. |
| Recovery scope/state-machine gaps | R1 P1. |
| Caller-chosen audit high-water / missing Authority sequence | R1 P1. |
| Production role separation and enforceable least privilege | R1 P2. |
| Independent migration execution coverage | R1 P2. |
| Secret-bearing migration command and unstable deployment contract | R1 P2. |

The architecture ambiguity target for this Design Gate is zero; implementation
findings intentionally remain open for the subsequent authorized coding turn.

## 16. Implementation DAG

1. **R1-0 — Safe baseline**: preserve the nine-file dirty draft/hash; start a
   separately authorized implementation in an independent worktree from clean
   HEAD; keep CASE D artifacts forensic-only; verify Gateway/Contracts/Core
   `0001` unchanged. Remove misleading witness claims/code only in the new
   canonical implementation, never by mutating the legacy acceptance database.
2. **R1-1 — Contract and schema**: define authority IDs/generation, canonical
   envelopes, operation ledger, receipt schema/signing, Authority sequence/head,
   terminal states, and unresolved-operation constraints.
3. **R1-2 — Independent migrations and provisioning**: new parentless
   `0001_control_plane_r1_initial` in an independent real Alembic history,
   signed origin and catalog fingerprint, new isolated
   `qingyu_control_r1_acceptance`, allow-list/current-database gate,
   migrator/service roles, secret-safe commands; no legacy adoption.
4. **R1-3 — PostgreSQL coordinator**: implement same-ID lookup, prepare,
   conditional terminal transition, sequence allocation, receipt signing,
   query-by-operation, and fail-closed connection behavior.
5. **R1-4 — Core reconciliation**: persist Authority receipts, introduce local
   reconciliation-required state, remove blind abort, add startup/request gate,
   and make finalize/abort idempotent.
6. **R1-5 — GENESIS/owner/recovery integration**: apply complete scope binding,
   signed owner authorization, terminal recovery operations, lease/epoch/storage
   fencing, and pending-operation barriers.
7. **R1-6 — Manual DR tooling/runbook**: instance/key creation, generation and
   trust-pin transition, credential revocation, isolated validation, canary and
   rollback-to-read-only behavior. No automatic election.
8. **R1-7 — Acceptance and failure injection**: execute the matrix below on
   fresh PostgreSQL with two Core clones and independent clients.
9. **R1-8 — Independent gates**: Reviewer A/B/C implementation review, full
   Core/Contracts/Gateway regression, clean worktrees, then and only then a
   later Foundation closure decision.

Dependencies are sequential at the contract/migration/coordinator boundary;
tests, deployment runbook, and Core reconciliation fixtures may proceed in
parallel only after R1-1 freezes their interfaces.

## 17. Final R1 acceptance matrix

| Area | Required evidence |
| --- | --- |
| Backend/config | The Authority Service selects PostgreSQL; Core selects only the authenticated HTTPS Authority client. Missing/bad config, connection, driver, schema or pin fails closed; no memory fallback. |
| Database isolation | Only the newly provisioned `qingyu_control_r1_acceptance` passes its signed origin, exact target, cluster/marker, and `current_database()` checks; legacy `qingyu_control_acceptance`, Core/Gateway/unknown/system DBs reject. |
| Migration | Parentless canonical `0001_control_plane_r1_initial` on the fresh isolated database; real Alembic heads/current/history/check; no automatic identity; legacy `0001_control_plane`, stamp/adopt/upgrade, downgrade and unknown head reject. |
| Provenance | Signed provisioning manifest/UUID, domain/instance/generation, cluster marker, expected and actual complete schema fingerprint, creation timestamp, key identity/reference, role separation and signed completion attestation agree before readiness; name/OID alone rejects. |
| Legacy containment | Old database, role, `alembic_version`, witness/acknowledgement and other control rows/grants remain unchanged and forensic-only; no trust/data/receipt/generation transfer and no cleanup without separate authorization. |
| Roles/secrets | Separate migrator/app roles; app is non-owner/non-DDL/non-superuser; credentials absent from Git, logs and process arguments. |
| API/network | Wrong client scope, credential/certificate, host, CA, SPKI, Authority tuple, API version or receipt key fails closed. Among runtime application components only the Authority Service connects to the Authority database; controlled provisioning/migration jobs use separate privileged identities. Core never receives its DSN or connects directly. |
| Authority identity | Domain/instance/generation/key pin verified; stale instance/generation/key receipt rejected. |
| Receipt | Authenticated PREPARED acknowledgement and canonical signed terminal COMMITTED/ABORTED receipts verify; tampering, unknown key/version and cross-scope replay reject. PREPARED has no terminal sequence/head position. |
| Sequence | Authority allocates generation-scoped monotonic sequence and predecessor; lexicographic generation/sequence order is verified; caller cannot choose it; gap/fork/reuse/rollback reject. |
| Idempotency | Same ID/envelope returns frozen result; same ID/different envelope conflicts; completed recovery does not block future recovery. |
| Concurrency | Two independent authenticated HTTPS clients/Core clones compete through the Authority API for mutation, owner transfer and recovery; at most one terminal winner. Direct DB connections are read-only test instrumentation only. |
| Dual Core clone | Same backup to A/B, distinct target generations, same Authority; exactly one committed writer and one deterministic loser. |
| Stale writer | Old lease/epoch/storage/owner/Authority pin rejected after transfer or recovery. |
| Crash points | Before Authority prepare; after prepare; before/after Authority commit; after commit before response; before/after Core finalize. |
| Commit-response loss plus Authority total loss | Inject a terminal database commit, lose the response before every Core persists its receipt, then destroy the Authority database and omit a complete recovery chain. Activation of an older backup must be refused permanently; no inferred abort, reconstructed head or new generation is allowed. Repeat with a proven complete recovery source and require recovery to the exact signed terminal head before activation. |
| Uncertain result | No blind abort; same-ID query deterministically finalizes COMMITTED or ABORTED; PREPARED blocks later writes until resolved. |
| Audit reconciliation | Receipt/sequence/hash binds Authority operation, Core receipt and Core Audit; missing/forked/tampered projection quarantines. |
| Restart/unavailable | Process/connection recycle preserves truth; refusal/drop/rollback/deadlock retry never creates two results; outage fails closed. |
| Core backup | Excludes Authority DB, signing key and runtime credentials; restored Core receives no automatic writer authority. |
| Manual Authority DR | Isolated restore, new instance/key/generation, old endpoint/credential revocation, explicit pin update, read-only until reconciliation. |
| Boundaries/regression | Core direct Gateway DB dependency remains zero; Gateway API-only; existing GENESIS/identity/alias/audit/restore tests pass. |

Explicitly excluded from this R1 matrix: two concurrently exposed cloned
Authority databases and automatic leader election. That is an R2 acceptance
suite, not a hidden R1 guarantee.

## 18. Design Gate and stop condition

This plan may be marked `R1 REMEDIATION DESIGN APPROVED` only after three
independent reviewers pass:

- Reviewer A: distributed correctness and honest R1 threat boundary.
- Reviewer B: receipts, Authority sequence, state machines, idempotency and
  uncertain-result reconciliation.
- Reviewer C: roles, secrets, migration, isolation and manual DR deployment.

Approval authorizes no implementation by itself. After design review, stop and
wait for a separate implementation instruction. Core Foundation Commit 1
remains NOT CLOSED throughout this Design Gate.

### Final independent Design Gate record

- Reviewer A — **PASS**; P0=0, P1=0, P2=0. Distributed correctness, honest R1
  threat boundary, and the complete-head limitation on manual DR are closed.
- Reviewer B — **PASS**; P0=0, P1=0, P2=0. Receipt/state-machine semantics,
  generation-scoped ordering, forced abort, and uncertain-result reconciliation
  are closed.
- Reviewer C — **PASS**; P0=0, P1=0, P2=0. Authority isolation, roles, secrets,
  migration/bootstrap, deployment, cleanup, and narrowed manual DR are closed.

Design Gate result: **R1 REMEDIATION DESIGN APPROVED**. This result neither
approves product implementation nor authorizes a commit, Foundation closure, or
entry to the next Core stage.

### Baseline Resolution Amendment Gate

The earlier Reviewer A/B/C PASS applies to the R1 reliability protocol, not
to the disproved canonical `0001_control_plane -> 0002_control_plane_r1`
history assumption. A separate independent Design Gate has now accepted CASE D,
the new parentless origin, and the signed provisioning/receipt opening rules:

- Reviewer A — **PASS**, P0=0, P1=0, P2=0: migration history, parentless
  canonical initial revision, and versioned signed migration-attestation chain.
- Reviewer B — **PASS**, P0=0, P1=0, P2=0: signed provisioning origin, Authority
  identity, generation-1 genesis seed, later DR links, and NO TRUST TRANSFER.
- Reviewer C — **PASS**, P0=0, P1=0, P2=0: isolated new acceptance database,
  roles, CASE D forensic preservation, and separate cleanup authorization.

Gate result: **R1 BASELINE RESOLUTION AMENDMENT DESIGN APPROVED**. This resolves
the baseline **design** blocker by refusing legacy adoption. It does not prove
legacy canonical provenance or authorize implementation, database mutation,
cleanup, Git product commit, Foundation Closure, or entry to R1-1. Those require
separate instructions.
