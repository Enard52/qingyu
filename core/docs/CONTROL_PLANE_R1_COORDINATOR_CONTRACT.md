# Current-R1 Canonical Coordinator Contract / 生产协调器契约

Status: implementation contract v1 for the user-authorized F3-only stage.
Not a signed migration authorization, deployment admission, PostgreSQL
Acceptance result or Foundation Closure. Prior F1/F2/F4/F9 remain frozen CLOSED;
Windows Identity remains FROZEN PASS. Implementation/review evidence must precede
any F3 CLOSED declaration.

## 1. Scope and unique production path

The current-R1 path is separate from shared InMemoryControlPlane and the disabled
legacy PostgreSQL adapter:

`Core durable R1 consumer -> AuthorityClient HTTPS -> authenticated Authority
API -> R1Coordinator -> R1PostgresStore -> reviewed SECURITY DEFINER routines`.

The Authority service alone owns its constrained PostgreSQL credential and
receipt-signing capability. Core receives neither and cannot invoke Authority
SQL. The new consumer must not inherit the old service's prepare-before-INTENT
or exception-driven abort behavior. Existing service/audit/Authority code remains
untouched unless a demonstrated integration regression needs a separately
recorded bounded repair.

F3 starts with independently admitted ACTIVE Authority/GENESIS/continuity and
runtime session state. It implements the canonical mutation PREPARE/COMMIT/ABORT
and query lifecycle, not a new GENESIS creation, owner-transfer, manual-DR or
Root-provisioning ceremony. Missing initial state is a refusal; no constructor,
request, migration or restart fabricates READY/GENESIS. Test setup is explicitly
synthetic provisioning, never evidence of an existing production history.

## 2. Frozen identities and operation-specific payload v1

Retain request schema 1, PrepareAck 1 and terminal receipt 1 from
`r1_protocol.py`, including exact fields and signing prefixes. Introduce a
strict versioned mutation payload inside its existing `payload` slot, and
strict commit/abort authorization bodies in a separate command module.

- `operation_id`: canonical opaque UUID for the one Authority operation;
  key is `(authority_domain_id, operation_id)`.
- Business mutation/change ID: preserved immutable input, mapped to the UUID in
  the local durable INTENT. A retry cannot generate another UUID.
- Intent identity: hash of the exact canonical request envelope; all inputs are
  frozen as canonical bytes before network/database effects.
- `local_commit_id`: immutable UUID generated and persisted before PREPARE;
  COMMIT attestation must bind that exact ID and transaction evidence to the
  frozen request/staged result/audit hashes. It is authenticated claimant
  evidence, not an Authority observation of another database.
- Lease: exact lease UUID, generation, runtime and session. Epoch, expected
  state/owner versions, storage generation and Authority tuple are already
  envelope-bound; the payload additionally binds control-plane generation,
  staged deterministic result, audit predecessor/candidate and lease/session.
- Canonical identity is the exact qingyu identity/continuity UUID pair and
  immutable committed GENESIS operation reference. Alias never grants authority.
- Result candidate binds the assigned state version to the receipt's existing
  `result_payload_hash`; terminal v1 must not silently acquire unsigned fields.
- The same payload freezes `abort_result` and `abort_result_hash`. The abort
  result has exactly `mutation_id`, unchanged expected `state_version`,
  `result_state: ABORTED`, and `core_audit_candidate_hash` for a separately
  pre-frozen abort Audit row. Both decision candidates are request-hash-bound.

Unknown fields/versions, invalid canonical data, mismatching duplicated scope,
same operation ID with different payload/context, or mutable-origin drift are
precondition failures with no governance state change.

## 3. Current state and one final eligibility rule

PREPARE and COMMIT use the same database-owned eligibility definition; COMMIT
re-evaluates it against locked current rows rather than a cached prepare permit:

1. Authority domain/instance/generation and active receipt key equal the pin;
   origin/cluster bindings are admitted; no competing active generation.
2. Exact identity, committed GENESIS, current owner identity/version,
   continuity epoch and expected state version match the frozen request.
3. Active storage and control-plane generations match; recovery is ACTIVE and
   mutation admission is OPEN, with no conflicting unresolved operation.
4. Lease ID/generation/runtime/session/storage/epoch are exact, current and
   ACTIVE; runtime session is still authenticated and unrevoked; both lease
   and session are unexpired against PostgreSQL `clock_timestamp()`.
5. Audit predecessor equals the current canonical checkpoint; payload/result/
   audit hashes and local attestation match the immutable PREPARED operation.

Lock order is global generation/head, continuity, operation, session/key. Every
supported competing state transition uses the same database serialization
boundary. No Python process lock is a production proof. Lease time must be
checked again in finalize after signing/waiting; transaction-start `now()` is
insufficient. A commit-time deferred guard should reject a transaction held past
its frozen lease/session deadline before commit.

The existing per-continuity unresolved-operation barrier remains. An ordinary
takeover cannot silently erase PREPARED. Revocation/recovery supersession must
follow the existing authenticated drain/resolve discipline; no timeout auto-abort
is introduced. Tests may use explicitly privileged fixture state changes to
exercise final predicates, but must identify these as test setup, not supported
production authority-grant APIs or a newly implemented recovery ceremony.

## 4. Durable prepare and atomic terminal transaction

The service role has only explicit procedure EXECUTE and restricted view reads,
never base-table/sequence DML, TEMP, DDL or owner membership. SQL objects are
NOLOGIN-owner-owned, pin a safe search_path and revoke PUBLIC EXECUTE. Runtime
constructors perform no schema creation, repair or migration.

PREPARE stores one immutable canonical envelope and signed Ack atomically. An
Ack is returned only after database commit. It consumes no terminal sequence.
Signing failure or transaction loss leaves no partially admitted prepare.

Terminal protocol, inside ONE database transaction:

1. `propose_terminal`: authenticate exact command and lock/recheck current
   state; create an internal transaction/backend-bound immutable proposal.
2. Return its exact canonical unsigned receipt bytes. The service checks the
   complete protocol/context/result, signs those bytes with the receipt key,
   and independently verifies the signature locally.
3. `finalize_terminal(operation_id, signature)` accepts no substitute result,
   state/version/head/receipt semantic fields. Recheck the transaction proposal,
   current fence and clock; apply effect, immutable terminal receipt, sequence
   and head together. A proposal cannot be committed without finalization.
4. Commit, then expose the terminal bytes. Rollback/connection loss before
   commit consumes no terminal sequence and exposes no accepted result.

Canonical SQL encoding is limited to the fixed flat scalar Ack/receipt shapes:
ASCII property names, strings, null and JCS-safe integers. It must match Python
RFC8785 byte-for-byte on actual PostgreSQL. `jsonb::text` is not JCS. Arbitrary
request payload canonicalization remains in the validated Python boundary;
its canonical bytes and hash are stored immutably. No general JSON codec claim
is made for a narrower SQL routine.

## 5. Terminal rules and reconciliation

Authority states are only `PREPARED -> COMMITTED` or `PREPARED -> ABORTED`.
Terminal history is immutable at the SQL layer as well as in Python. ABORTED
never reopens under the same ID. A new attempt requires a newly authorized
identity/context. Lease expiry or a lost response is not ABORT permission.

Both terminal decisions publish exactly one appropriate pre-frozen Core Audit
row. COMMIT advances business state version and the commit audit checkpoint;
ABORT advances only the audit checkpoint and Authority sequence, retaining the
business state version. The existing receipt `core_audit_candidate_hash` always
copies the PREPARE's staged commit candidate, as required by wire v1. On ABORT,
`result_payload_hash` instead binds the frozen abort result including the actual
abort audit hash. Consumers verify both bindings and publish the selected row;
they never publish the commit candidate for an aborted mutation.

COMMIT requires exact creator scope and local-commit attestation. ABORT requires
the same still-authorized creator and explicit evidence assertion that no local
business commit exists. Otherwise PREPARED stays pending/read-only. Future
Root-authorized forced resolution is not silently implemented as ordinary abort.

Same ID + exact envelope replays original Ack/terminal bytes. Historical results
do not re-sign, allocate another sequence, change audit/state, or require a new
lease in order to rewrite history. Authenticated query access remains required.
Different scope under the same ID is rejected, not treated as historical replay.
An explicit terminal POST retry must also carry the exact stored canonical
authorization bytes; a different decision or transaction-evidence hash conflicts.
Authenticated GET returns established terminal history without requiring another
terminal authorization and can reconcile a client whose attempted decision lost.

Core persists INTENT before any Authority call; records verified Ack and invisible
staged evidence before COMMIT; verifies the terminal pin/signature/request,
frozen result and saved chain cursor before one idempotent local finalize.
The explicit requested decision is durable before PREPARE, bound into the
canonical staged value/source input. Startup resumes that exact decision even
if the caller crashed after PREPARE but before saving the Ack; an explicit
ABORT intent must never restart as COMMIT. Exact terminal authorization bytes
and deterministic evidence hashes are persisted before the first terminal POST
and reused unchanged after restart.
Uncertain POST or crash becomes RECONCILIATION_REQUIRED, queries the same ID and
never invokes abort automatically. Startup/request reconciliation prevents new
writes while unresolved. Historical replay uses the saved receipt/cursor, not
the current global head. No local state reconstructs missing Authority history.

The bounded Core store admits one independently provisioned continuity/checkpoint
and verifies its whole local audit and receipt chain from its admitted GENESIS.
The Authority sequence is global: another continuity can legitimately consume a
sequence. No cross-continuity chain synchronization protocol is implemented in
this stage. Any resulting gap fails closed without publishing a local result or
Audit row; Core must not choose a new cursor from the response. This is an
explicit availability limit, not permission to reconstruct missing history or
claim multi-continuity synchronization support. Existing GENESIS and an already
admitted current owner/lease/session are prerequisites; their issuance, takeover
and recovery transitions remain unsupported production APIs.

## 6. Authentication, signatures and admission

HTTP authentication establishes a server-owned continuity/runtime/session scope;
the request body cannot declare itself authenticated. Require HTTPS; no ambient
proxy/header shortcut changes that trust decision. Outbound Core credentials are
obtained only through the existing pre-send pinned TLS path. Commit/abort extend
the same client transport and preserve same-ID uncertainty handling.

Coordinator may VERIFY the existing immutable Operator-Root-signed origin and
migration attestation against independently supplied observations. Root public
verification never confers Root signing capability. ReceiptSigner is a separate,
preprovisioned service-key capability and must not create or rotate keys. Tests
use synthetic keys only; no real acceptance Root/private/pin material changes.

An explicit production construction path requires verified deployment admission;
configuration shape or a `ready=true` boolean is not evidence. Existing missing
signed intent, inspected target/catalog, migration admission and protected
secret-store prerequisites remain fail-closed. Production app/server factories
must actually reference the new coordinator/consumer while refusing absent
prerequisites; never fall back to memory or direct DB in Core.
Both supported production factories reload the canonical public Operator Root
with the unchanged bounded root-pin loader and compare its profile, test-only
marker, key ID and public bytes with the supplied admission. A caller-created
pin dataclass is not proof of the machine's canonical trust source. The default
source is the real Windows source; tests explicitly inject a synthetic source,
never an HTTP/manifest/environment-selected provider. Core receives only public
deployment-bound evidence and its own preinstalled local checkpoint, never a
PostgreSQL inspector, Authority DSN, or receipt-signing secret.

## 7. Candidate schema versus formal migration

Implement reviewed F3 candidate schema/routine sources and an explicit isolated
test installer. The prior initial authored-DDL snapshot is not silently changed
or reported to contain these new objects. Formal Alembic admission remains
closed; no formal migration is run. A later signed initial migration artifact
must include the reviewed coordinator schema/routines and its actual catalog
fingerprint before deployment. An installed schema mismatch fails startup.

Do not eager-import new runtime modules from the artifact-bound
`app/control_plane/__init__.py`. Core's own durable operation schema is distinct
from Authority SQL and never stores Authority credentials or signing secrets.

## 8. Required tests and evidence limits

Deterministic independent-connection PostgreSQL tests cover concurrent prepares,
takeover/stale-versus-valid holders, 16-way identical finalization, quarantine
and version/generation races, signer/finalize/connection failures, committed
response loss, immutable terminal replay and ABORTED permanence. Record state,
ledger/sequence/head before and after, not just exceptions. SQLite can test Core
local workflow only, never PostgreSQL locks/atomicity.

Any PostgreSQL target is wholly NEW, explicitly `R1_F3_TEST_ONLY`, with unique
container/volume/network/database and no legacy resource reuse. It is disposable
test evidence, NOT R1 PostgreSQL Acceptance. Record image/version, exact resource
identities, setup/teardown and isolation. No acceptance Root keys or final signed
intent may be used. Official acceptance and Foundation Closure remain NOT STARTED.

F3 CLOSED requires the actual coordinator, unique wired production path, all
current fencing/lifecycle/durability evidence, frozen-finding regressions and
independent A/B/C with no P0/P1/P2/OPEN/PARTIALLY FIXED. Otherwise BLOCKED / STOP.
Even PASS does not authorize commit, Signed Migration Intent, PostgreSQL
Acceptance or Foundation Closure; await the user's next instruction.
