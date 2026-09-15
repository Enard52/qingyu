# Control Plane R1 Implementation — in-progress state

Status: **BLOCKED / Implementation Gate not passed**. This file records the
isolated implementation worktree only; it does not authorize provisioning,
database migration, Foundation Closure, or the next Core stage.

## Current F3-only result — 2026-09-14

**R1 F3 COORDINATOR IMPLEMENTATION = PASS; F3 CLOSED.** Independent A/B/C
bounded PASS, no remaining P0/P1/P2. Final targeted tests: 118 passed. Final
complete suite: 485 passed / 4 legacy skipped (415 known deprecation warnings).
See `CONTROL_PLANE_R1_F3_COORDINATOR_REPORT.md` and
`evidence/r1-f3-coordinator/` for the full 33-item report, original failures,
independent reviews, source classification and test-only SQL evidence.

The actual new path is durable Core -> pinned HTTPS -> Authority API ->
R1Coordinator -> restricted PostgreSQL store/procedures. It starts from already
admitted GENESIS/owner/lease; it does not implement their issuance, takeover or
recovery ceremonies. Cross-continuity receipt gaps continue to fail closed.

The Lead used only a newly created, isolated `R1_F3_TEST_ONLY` PostgreSQL cluster.
After final verification, its container, volume and both new networks were
removed at 2026-09-14T18:38:07Z. This was NOT formal PostgreSQL Acceptance.
Gateway/legacy and the real Root/private custody/deployment were untouched.
F1/F2/F4/F9 remain CLOSED; Windows Identity remains FROZEN PASS, without full rerun.

Overall Implementation Gate remains **BLOCKED / not accepted** pending its
separate deployment/migration/acceptance work. No final commit. Signed Migration
Intent NOT STARTED; PostgreSQL Acceptance NOT STARTED; Foundation NOT ENTERED.
Only the NEXT Signed Migration Intent stage may resume after new user authority;
this F3 turn stops here.

The following older implementation notes record earlier checkpoints. Statements
about missing mutation integration or absence of disposable test evidence are
superseded by the current F3 result above, not permission to bypass formal gates.

## Protected baseline

- Original worktree: `<repo>\core`, HEAD
  `5d4133a71df69d6c7c51644cfb54b9e410e4ab11`.
- Original tracked dirty diff hash remains
  `9594b6b6f5374094a88bcb068d5bcd7afd875d18`.
- This implementation worktree: `<repo>\core-r1-implementation`, branch
  `ai/task-r1-canonical-implementation`, clean-HEAD base as above.
- CASE D legacy database, role, marker, witness rows and Gateway volume remain
  forensic-only. No connection, DDL/DML, migration or Docker operation targeted
  them. Earlier checkpoints preceded any disposable SQL testing; the separate
  user-authorized F3 test-only operations are recorded above. No trust transfer
  or Git commit was performed.

## Built but not accepted

- R1 canonical wire primitives: RFC 8785 JCS, SHA-256, Ed25519, separate
  PrepareAck/terminal-receipt prefixes, full Authority pin and receipt-chain
  checks.
- Pure signed-provisioning verification: preexisting operator-root intent,
  separately signed creation completion, full-envelope origin digest, and
  post-migration attestation/readiness verification. External storage identity
  requires an independent deployment inspector, not a manifest assertion.
- Static new `control_plane` schema contract and separate Alembic root
  `0001_control_plane_r1_initial`; Core remains `0001_core_foundation` in its
  own script location and version table.
- HTTPS client prototype pins CA/hostname/TLS 1.3/SPKI and reconciles an
  uncertain POST by the same operation ID. It is not yet integrated with Core
  durable INTENT or a live Authority Service.
- Legacy direct-DB migration is disabled; Core configuration rejects direct
  Control Plane DSNs, and legacy write-capable acceptance tests are skipped.

## Explicit blockers before any acceptance provisioning

1. Independent read-only inspectors for Docker/storage identity, TLS endpoint,
   receipt-key store and PostgreSQL target must be implemented and bound to the
   signed completion. The Alembic online entrypoint currently raises before
   opening a DB connection, intentionally.
2. The initial migration now uses an authored-DDL snapshot and a versioned
   complete transitive source artifact digest covering the migration entrypoint, revision,
   snapshot and trust-verification modules. The signed digest is checked before
   database connection and again before revision SQL; this is static source
   integrity, not live catalog acceptance. Independent review is pending.
3. Versioned actual PostgreSQL catalog fingerprint, owner/role/grant procedures
   and signed expected-fingerprint comparison are not implemented. The initial
   revision also lacks reviewed restricted views, service procedures and
   default-privilege policy. Consequently a complete provisioning intent
   cannot yet be signed and no new acceptance cluster may be created.
4. Production Authority coordinator, DB CAS/locking, stored procedures,
   authenticated service API, Core durable INTENT/reconciliation, GENESIS,
   owner lifecycle, and Manual DR are not implemented.
5. No new acceptance DB, volume, signed provisioning intent, completion,
   initial attestation or failure-injection evidence exists. Docker engine is
   reachable; the read-only inventory shows only healthy legacy
   `gateway-db-1` mounted to `gateway_qingyu_postgres`. The fixed acceptance
   Operator Root was subsequently created by the human operator for the
   `R1_ACCEPTANCE_TEST_ONLY` profile. Its approved public fingerprint is
   `e50485fc68a6a2b26a2b369e6e34789125fb9573c279075b090a1365b7cb74f1`.
   The fixed public file and canonical 64-bit HKLM pin were later installed;
   the 32-bit slot remains absent. A signed complete provisioning intent,
   and isolated target remain absent. Windows service-principal evidence now
   exists; see the bounded Windows acceptance section below. Docker availability
   does not satisfy signed-origin preflight.
6. Independent Reviewer A/B/C Implementation Gate has not occurred. Early
   independent reviews found schema and protocol P1 defects. Local edits now
   cover terminal `NULL` sequence, writer storage/instance binding, GENESIS
   PREPARED without a preexisting continuity, signed-origin TOCTOU, non-200
   POST uncertainty, and terminal NULL receipt signature. A bounded independent
   re-review closed these specific static defects; live PostgreSQL validation
   and full Reviewer A/B/C Implementation Gate remain absent. The preexisting
   version-table ownership path remains an explicit migration blocker.
7. A later independent pin/snapshot pre-review found open P1s in artifact
   coverage and 32/64-bit HKLM view handling. Candidate fixes explicitly use
   the 64-bit view, detect a conflicting or malformed 32-bit pin (including an
   existing empty key), and bind the transitive source closure into the signed artifact.
   The pin ACL gate now checks parent replacement rights, directory
   FILE_DELETE_CHILD, and actual Windows ACL rights properties. These are
   code-level fixes with bounded independent static re-review finding no
   remaining P0/P1/P2 in that scope. The real acceptance pin is now installed
   and has been loaded by both dedicated Windows service identities. No first
   migration is permitted on this bounded Windows evidence.
8. The current revision leaves `public.cp_alembic_version` migrator-owned,
   while the approved role contract requires the NOLOGIN owner to own database,
   schema and objects. Its final owner, ACL, and pre-migration DDL path must
   be reconciled before real PostgreSQL acceptance.

## Trust Bootstrap and bounded Windows acceptance

- An operator-only, test-only local Root creation/public export/pin installer
  and its custody runbook exist. The human creation ceremony and public-pin
  installation have now occurred; no operator-signed provisioning/migration
  intent exists and no executable target is admitted.
- The owner contract selects a separate NOLOGIN `control_plane_owner`, including
  ownership of `public.cp_alembic_version`. The current Alembic role-switch
  timing still conflicts with this contract; the design does not assert a
  real PostgreSQL owner or permission result.
- The initial signed provisioning intent is now strict V2 and binds the
  authored-DDL digest, first-party dependency-source digest, owner/intent
  document digest, artifact digest, expected catalog fingerprint, and explicit
  operator approval. V1 drafts are rejected. Both env and revision verify the
  local digests before connection/SQL, while the entrypoint remains hard-stopped.
  This is not a signed final approval or full schema-contract/catalog proof.
- Exact resolved third-party dependencies, reviewed procedures/views/GRANTs,
  versioned expected actual catalog fingerprint, independent target inspector,
  and PostgreSQL privilege acceptance remain open. Root/public-pin installation
  is complete; this does not supply a signed provisioning intent.

## Windows identity remediation — bounded gate PASS

- Exact virtual accounts are frozen in
  `CONTROL_PLANE_R1_WINDOWS_IDENTITY_CONTRACT.md`; both demand-start services
  have run as their own non-administrator, unelevated SIDs with only
  `SeChangeNotifyPrivilege`. SCM host/child PIDs and owner SIDs were independently
  observed. Both services are stopped between acceptance runs.
- Canonical public and Registry64 parent/leaf ACLs received only the two exact
  service SIDs' read grants. Root fingerprint, public bytes, pin values and
  private custody remain unchanged. No private bytes or passphrase were read.
- Protected deployment: `C:\Program Files\Qingyu\ControlPlane\R1\Acceptance`.
  Development worktree permissions were not altered. Complete manifest and
  actual permission-open evidence reside in the administrator-controlled
  `C:\ProgramData\QingyuR1IdentityEvidence` tree.
- The formal pin loader uses native read-only owner/DACL APIs because the
  real service PowerShell language mode rejected the previous .NET call.
  No Windows application-control policy or service privilege was relaxed.
  The native module is included in the unsigned release's artifact/dependency
  source digest; authored DDL and migration revision bytes were not changed.
- Current bounded evidence evaluates 7,146 checks with no failures; full suite
  is 283 passed, 4 legacy direct-DB tests skipped. Independent Trust Boundary
  Reviewer PASS, no P0/P1/P2 or OPEN/PARTIALLY FIXED findings. See
  `CONTROL_PLANE_R1_WINDOWS_IDENTITY_REPORT.md`. This is not Implementation Gate PASS.
- Signed Migration Intent NOT STARTED; PostgreSQL NOT STARTED;
  Foundation Closure NOT ENTERED. No Git commit in this turn.

## Current inserted stage — Core invariant remediation BLOCKED / STOP

- F1/F2/F3/F4/F9 were reproduced before bounded fixes. One independent-review
  rework completed; final full suite 367 passed / 4 legacy direct-DB skips,
  compile and diff checks pass. See `CONTROL_PLANE_R1_CORE_INVARIANT_REPORT.md`
  and `evidence/r1-core-invariants/`. This is not a database acceptance result.
- F1/F2/F4/F9 CLOSED in the current bounded implementations. Independent A/B/C
  report PASS with no in-scope P0/P1/P2; their initial findings and completed
  re-reviews are preserved. Reviewer A's completed final report was verified
  on disk after its final-message delivery was blocked by the platform.
- Shared fencing is fixed, but production current-R1 F3 remains OPEN: no
  coordinator exists to accept. Overall remediation is BLOCKED; stop without
  extending implementation scope or claiming production commit acceptance.
- Windows Identity & Trust Boundary remains **frozen PASS**, not reopened.
  Root/public/pin and the protected deployment are not being changed. No full
  Windows identity rerun is authorized without an actual scope impact.
- Signed Migration Intent is paused/NOT STARTED pending this remediation.
  If all five findings close and independent review passes, resume Signed
  Migration Intent, not Windows Identity Gate. The production R1 coordinator
  remains absent, so shared in-memory fencing tests cannot close that proof.
- PostgreSQL Acceptance NOT STARTED; Foundation Closure NOT ENTERED; no commit.

Do not infer R1 readiness from unit tests or an Alembic `heads` listing. Resume
from these blockers and the approved R1 design documents in the original
worktree. Do not modify the CASE D environment or the original dirty files.
