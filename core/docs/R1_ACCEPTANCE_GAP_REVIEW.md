# R1 Acceptance Marathon — Phase 2 Gap Review

Status: **BLOCKED**. This is a read-only investigation report, not an amendment,
implementation approval, new frozen candidate, or final acceptance review.

## R1-MARATHON-C01 — GENESIS preactivation abort contradiction

Three existing rules cannot all be satisfied for the first authoritative GENESIS:

1. GENESIS durably enters PREPARED before continuity activation. PREPARED does
   not consume a terminal sequence.
2. Once the original credential is revoked, an Operator-Root-signed
   FORCE_ABORT_PREPARED must resolve every operation type, individually, with
   an ordered signed ABORTED terminal. It cannot force commit.
3. Generation 1, terminal sequence 1 only accepts AUTHORITY_GENESIS_ACTIVATION
   with COMMITTED / ACTIVATED and the signed provisioning origin.

Consequently an initial PREPARED GENESIS whose credential is revoked has no
legal forced terminal under the combined rules: its ABORTED terminal would be
the first terminal and is rejected. Allocating a hidden earlier receipt, skipping
sequence 1, creating a second GENESIS, silently dropping PREPARED, or automatically
committing it is not an authorized resolution.

### Exact evidence

- Original, read-only contract:
  `<repo>\core\docs\CONTROL_PLANE_R1_REMEDIATION_PLAN.md`:
  lines 259–265 (prepare/terminal allocation), 270–287 (opening), 299–306
  (ABORTED is ordered), 347–353 (GENESIS barrier), 385–393 (every operation type,
  credential revocation, ordered force-abort).
- Current implementation `app/control_plane/r1_schema.py:222–228` expressly
  persists GENESIS PREPARED before continuity existence; only its COMMITTED
  terminal creates continuity.
- Current implementation `app/control_plane/r1_protocol.py:395–409` explicitly
  rejects an ABORTED generation-1 opening with `invalid genesis opening`.
- Lead independently reproduced the structural contradiction:
  `docs/evidence/r1-acceptance-marathon/genesis-abort-probe.json`.
  The probe uses public dummy identifiers and placeholder signature-shaped
  strings. It checks receipt shape only: COMMITTED / ACTIVATED is accepted,
  ABORTED is rejected. It does not create or verify a real signature, generate a
  Root, access private material, or connect to a database.

### Disposition and required authorization

**OPEN / shared contract decision required.** The user explicitly requires STOP
on a blocker that cannot safely proceed under existing contracts. No product
or migration bytes were changed, and no option below was selected:

- A precisely bounded opening-operation exception, with an explicit safe
  preactivation retirement and retry contract;
- Separate authenticated preactivation abort/retirement evidence, whose relation
  to canonical history and identity reservations must be designed;
- A versioned change to opening/terminal-sequence semantics, with corresponding
  trust, replay, migration, and Core reconciliation consequences.

The next design authorization must resolve same-ID retry, duplicate GENESIS
prevention, immutable identity reservation, credential-revocation proof, durable
abort evidence, restart behavior and sequence/head semantics together. These
are decision topics, not approved changes. Production implementation resumes
only after that decision is reviewed and frozen.

This does not reopen the previously CLOSED F3 scope. F3 covered mutation
coordination from an already admitted GENESIS and active lease; it explicitly
excluded the initial issuance/forced-resolution paths examined here.

## Remaining production gaps disposition

Contract line references below refer to the original read-only R1 remediation
plan unless a different file is named. Required means still required for the
overall gate; it does not mean implemented or passed this turn.

| Capability | Disposition | Required boundary / evidence |
| --- | --- | --- |
| GENESIS issuance | REQUIRED FOR R1 GATE; blocked by C01 | Authorized durable prepare and terminal, initial Core audit/checkpoint; no fixture/bootstrap SQL authority. Plan 153–159, 270–292, 796–798. |
| Lease issuance / revocation | REQUIRED FOR R1 GATE | Exact runtime/session/storage/epoch/generation scope. First lease cannot presuppose an already active lease. Plan 335–360. |
| Owner transfer / takeover | REQUIRED FOR R1 GATE | Signed authorization, owner hash/version CAS, owner/epoch transition, old lease revocation. Distinguish ownership transfer from runtime lease takeover. Plan 361–373, 827–829. |
| Core storage recovery | REQUIRED FOR R1 GATE | Target reservation, exact manifest and owner scope, atomic storage/epoch advancement and old lease revocation; READY last. Plan 335–345, 362–373, 451–463, 796–798. |
| DRAINING / FORCE_ABORT_PREPARED | REQUIRED FOR R1 GATE; blocked by C01 for opening GENESIS | Each PREPARED resolved through its authenticated same ID, no blind batch abort, no timeout inference, no forced commit. Plan 347–353, 385–393. |
| Manual Authority DR | REQUIRED FOR R1 GATE | Complete source proof, stable DR ID, new instance/key/generation, signed DR, pin transition and canary; incomplete history stays fail-closed. Plan 799–801, 831, 836. |
| Production deployment inspector | REQUIRED FOR R1 GATE | Trusted read-only observation of real deployment/token/trust/target/catalog; mismatch rejects, never auto-fixes. Marathon Phase 5/19. |
| Cross-continuity global chain synchronization | DEFERRED BY CONTRACT only after explicit single-continuity restriction is implemented and reviewed | Marathon Phase 4 authorizes the minimal single-continuity option. Config/API/runtime/GENESIS/session/DB must reject a second continuity before effects. Current scope restriction is not yet established and cannot be claimed PASS. Future multi-continuity phase requires a new protocol authorization. |
| Same-continuity governance receipt reconciliation | REQUIRED FOR R1 GATE even if multi-continuity is deferred | Local consumption must distinguish governance from mutation and validate historical scope/epochs without dropping chain rows. Single-continuity does not eliminate this requirement. |
| Independent durable zero-RPO infrastructure | DEFERRED BY CONTRACT | Plan 483–487 permits later infrastructure work; missing complete source proof permanently fails closed rather than reconstructing Authority truth from Core. Future independent durability phase, separately authorized. |
| Concurrent multiple Authorities / automatic election | NOT APPLICABLE TO R1 | Plan 839–841 assigns the multi-Authority design to R2. R1 cannot admit competing active Authorities or imply automatic failover. |

The recommended minimal Phase 4 direction is explicit single-continuity R1,
not a claim that today's code already enforces the complete boundary. No
architecture amendment or code for either option was written this turn.

## Implementation gap observations, not new F3 regressions

- `app/r1_service.py` rejects unsupported lifecycle entry points;
  `r1_commands.py` / `r1_coordinator.py` currently execute mutation intent.
- The F3 test-only SQL assumes a previously committed GENESIS plus active lease.
  It is not the canonical production migration artifact.
- `app/r1_local_store.py` currently projects post-GENESIS receipts as mutation
  and compares historical receipt epochs to current scope. Typed governance
  reconciliation is required before extending production flows.
- `app/config.py` currently excludes later Authority generations; manual DR
  requires a designed admission path, not relaxation of a numeric check alone.
- `r1_admission.py` defines an inspector interface and synthetic observations;
  this is not evidence of a real production inspector. Existing protected
  Windows ServiceHost deployment is a probe, not an admitted Authority runtime.
- Migration currently stops before connecting to a database. That fail-closed
  state was preserved.

## Preserved planning from read-only analysts

### Artifact / catalog dependency order

Source for the canonical migration, catalog serializer, candidate manifest,
verifier, deployment inspector and exact dependency closure must be implemented
and reviewed before candidate freeze. Phases 9–10 may derive and verify artifacts
from frozen bytes; they cannot introduce unbound product changes after signing.
Candidate identity must not recursively include itself or the later commit ID.
The subsequent Signed Intent binds both the established commit and candidate
digest. No candidate/artifact/catalog fingerprint was minted in this turn.

### Ownership and actual privilege acceptance

Preserve `control_plane_owner = NOLOGIN`. The approved migrator session must
enter owner capability before Alembic creates its version table and retain the
correct owner context through revision persistence. An Owner test means an
authorized migrator connection with temporary SET ROLE plus a direct owner
LOGIN-denial test; it does not mean enabling owner LOGIN.

Temporary membership requires a real grant/execute/revoke lifecycle with
crash recovery and independent cleanup evidence. NOINHERIT, transaction-local
SET ROLE, VALID UNTIL, or a language finally block alone do not establish that
the underlying membership is time-bounded. Operator privileges remain bounded
by the signed contract, not an improvised login capability.

Expected catalog must cover schemas, relations, columns/types/defaults/generated
expressions, constraints/indexes, sequences and owned columns (including the
origin sequence), functions/definitions/security/search_path, views/triggers,
owners/ACL/default privileges, Alembic version table/revision and role policy.
OID/time/physical identity observations belong in separate provenance evidence,
not the deterministic catalog identity. Actual catalog is obtained only from
the real authorized post-migration target.

### Signed evidence and user ceremonies

The existing signed chain distinguishes authorization, provision-completion
evidence after the target exists, and post-migration attestation. These are
different factual events: no signature may pre-certify unknown future facts.
The final payload needs explicit binding to candidate Git commit/digest,
artifact/dependencies/catalog, target class, profile and Root fingerprint.
Any required schema extension must be reviewed before freeze.

### Read-only production inspector

Observe actual executable/module/dependency bytes, protected manifest and file
inventory, ancestor paths/reparse/ACL state, SCM identity and actual runtime
process/token, public Root/Registry64 pin, profile/origin/SPKI, and verified
database identity/marker/revision/catalog. Do not accept the application's
self-reported config as independent evidence. Separate pre-migration target
checks from post-migration catalog checks. Wrong/stale/missing observations,
extra files, identity mismatch and TOCTOU must reject without modifying state.

## Team accountability

- `marathon_gap_flows`: independent read-only flow/contract classification;
  identified C01.
- `marathon_artifact_plan`: independent read-only artifact/catalog/ownership
  dependency analysis; no additional new P0/P1/P2 reported within its scope.
- `invariant_reviewer_a`: this turn only a read-only inspector gap analyst;
  no additional new P0/P1/P2 confirmed within that scope.
- Lead: public baseline, original-workspace protection, independent source
  verification and in-memory structural reproduction, report/state persistence.

No implementation Worker was dispatched. These analyses are not the Marathon
Phase 20 final A/B/C reviews and cannot substitute for actual acceptance DB
evidence. On C01 discovery, expansion stopped and already obtained findings
were retained here.
