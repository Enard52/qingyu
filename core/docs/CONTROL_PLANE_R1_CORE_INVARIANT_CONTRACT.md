# R1 Core Invariant Remediation — bounded contract

Status: BLOCKED / STOP after one independent-review rework. Bounded A/B/C
reviews pass, but production current-R1 F3 remains unimplemented.
See `CONTROL_PLANE_R1_CORE_INVARIANT_REPORT.md`. This document does not
approve migration, provisioning, Signed Migration Intent, or Foundation Closure.

## Scope and evidence boundary

The findings are verified against the dirty implementation worktree based on
`5d4133a71df69d6c7c51644cfb54b9e410e4ab11`, not treated as findings against a
released commit. `evidence/r1-core-invariants/baseline/inventory.json` records the
pre-remediation paths and hashes; the adjacent source copies preserve the exact
service, shared Authority and client under investigation.

F1/F2/F9 concern the current Core service and its local projections. F3 concerns
the shared in-memory Authority used by isolated tests/development. The legacy
direct-PostgreSQL backend remains disabled. The production R1 Authority
coordinator, durable INTENT integration, database CAS and authenticated service
are still absent. Hardening an in-memory Authority is not production-R1 final
commit acceptance and must not be reported as such. F4 concerns the R1 client
prototype's actual TLS transport.

## Canonical write eligibility

Neither `CoreMetadata.status` nor `ControlPlaneState.status` alone authorizes a
write. They are local durable projections, not alternative Authority histories.
The Core service must refresh and validate both, the exact local GENESIS record
and completion receipt, canonical identity, epoch, storage/control-plane
generations, owner and committed state version against current Authority state.
Any quarantine, incomplete GENESIS, unavailable Authority or inconsistent
projection is a denial, not permission to repair identity from local state.

The same service predicate applies at lease acquisition, write preparation and
terminal publication; owner changes must not bypass it. Local quarantine updates
both projections and clears local lease eligibility transactionally. A failure
after an external transition remains ambiguous/quarantined until verified
reconciliation; absence of a local success receipt does not prove external abort.

Final Authority commit independently revalidates an immutable issued intent and
current lease identity, generation, expiration, epoch, storage, state version,
GENESIS and recovery eligibility under the Authority lock. A prepared permit is
not a perpetual capability. Terminal replay returns established history without
performing a new write; it cannot substitute for a missing production coordinator.

## Restore reconciliation

The local audit chain must be self-consistent AND match the manifest and current
Authority checkpoint. Sequence, hash, canonical identity, hash-bound audit state
version, owner and generations must agree. Checking only the chain's internal
hashes is insufficient. An audit row's mutable projection columns cannot replace
the values bound into its canonical hashed record.

Restore activation is a reconciliation sequence, not a single local ACTIVE bit.
The local rebase may be durably prepared while still quarantined; Authority
checkpoint reconciliation must complete before either side grants write
eligibility. Local ACTIVE/READY publication is last. A failed sync must leave
retryable, non-writable state. A retry verifies the exact request, stored rebase
and current external result; finding an ACTIVE receipt alone is not evidence of
reconciliation. No retry invents a second rebase record.

## Historical receipts

A committed mutation receipt uses the immutable audit record at its recorded
sequence and verifies that record against the canonical change identity and
committed version. Its hash is not the current global audit head. The first
response and retries before/after later mutations retain the same canonical
receipt. Missing or contradictory row bindings fail closed.

## TLS before HTTP

The R1 transport must finish TLS 1.3 CA validation, hostname validation and
SHA-256 SPKI pin verification before obtaining the bearer credential or sending
any HTTP headers/body. Every new or implicitly reopened socket passes this same
gate. There is no redirect, ambient proxy, plaintext fallback or unverified
connection reuse. Isolated loopback TLS tests observe actual server-side HTTP
bytes, including the valid-CA/valid-hostname/wrong-SPKI case.

## Frozen gates and forbidden operations

The previous Windows Identity & Trust Boundary Gate remains frozen PASS:
7,146 checks, zero failures, prior 283 passed / 4 legacy skipped, independent
review PASS. This remediation does not refresh the protected deployment or
repeat the full identity gate. Only an actual affected trust/identity component
would require a targeted impact regression.

Canonical Root/public bytes, Registry64 pin values and ACLs remain untouched;
private custody/passphrase are not read. No DB connection, Docker operation,
Alembic execution, migration edit, original-worktree edit or Git commit is
authorized here. F5/F6/F7/F8 remain out of scope.

Only all five findings CLOSED with independent Reviewer A/B/C finding no
P0/P1/P2 permits this remediation's PASS. An absent current-R1 coordinator leaves
F3 unproven and this bounded gate BLOCKED. If a later authorized action closes
all findings, the next stage is Signed Migration Intent, not a repeat Windows
Identity Gate. PostgreSQL Acceptance remains NOT STARTED; Foundation Closure
remains NOT ENTERED.
