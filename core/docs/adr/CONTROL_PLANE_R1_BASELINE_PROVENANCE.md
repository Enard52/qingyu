# ADR: Control Plane R1 Baseline Provenance

- Status: Accepted for R1 baseline design by independent Reviewer A/B/C (P0=P1=P2=0); implementation pending separate authorization
- Scope: R1 migration origin, legacy acceptance isolation, and provenance only
- Does not authorize: implementation, database mutation/cleanup, a Git product
  commit, Foundation Closure, or entry to R1-1
- Related decision: `CONTROL_PLANE_RELIABILITY_PROFILES.md`

## Evidence and limit of inference

Read-only investigation found `qingyu_control_acceptance` (database OID
`92770`) and `qingyu_control_app` (role OID `92842`) in the existing PostgreSQL
16.15 cluster with system identifier `7682294117667672102`. That cluster runs
as `gateway-db-1` on the existing `gateway_qingyu_postgres` volume. The
acceptance database has `alembic_version = 0001_control_plane`, seven
`cp_*` tables including `cp_witnesses` and `cp_quorum_acks`, three witness rows,
and 120 acknowledgement rows. The observed table/column/constraint/index
catalog fingerprint is
`567fa036f369628ee2a9a249a0244257ba655a97f23a4874a67c9e3a01316b06`
(95 sorted entries). Its structure is consistent with the current dirty DDL.
The `qingyu_control_app` role can directly SELECT, INSERT, and UPDATE the
legacy base tables.

Git history, branches, tags, reflogs, and safely inspected unreachable commits
contain no committed independent Control Plane `0001_control_plane` Alembic
revision. The committed `0001_core_foundation` is a **Core database** revision,
not an Authority parent. The Control Plane `0001_control_plane` marker and
pseudo-Alembic CLI occur only in the nine-file uncommitted draft. An
`alembic_version` row can be produced by that code's hand-written INSERT or
other SQL; it does not prove that a canonical Alembic migration ran. No signed
provisioning manifest, provisioning UUID, stable Authority domain/cluster
marker, frozen historical schema fingerprint, or deployment attestation was
found. The observed fingerprint is a post hoc description, not a signed origin
proof. Object OIDs are supporting evidence only, not stable provenance after
restore or recreation. Existing objects and rows are real forensic artifacts;
their production/canonical Authority status is **not proven**.

## Decision: CASE D — UNPROVEN LEGACY ACCEPTANCE ARTIFACT

CASE D applies when a real database, schema, data, and version marker exist,
but the evidence needed to prove canonical Authority history is missing:
committed migration lineage, signed provisioning origin, stable Authority
identity marker, or frozen historical fingerprint/deployment provenance.
CASE D neither denies that objects exist nor promotes them to Authority truth.

`qingyu_control_acceptance` and its associated `qingyu_control_app` role are
classified **LEGACY / UNPROVEN / FORENSIC-ONLY**. They must not become an R1
Authority, an R1 migration parent, or an R1 acceptance environment. The old
database is not stamped or upgraded to any canonical revision. Its
`alembic_version`, witness tables, acknowledgements, operation/control data,
and unsafe grants are preserved unchanged as evidence. No cleanup is implied
or authorized by this ADR; any future cleanup needs its own authorization and
provenance-safe procedure. The Gateway database and volume are never an
Authority identity credential.

The old code's `0001_control_plane` string is a **legacy/unproven marker**, not
the new revision. The dirty draft must not be committed to fabricate a
historical parent. The legacy tables may be read as forensic evidence under a
separately approved procedure, but cannot issue writer ownership, generation,
receipt, or DR-head truth for R1. Default policy is **NO TRUST TRANSFER**:
neither data import nor automatic reconstruction into the new Authority is
permitted. Any future archival/export design must remain outside the new
canonical receipt and generation chain.

## New canonical migration origin

The canonical R1 Control Plane Alembic lineage starts at a newly authored,
formally reviewed and committed base revision named
`0001_control_plane_r1_initial`, with `down_revision = None` in its own
independent Authority Alembic environment. Its identity is deliberately
distinct from legacy `0001_control_plane`:

```text
legacy/unproven: 0001_control_plane           (no canonical child)
canonical R1:   0001_control_plane_r1_initial (new base; no legacy parent)
```

No `0002_control_plane_r1` is created as a child of the legacy marker. Later
R1 revisions, if required, descend only from the new canonical initial
revision. The initial revision creates no pseudo-witness or same-database
quorum structures. It creates the immutable Authority domain/cluster marker
and the R1 operation, receipt, sequence, and provenance schema specified by
the approved reliability contract. An empty canonical database is upgraded
through real Alembic history; a database containing the legacy marker, legacy
tables, unexpected objects, or a mismatched origin fails closed. There is no
stamp/adopt/repair path from the old acceptance database.

## New acceptance environment and signed origin

Freeze the new acceptance database name as `qingyu_control_r1_acceptance`.
It must be newly provisioned in a clearly isolated Authority acceptance
deployment, not inside or from the existing Gateway volume, and must not
reuse `qingyu_control_acceptance` or its legacy role/grants. Provisioning is
not authorized by this design Gate.

**Before any cluster/database/role/key provisioning action**, the operator
signs a versioned provisioning intent outside the database. It binds a
one-time `provisioning_uuid`, `authority_domain_id`, `authority_instance_id`,
initial `authority_generation = 1`, environment/profile, intended isolated
cluster deployment and exact database name, planned TLS origin, canonical
initial revision ID and expected versioned schema fingerprint, owner/migrator/
service/operator role names and policies, receipt-key slot/reference and
creation policy, and immutable operator-root identity. The intent does not
pretend to know OIDs, server system identifier, the creation-event timestamp, or
the generated receipt public-key fingerprint before those values exist.

After the intended cluster/database/roles/key are created, but **before the
first schema migration**, the operator signs a completion manifest binding
their observed TLS endpoint, server system identifier, database and owner OIDs,
provisioner-recorded creation-event timestamp, receipt public-key
fingerprint/key reference, and role
identities to the exact provisioning intent ID. Name and OID are supporting
checks, not sole provenance. The verified intent and completion are the
immutable signed provisioning origin. Its
`signed_provisioning_origin_digest` is exactly
`SHA-256("QINGYU-CP-R1-PROVISIONING-ORIGIN\x00" ||
JCS({"intent": full_signed_intent_envelope,
"completion": full_signed_completion_envelope}))`, including envelope
versions, key IDs and signatures. A completion-only or unsigned-payload digest
is invalid. That digest is written into the marker by the initial migration;
the private receipt key is never stored
in the database or manifest. If any creation occurred before a signed intent,
that environment is not admissible as a canonical R1 origin.

The initial migration atomically installs the immutable domain/cluster and
provisioning markers together with its schema and signed origin digest. The
provisioner compares the actual complete catalog fingerprint (schemas,
owners, tables, columns, constraints, indexes, functions, grants and default
privileges) with the signed expected fingerprint and records an external
signed **initial migration completion attestation**. No runtime becomes ready
before this attestation exists.

The origin intent/manifest remains an immutable genesis anchor. Every later
migration needs a new signed versioned authorization binding the exact prior
revision, attested fingerprint and authorization-chain head to the target
revision, expected fingerprint and migration artifact digest. Preflight
verifies the old state; a signed post-migration completion attestation binds
the actual new fingerprint and chain head. A crash between database commit
and external attestation remains non-serving and resumes the same migration
authorization ID after read-only verification. Runtime and every later
migration verify the full origin and signed transition chain plus the **current**
revision/fingerprint, markers, cluster and key identity. Unexpected jump,
mismatch or absent attestation fails closed. There is no name-only, OID-only,
legacy-marker, or test-fixture-only adoption.

The canonical generation `1` has no predecessor generation. Its opening
terminal receipt has sequence `1` and `previous_receipt_hash` equal to a
domain-separated SHA-256 genesis seed over the signed provisioning-origin
digest, Authority domain/instance IDs, `provisioning_uuid`, receipt key ID and
operator-root key ID, as specified in the R1 plan. It is an operator-authorized
activation and imports no legacy state. A later DR generation instead seeds
its opening receipt from the verified prior generation terminal head and binds
the signed DR artifact. Thus the new receipt/generation chain starts only at
the new canonical origin.

The new owner, migrator, service, and operator duties remain separate. The
Authority Service is the only business writer; its new service database role
has no arbitrary base-table DML and may use only reviewed procedures and
restricted views. The legacy `qingyu_control_app` grants are observations,
not templates for new provisioning.

## Implementation isolation and gate

The nine existing dirty product files and their tracked diff hash
`9594b6b6f5374094a88bcb068d5bcd7afd875d18` are preserved as legacy
draft/reference evidence. A future separately authorized R1 implementation
starts from clean HEAD in an independent Git worktree and does not layer the
canonical implementation onto the dirty main worktree. This design Gate
creates no implementation worktree.

Independent Reviewer A/B/C design reviews each found P0=P1=P2=0 for migration
history, Authority origin/receipt chain, and PostgreSQL isolation/roles/legacy
disposition respectively. The **baseline design contradiction is resolved** by
CASE D and the new parentless origin. This does not prove that the legacy
database is canonical, authorize cleanup or implementation, close Core
Foundation Commit 1, or permit R1-1 without a separate instruction.
