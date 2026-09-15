# Control Plane R1 Owner Contract / 所有权合同

Status: **Trust Bootstrap design contract; implementation and PostgreSQL acceptance pending**.
Scope: the new, isolated R1 Authority target only. This document does not
authorize provisioning, migration, legacy database access, or Foundation
Closure. Its controlling sources are the approved
`<repo>\core\docs\CONTROL_PLANE_R1_REMEDIATION_PLAN.md` §§12–13 and
`<repo>\core\docs\adr\CONTROL_PLANE_R1_BASELINE_PROVENANCE.md`.

## Decision and threat boundary

Choose **B: a separate `NOLOGIN` schema owner owns the database and every R1
Authority object; a distinct migration login temporarily assumes that owner
only for an independently authorized migration job**. Reject A (permanent
migrator ownership of all objects). A would leave the credential used by jobs
as an enduring owner and make post-job credential exposure sufficient to alter
the Authority catalog. B keeps the runtime credential out of the owner path
and permits the migration credential's owner-assumption membership to be
disabled outside a bounded job.

This is not a claim that PostgreSQL can restrict an owner to a list of DDL
statements: during an authorized `SET LOCAL ROLE control_plane_owner` window,
the migration session has full owner powers. Its containment requires an
offline, short-lived job identity; a preverified Operator-Root-signed intent
and exact migration artifact; an isolated target; a single transactional
migration; post-migration catalog/ACL attestation; and credential and role
membership deactivation when the job ends. If any element is absent, the
Authority remains non-serving. Runtime, read-only, Core, and AI-agent
credentials never gain an owner-assumption path.

The signing Operator Root is cryptographic authorization, **not** a PostgreSQL
login or a substitute for database privileges. The `operator` database role
is for a separately approved break-glass workflow and has no ordinary data,
DDL, or `SET ROLE owner` entitlement. Neither an AI agent nor an application
request can turn an operator signature into an unrestricted SQL session.

## Canonical roles

The five names are pinned by the signed provisioning `role_policy` and must be
distinct from one another and from legacy `qingyu_control_app`:

| Signed duty | PostgreSQL role | Baseline policy |
| --- | --- | --- |
| `owner` | `control_plane_owner` | `NOLOGIN`, owns new R1 database and Authority objects; no application credential. |
| `migrator` | `control_plane_migrator` | Dedicated `LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS`; may `SET ROLE` to owner **only** for an approved migration job, never inherited by runtime. |
| `service` | `control_plane_app` | Dedicated `LOGIN NOINHERIT` with the same negative role attributes; non-owner, no DDL, no base-table/sequence DML; only reviewed procedure execution and restricted view reads. |
| `read_only` | `control_plane_reader` | Dedicated `LOGIN NOINHERIT` with the same negative role attributes; only explicitly approved restricted-view `SELECT`; no write-capable procedure execution, DDL, base-table or sequence access. |
| `operator` | `control_plane_operator` | Separate `NOINHERIT` break-glass workflow identity; no automatic owner/migrator/service membership or ordinary SQL mutation grant. Its login policy and any exceptional action require a separate signed runbook, not implicit R1 runtime access. |

All five role OIDs, names, login and special attributes, inheritance flags,
membership graph, grant options, and effective privileges are observed on the
**new** target. A role name alone is not provenance. In particular, the owner
membership for the migrator must have no automatic inheritance or membership
administration option. It may allow explicit `SET ROLE` solely while the
independent migration authorization is live, and must be removed or disabled
afterward. Whether a later migration needs a new bounded membership is a new
authorization event. The service, reader, and operator must not be members of
owner or migrator, directly or transitively. Every PostgreSQL role implicitly
receives privileges granted to `PUBLIC`; this is not role membership. Its
effective grants must be constrained below.

## Ownership matrix

| Object class | Intended owner | Non-owner boundary |
| --- | --- | --- |
| New R1 database | `control_plane_owner` | `migrator` has only explicit connection and time-bounded owner-assumption ability; `PUBLIC` has no database `CREATE` or `TEMPORARY`. |
| `control_plane` schema | `control_plane_owner` | `PUBLIC` has no `USAGE` or `CREATE`; service/reader get only `USAGE`, never `CREATE`. |
| All `control_plane.cp_*` base/partition tables | `control_plane_owner` | No direct service/reader/operator base-table DML or arbitrary `SELECT`; reviewed owner-owned routines and views mediate access. |
| All Authority sequences and identity generators | `control_plane_owner` | No service/reader/operator `USAGE`, `SELECT`, `UPDATE`, or ownership. |
| All Authority functions/procedures | `control_plane_owner` | `PUBLIC` has no `EXECUTE`; only reviewed, named, signature-qualified procedures get explicit service `EXECUTE`. `SECURITY DEFINER` routines pin a safe `search_path` and validate authenticated scope. |
| All restricted Authority views | `control_plane_owner` | Explicit, named `SELECT` only for the role and columns/data surface approved for service or reader. No view may act as an unreviewed base-table bypass. |
| `public.cp_alembic_version` | `control_plane_owner` | Administrative migration metadata, not runtime data. No service/reader/operator DML or `SELECT` by default; `PUBLIC` has no table grant. Owner-assuming migrator performs Alembic version writes. |
| `public` schema | Inspect actual owner/ACL; normally database-owner-controlled on the intended PostgreSQL profile | This is **not** the Authority data schema. `PUBLIC` must not retain `CREATE`; no permanent migrator-specific `CREATE` grant. A mismatched owner/ACL is a pre-migration blocker, not a reason for ad hoc widening. |

The ownership rule includes tables, indexes, constraints' backing objects,
sequences, views, materialized views if later approved, functions, and future
revision objects. Object ownership and role grants are part of the expected
versioned **actual PostgreSQL catalog fingerprint**, not inferred from the
authored-DDL digest. No witness/quorum objects or legacy marker are imported.

## Initial Alembic version-table path

The first revision remains parentless `0001_control_plane_r1_initial` in the
independent Authority Alembic environment. Its version table is deliberately
`public.cp_alembic_version`: Alembic can create it before the initial revision
creates `control_plane` in the **same** migration transaction. This is an
administrative exception to the schema location, **not** an ownership exception.

The migration entrypoint must, in order:

1. Verify the machine-pinned Operator Root, signed provisioning intent and
   observed completion, exact artifact digest, revision and DDL snapshot
   **before database connection**. Independently inspect the intended isolated
   target; do not trust a manifest's self-asserted volume/TLS/key identity.
2. Connect as `control_plane_migrator`; prove `session_user` and `current_user`
   are that role, read-only-check the signed database/cluster/role identities,
   pristine lineage, `public` owner and ACL, membership graph, and exact
   pre-migration privilege baseline. This stage emits no DDL/DML.
3. Start one PostgreSQL transaction for the **entire** Alembic run. Only after
   all read-only admission checks pass, recheck the target identity and empty
   lineage under the migration transaction's serialization guard, then use
   transaction-local `SET LOCAL ROLE
   control_plane_owner` **before** Alembic can create the version table or run
   the revision. Prove `session_user` is still migrator and `current_user` is
   owner. `public` must already permit this owner to create the version table
   without granting `CREATE` to `PUBLIC` or a permanent migrator grant.
4. Under that owner identity, Alembic creates `public.cp_alembic_version`, the
   initial revision creates `control_plane` and all Authority objects, and
   Alembic writes the canonical revision row. Do **not** reset the role inside
   `upgrade()` before Alembic's version write. On rollback, all catalog/row
   effects roll back; on transaction end, the local role assumption ends.
5. Before any service readiness, independently inspect actual owner OIDs,
   grants, default privileges, `search_path`, relation/function/view inventory,
   version row and full catalog fingerprint; compare with the signed expected
   fingerprint and create the separate signed migration completion attestation.
   A commit without that attestation remains non-serving and is reconciled by
   the same authorization ID, never stamped or adopted.

The current draft does **not** implement this path: it switches role inside
`upgrade()` and resets before Alembic's version write. Under the expected
Alembic creation order, that would leave `public.cp_alembic_version`
migrator-owned; this remains an untested static finding, not an observed R1
catalog result. Its migration entrypoint also
remains intentionally hard-stopped pending the independent target inspector.
This contract requires a separately reviewed code/artifact update before any
R1 database can be created or migrated. It does not approve the current draft
as a signed migration artifact. The `SET LOCAL ROLE` timing, version-table
creation and write order, one-transaction rollback behavior, and absence of a
permanent `public` privilege leak require real PostgreSQL verification later;
static inspection cannot mark the pre-migration privilege gate PASS.

If an actual target's `public` schema ownership/ACL cannot support this
owner-owned version-table path, stop. Do not add permanent `PUBLIC CREATE`,
make the migrator an enduring object owner, move the version table behind
Alembic's back, or provision a workaround database. A revised, signed
pre-migration design would be required.

## Grant and default-privilege boundary

Before migration, revoke/verify database `CONNECT`, `CREATE`, and `TEMPORARY`
from `PUBLIC`, granting `CONNECT` only to explicitly approved R1 roles; revoke
schema `public` `CREATE` from `PUBLIC`; and verify no service/reader/operator
owner membership or effective DDL. The owner can create in `public` only to
support its owner-owned version table; the Authority objects live in
`control_plane`. `search_path` for all five roles is deterministic and contains
no attacker-writable schema before trusted schemas. An inherited or default
grant that restores `PUBLIC`/service/reader capabilities fails preflight.

During migration, the owner installs explicit ACLs and default privileges in
the same transaction. In particular, PostgreSQL's default `PUBLIC EXECUTE` on
new functions must be revoked at the **owner's global default-privilege
level**; a per-schema revoke alone does not cancel a global default grant.
Existing functions also require explicit `REVOKE EXECUTE FROM PUBLIC` before
commit. Tables, sequences, schemas, views, routines, and the version table
must have catalog-verified final ACLs. Grant only named service procedure
`EXECUTE` and restricted-view `SELECT`; grant the reader only its approved
restricted-view `SELECT`. No default grant should silently extend these to
future objects. Future migrations must repeat this review for every new
function or view.

After migration, test effective privileges as each real role, not only stored
GRANT text: service procedure success and base-table/sequence/DDL denial;
reader restricted-view success and write/procedure/DDL denial; both roles'
`SET ROLE owner` failure; operator ordinary mutation denial; `PUBLIC` create,
temporary, function-execute and unexpected view/table access denial. Check
owners, `rolinherit`, transitive memberships, grant options, `search_path`,
`pg_default_acl`, database/schema/relation/routine ACLs, and actual negative
operations. Temporary test actions must be transactionally rolled back on the
new isolated acceptance target only. The migration-role positive DDL test
belongs to the authorized migration window; it must not grant runtime DDL.

This yields **two distinct gates**: a pre-migration privilege preflight may
permit the first migration on a new, signed, isolated target, but it is not
Implementation Gate PASS. Post-migration actual catalog and role-behavior
acceptance plus independent Reviewer A/B/C remain mandatory. No static test,
snapshot digest, or simulated database can substitute for those observations.

## Static validation proposal and unresolved implementation gaps

Static tests should parse the five signed duty names and reject a missing or
duplicate role; assert parentless revision identity and fixed version-table
location; assert the role switch occurs after all admission checks but before
`context.run_migrations()` and is not reset in the revision; reject grants to
`PUBLIC`, service/reader direct base-table or sequence DML, and unqualified
`SECURITY DEFINER` execution paths; and bind this contract (or its canonical
policy representation) into the signed migration artifact/expected fingerprint.
These tests are a guard against drift, **not** live PostgreSQL proof.

Open blockers before database creation: the current revision lacks reviewed
`SECURITY DEFINER` procedures, restricted views, service grants and safe
default-privilege policy; the complete expected actual-catalog fingerprint
has not been computed or signed; the independent target inspector is not
installed; and the owner-owned version-table path above is not implemented.
Therefore this owner design can be reviewed now, but migration and permission
acceptance remain **BLOCKED**.

PostgreSQL 16 semantics referenced by this design: [transaction-local `SET
ROLE`](https://www.postgresql.org/docs/16/sql-set-role.html), [role
membership `SET`/`INHERIT` options](https://www.postgresql.org/docs/16/role-membership.html),
[`pg_database_owner` and initial `public` schema
ownership](https://www.postgresql.org/docs/16/predefined-roles.html), and
[global versus per-schema default
privileges](https://www.postgresql.org/docs/16/sql-alterdefaultprivileges.html).
