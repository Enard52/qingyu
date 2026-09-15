# Control Plane R1 Initial Signed Intent V2 / 初始签名意图合同

Status: **static trust-bootstrap implementation draft; no executable target
admitted**. A separate acceptance-only amendment authorizes operator-invoked
test Root creation on this Windows host; this document itself authorizes no
database/container/role provisioning, migration, Gateway access, or Foundation Closure. The controlling
design is `<repo>\core\docs\CONTROL_PLANE_R1_REMEDIATION_PLAN.md` §13,
its baseline-provenance ADR, and `CONTROL_PLANE_R1_OWNER_CONTRACT.md`.

## One initial Root-signed authorization

The initial provisioning intent is **one** Ed25519 Operator-Root-signed
envelope, not a second competing migration approval. Its envelope has exact
`version`, `key_id`, `payload`, `signature` fields and **version 2**. The
signature is over `QINGYU-CP-R1-PROVISIONING-INTENT\x00 || JCS({version,
key_id, payload})`, using the pinned immutable Root's public key. `key_id`
must match that Root. Version 1 was only an uncommitted draft and is rejected
for initial executable admission; no grandfathering or TOFU path exists.

The exact signed V2 payload binds the one-time provisioning UUID; Authority
domain/instance/generation; acceptance or production profile and test-only
flag; intended isolated deployment, database and TLS origin; five distinct
roles and versioned role policy; receipt-key slot and creation policy;
immutable operator-root key ID; `0001_control_plane_r1_initial`; versioned
expected **actual catalog** fingerprint; the initial migration artifact,
authored-DDL snapshot, first-party dependency-source and schema-contract
digests; and an explicit `{approval_id, decision, approved_at}` operator
approval. The only accepted decision is
`APPROVE_R1_INITIAL_PROVISIONING_AND_MIGRATION`. Its timestamp is canonical
UTC. All fields are mandatory; unknown fields fail closed.

The later Root-signed completion manifest is also envelope **version 2**; a
version-1 completion draft is rejected. It is a *fact-observation completion*
for this same provisioning intent, not a replacement approval. It echoes all
four content digests, their versions, the schema fingerprint and operator
approval, and adds only facts that were unknowable before creation (system
identifier, OIDs, creation event, receipt key identity, storage identity and
cluster binding). It cannot rewrite the intent. The full signed intent and
completion envelopes form the origin digest defined by §13. Any completion
without a pre-existing signed intent is inadmissible.

## Byte and digest boundary

The authored-DDL digest pins the revision-owned SQL compilation and fixed
prefix/suffix statements; it is **not** a live catalog fingerprint. The V2
artifact digest is SHA-256 over domain
`QINGYU-CP-R1-INITIAL-MIGRATION-ARTIFACT-V2\x00`, the framed exact revision
ID, then fixed ordered POSIX-relative path and raw-byte pairs from
`INITIAL_MIGRATION_ARTIFACT_SOURCES`. Each frame is an unsigned big-endian
64-bit length followed by that many bytes. The artifact includes the
Alembic config/environment/revision, snapshot, provisioning and pin code,
including the native read-only `r1_windows_acl.py` dependency,
the transitive first-party import chain (`app/__init__.py`,
`app/control_plane/__init__.py`, `authority.py`, `app/canonical.py`,
`app/errors.py`), `r1_protocol.py`, `pyproject.toml`, and both contract
documents. There is no mutable digest constant inside that artifact: the
operator signs the digest of a frozen release, and runtime recomputes it.
The digest path statically scans imports from every bound Python source and
fails if an existing first-party `app.*` module or package initializer is
reachable but unlisted. Bare dynamic `__import__` calls and any `importlib`
or `builtins` import in that boundary fail closed, including aliased imports,
since their targets cannot be proven by the fixed source list. This is a
conservative static guard, not a proof against every possible Python dynamic
execution construct; exact signed source bytes remain the final drift check.

The separately signed dependency-source digest uses the same framing and
domain `QINGYU-CP-R1-INITIAL-MIGRATION-DEPENDENCIES-V1\x00` over the fixed
first-party Python import closure plus `pyproject.toml`. The separately signed
schema-contract digest uses domain `QINGYU-CP-R1-SCHEMA-CONTRACT-V1\x00` over
both exact contract documents. Each digest is checked independently as well
as being covered by the full artifact. Mutation of the revision, snapshot,
dependency module or contract document after signing must fail. A snapshot
edited together with its expected code constant is still rejected by the
Root-signed exact-byte artifact.

These source digests **do not freeze resolved third-party wheel versions**:
`pyproject.toml` has ranges and this worktree has no lockfile. A future
provisioning/migration deployment must freeze and attest the exact installed
dependency closure before executable admission. A source digest alone cannot
be reported as dependency closure PASS.

## Verification versus admission

`verify_signed_intent` checks the V2 signature and signed structural fields.
`verify_signed_initial_migration_intent` additionally recomputes the four
local release digests. Both are **necessary pure checks, not executable
admission**. Neither proves that the public key came from a genuine
machine-protected 64-bit HKLM pin, that the private key remains in approved
custody, that Docker/TLS/key-store identities are observed independently, or
that the expected actual catalog fingerprint is achievable. Those facts are separate
fail-closed gates. This static V2 contract must be wired into the independent
provisioner and migration entrypoint, alongside all other independent gates,
**before** either is allowed to create or connect to a new R1 target. The
migration entrypoint remains hard-stopped until those gates and the
owner-owned version-table path are reviewed.

For `R1_ACCEPTANCE_TEST_ONLY` only, approved custody is a distinct
ACL-protected, encrypted operator file outside Git on the same Windows
acceptance host, not an independent offline workstation. The passphrase never
becomes an application or migration secret. Application/API/migration
processes must not read the private file or run under the operator principal;
if that separation is not demonstrated, executable admission remains blocked.
This is a narrow acceptance-only amendment to the original remediation plan
§13's offline-location language, not a relaxation of signature or pin checks.
The future production Root still requires a separate offline ceremony and
must never adopt or promote this test Root. The signed payload's
`R1_PERSONAL_PRODUCTION` is the Authority reliability profile, not the Root
pin profile; acceptance still requires the explicit environment and test-only
flag.

`verify_signed_origin` verifies the two Root signatures and their exact
cross-binding, but likewise does **not** implicitly perform the local-byte
or live-target checks. A future caller must explicitly perform them all;
holding a `VerifiedOrigin` object alone is not authorization to connect or
migrate.

No live database, migration or privilege evidence has been produced by these
tests. The final Implementation Gate still requires isolated PostgreSQL
pre-migration privilege PASS, actual migration, post-migration catalog/ACL
attestation, retry/crash tests, and independent Reviewer A/B/C PASS.
