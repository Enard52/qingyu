# Phase 3 Audit Remediation Report

## Scope and status

This report covers Phase 3 P1, AUD-06 through AUD-16. Every item is `self_tested`;
none is declared closed or independently verified. AUD-01 through AUD-05 remain
the accepted baseline and pass the regression suite. AUD-17 and AUD-18 remain
open and unchanged.

| Audit | Status | Commit | Migration |
|---|---|---|---|
| AUD-06 | self_tested | `0f7c4b8` | none |
| AUD-07 | self_tested | `d908912` | `0012_import_identity_constraints` |
| AUD-08 | self_tested | `d908912` | none |
| AUD-09 | self_tested | `c108de4` | none |
| AUD-10 | self_tested | `04eff03` | none |
| AUD-11 | self_tested | `0f7c4b8` | none |
| AUD-12 | self_tested | `0f7c4b8` | none |
| AUD-13 | self_tested | `d908912` | none |
| AUD-14 | self_tested | `c108de4` | none |
| AUD-15 | self_tested | `a6385ce` | none |
| AUD-16 | self_tested | `a6385ce` | none |

## AUD-06 — stale recovery stale-read race

- Original problem: recovery could act on an obsolete ORM snapshot and revoke a
  newer Worker's ownership.
- Files: `app/importers/worker.py`, `tests/test_group_a_worker_runtime.py`.
- Fix: recovery records the observed token, expiry, attempts and status, then
  issues one conditional UPDATE matching that exact expired lease and database
  wall time. Zero affected rows means the observation is obsolete.
- Tests: stale recovery cannot overwrite a newer claim; PostgreSQL recovery
  competition can transition only the observed stale lease.
- Commit/migration: `0f7c4b8`; none.

## AUD-07 — concurrent stable identity

- Original problem: SELECT-then-INSERT was not protected by database uniqueness.
- Files: `app/models.py`, `app/importers/service.py`,
  `alembic/versions/0012_import_identity_constraints.py`,
  `tests/test_group_b_identity_tree_provenance.py`.
- Fix: constraints protect SourceAccount, Message, MessageRevision and
  MessageObservation identities. `account_label` is the current stable namespace
  within a platform. Account-row locking serializes competing inserts. Synthetic
  conversation IDs include archive digest, member and source array index.
- Tests: concurrent PostgreSQL imports of one stable message produce one Message
  and safely reuse its Revision.
- Commit/migration: `d908912`; `0012_import_identity_constraints`.

## AUD-08 — tree snapshot isolation

- Original problem: observations from different Import Jobs could be combined
  into an impossible historical parent path.
- Files: `app/importers/query.py`,
  `tests/test_group_b_identity_tree_provenance.py`.
- Fix: all tree methods require `conversation_id` and `import_job_id`; joins are
  explicit and parent walking/current-path derivation stays inside one snapshot.
- Tests: adversarial snapshots cannot mix across tree, path, branch or current
  path queries.
- Commit/migration: `d908912`; none.

## AUD-09 — Windows-safe ZIP extraction

- Original problem: extraction did not reject every Windows alias, collision,
  ADS or unsupported member before writing.
- Files: `app/importers/zip_staging.py`, `tests/test_group_d_zip_archive.py`.
- Fix: prevalidate the full member table; reject traversal, absolute/drive/UNC,
  colons/ADS, reserved names, trailing dot/space, exact/case/normalized
  collisions, file-directory conflicts, symlinks and unsupported types. Extract
  with exclusive creation.
- Tests: parameterized unsafe names plus collision and symlink cases verify that
  rejection precedes every write.
- Commit/migration: `c108de4`; none.

## AUD-10 — parser prevalidation

- Original problem: shallow detection could commit early conversations before a
  malformed later item failed; candidate/parser use was ambiguous.
- Files: `app/importers/generic.py`, `app/importers/processor.py`,
  `app/importers/service.py`, `tests/test_group_c_parser_validation.py`.
- Fix: candidate discovery, parser detection and complete fixture validation run
  before persistence; the detected parser performs parsing. Multiple candidates
  are ambiguous. Validation and unknown-field reports retain member/pointer data.
- Tests: top-level arrays, invalid later conversation, unknown fields and no
  partial persistence.
- Commit/migration: `04eff03`; none.

## AUD-11 — executable Worker runtime

- Original problem: claim, heartbeat, recovery and Processor existed without a
  connected durable runtime.
- Files: `app/importers/worker_runtime.py`, `app/importers/worker.py`,
  `app/importers/processor.py`, `app/api_import.py`,
  `tests/test_group_a_worker_runtime.py`.
- Fix: `python -m app.importers.worker_runtime` provides recovery, claim,
  independent-session heartbeat, processing, fenced finalization, polling,
  exception isolation and graceful shutdown. API and Processor share a ZIP-only
  contract, and ZIP validity is detected from bytes rather than MIME.
- Tests: runtime claims and completes a real pending Job; final E2E covers POST to
  GET Job.
- Commit/migration: `0f7c4b8`; none.

## AUD-12 — bounded claim and transaction scope

- Original problem: claim scope and ownership checks risked retaining Job locks
  across slow filesystem work.
- Files: `app/importers/worker.py`, `app/importers/processor.py`,
  `tests/test_group_a_worker_runtime.py`.
- Fix: claim uses `LIMIT 1 FOR UPDATE SKIP LOCKED`. Archive copy, extraction,
  scanning and validation use fresh lock-free checks. Business writes retain
  short conversation transactions with in-transaction fencing.
- Tests: real PostgreSQL claim/ownership concurrency and the fencing regression
  suite verify bounded transactional ownership.
- Commit/migration: `0f7c4b8`; none.

## AUD-13 — exact provenance and raw pointers

- Original problem: a Job could claim unrelated unbound observations for the same
  object, and source pointers did not always address the real JSON node.
- Files: `app/archive/service.py`, `app/api_import.py`,
  `app/importers/service.py`, `app/importers/processor.py`,
  `tests/test_group_b_identity_tree_provenance.py`.
- Fix: ArchiveService returns the exact new observation ID and the API binds only
  it. Provenance records archive identity, ZIP member, array index, mapping key
  and RFC 6901 escaping (`~0`, `~1`).
- Tests: stored pointers resolve the expected node in the original fixture;
  repeated archive observations remain distinct.
- Commit/migration: `d908912`; none.

## AUD-14 — immutable archive publication

- Original problem: exists-then-replace could overwrite a concurrent object and
  file/DB/manifest crash recovery was unclear.
- Files: `app/archive/service.py`, `tests/test_group_d_zip_archive.py`.
- Fix: fsync staging, publish using create-if-absent hard-link semantics, verify
  and reuse existing targets, and serialize object-row creation with a digest
  advisory transaction lock. Object MIME is first-seen; later MIME stays in
  observation metadata. Manifests derive from committed state and regenerate.
- Tests: concurrent publication yields one object/two observations; injected
  post-publication failure recovers; missing manifest regenerates.
- Commit/migration: `c108de4`; none.

## AUD-15 — credential fail-closed behavior

- Original problem: an example/default token could become a live credential and
  comparison was not timing-safe.
- Files: `app/config.py`, `app/auth.py`, `.env.example`, `README.md`,
  `tests/conftest.py`, `tests/test_group_e_auth_privacy.py`.
- Fix: non-test settings reject empty and known example tokens; tests use
  TEST_API_TOKEN; Bearer comparison uses `secrets.compare_digest`. `.env` is
  ignored/untracked and the README documents random token generation.
- Tests: parameterized invalid-token startup and authentication log redaction.
- Commit/migration: `a6385ce`; none.

## AUD-16 — database and log privacy

- Original problem: SQL parameters and raw database exception text could expose
  chat content, credentials or Authorization values.
- Files: `app/db.py`, `app/errors.py`, `app/main.py`,
  `app/importers/processor.py`, `app/importers/worker_runtime.py`,
  `tests/test_group_e_auth_privacy.py`.
- Fix: SQLAlchemy hides parameters; API, Worker and Processor paths emit stable
  safe codes without raw exception strings or payloads.
- Tests: distinctive chat, SQL parameter and Bearer markers are absent from
  exceptions, logs and API responses.
- Commit/migration: `a6385ce`; none.

## Final P1 end-to-end verification

`tests/test_p1_e2e.py` covers authenticated POST, immutable Raw Archive, pending
Job, real Worker claim/heartbeat/process/finalize, byte verification, extraction,
registry detection, prevalidation, short conversation transactions, tree
snapshot, provenance, report/counts, fenced completion, GET Job, staging cleanup
and retained Raw Archive.

Failure paths cover unsafe ZIP, unsupported structure, parser validation error
and corrupted Archive. They assert explicit failed results and no conversation
rows. Existing fencing tests cover stale-worker takeover and prohibit obsolete
business writes or finalization.

## Database, migration and validation safety

- Destructive tests require TEST_DATABASE_URL and verify using a real connection
  that `current_database() = qingyu_test`; override-capable URL parameters are
  rejected. Pytest never uses the long-term `qingyu` database.
- New Alembic head: `0012_import_identity_constraints`.
- `qingyu_test` was upgraded to the new head. The long-term `qingyu` database was
  not upgraded and is checked read-only; deployment awaits the controlled
  migration procedure.
- Full suite: 76 passed.
- Two unsuppressed third-party deprecations originate in FastAPI/Starlette
  TestClient and AnyIO compatibility.
- P0 regression coverage remains green: database guard, account identity,
  revision fingerprints, stale-worker fencing, archive corruption rejection and
  DB/manifest consistency.
- E2E commits: `7fd0b3a` (success path) and `94a53de` (failure paths).
