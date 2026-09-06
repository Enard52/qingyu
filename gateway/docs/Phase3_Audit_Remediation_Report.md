# Phase 3 Audit Remediation

| Audit | Status | Commit | Tests | Result |
|---|---|---|---|---|
| AUD-01 | code_fixed / self_tested | pending | `tests/test_database_safety.py` + full pytest | Explicit URL allowlist and runtime `current_database()` verification |
| AUD-02 | closed / independently_verified | `01824e1` | `tests/test_aud02.py` | SourceAccount-scoped identities and synthetic missing IDs |
| AUD-03 | code_fixed / independently_verified | `6d40e0d` | `tests/test_revision_fingerprint.py` | Canonical fingerprint deployed to application and test databases; backfill verified |
| AUD-04 | code_fixed / self_tested | `2c49cd8`, `d51a702` | `tests/test_aud04_closure.py` + fencing suite | Fresh lifecycle sessions prevent caller autoflush; integrity failure is finalized only under valid ownership |
| AUD-05 | code_fixed / self_tested | `aa969e1`, `6280a11`, `9e5cada`, `d51a702` | archive corruption, processor consumption, manifest consistency tests | Attempt-local verified copy; manifest rendered atomically from committed ArchiveObject state; explicit reverify required |
| AUD-06–AUD-18 | open | — | — | Outside current P0 closure scope |

## AUD-01 verification

- Test database: `qingyu_test`
- Test URL: `postgresql+psycopg://qingyu:PASSWORD@127.0.0.1:5432/qingyu_test`
- `TEST_DATABASE_URL` must be explicitly provided.
- Query parameters capable of overriding the database target are rejected.
- A real connection must return `current_database() = qingyu_test` before tests run.
- The persistent application database `qingyu` is not used by pytest.

## Migration deployment verification

- Pre-upgrade application database: `0008_import_result_codes`
- Application database after controlled upgrade: `0011_integrity_checked_at`
- Test database: `0011_integrity_checked_at`
- Backup: `<repo>/backups/qingyu-pre-0010-20260905-195609.dump` (custom format; TOC verified)
- Existing revision fingerprints with NULL after backfill: `0`
- `archive_objects.integrity_error` column: present
- `archive_objects.integrity_checked_at` column: present

## AUD-04-C and AUD-05-B self-test

- `ImportProcessor` raises a structured integrity mismatch without mutating `ArchiveObject` in its caller session.
- Archive integrity failure and Job failure are committed together in a fresh, ownership-checked transaction.
- A stale worker cannot change ArchiveObject, Job, or manifest state; a new valid owner can record the failure.
- Fenced lifecycle helpers use fresh sessions, so they cannot commit unrelated dirty objects from the caller session.
- Manifests are rendered through one shared function from committed `ArchiveObject` state and written with a temporary file plus atomic replace.
- Targeted tests: `16 passed`.
- Full test suite, after `current_database() = qingyu_test` verification: `47 passed`, 2 dependency deprecation warnings.
