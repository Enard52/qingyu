# Phase 3 Audit Remediation

| Audit | Status | Commit | Tests | Result |
|---|---|---|---|---|
| AUD-01 | code_fixed / self_tested | pending | `tests/test_database_safety.py` + full pytest | Explicit URL allowlist and runtime `current_database()` verification |
| AUD-02 | closed / independently_verified | `01824e1` | `tests/test_aud02.py` | SourceAccount-scoped identities and synthetic missing IDs |
| AUD-03 | code_fixed / independently_verified | `6d40e0d` | `tests/test_revision_fingerprint.py` | Canonical fingerprint deployed to application and test databases; backfill verified |
| AUD-04 | code_fixed / self_tested | `2c49cd8` | `tests/test_aud04_closure.py` + fencing suite | Required job/token path, `clock_timestamp()` ownership, fenced report/count finalization |
| AUD-05 | code_fixed / self_tested | `aa969e1`, `6280a11`, `9e5cada` | archive corruption, processor consumption, manifest consistency tests | Attempt-local verified copy; DB/manifest integrity state consistent; explicit reverify required |
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
- Application database after controlled upgrade: `0010_archive_integrity_error`
- Test database: `0010_archive_integrity_error`
- Backup: `<repo>/backups/qingyu-pre-0010-20260905-195609.dump` (custom format; TOC verified)
- Existing revision fingerprints with NULL after backfill: `0`
- `archive_objects.integrity_error` column: present
