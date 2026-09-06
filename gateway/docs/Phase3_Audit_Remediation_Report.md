# Phase 3 Audit Remediation

| Audit | Status | Commit | Tests | Result |
|---|---|---|---|---|
| AUD-01 | code_fixed / self_tested | pending | `tests/test_database_safety.py` + full pytest | Explicit URL allowlist and runtime `current_database()` verification |
| AUD-02 | closed / independently_verified | `01824e1` | `tests/test_aud02.py` | SourceAccount-scoped identities and synthetic missing IDs |
| AUD-03 | code_fixed / independently_verified / deployment_pending | `6d40e0d` | `tests/test_revision_fingerprint.py` | Canonical full revision fingerprint; application DB migration pending |
| AUD-04 | code_fixed / self_tested | pending | `tests/test_aud04_closure.py` + fencing suite | Required job/token path, `clock_timestamp()` ownership, fenced report/count finalization |
| AUD-05 | partially_fixed | `aa969e1` | archive corruption regression | Processor consumption and manifest consistency pending |
| AUD-06–AUD-18 | open | — | — | Outside current P0 closure scope |

## AUD-01 verification

- Test database: `qingyu_test`
- Test URL: `postgresql+psycopg://qingyu:PASSWORD@127.0.0.1:5432/qingyu_test`
- `TEST_DATABASE_URL` must be explicitly provided.
- Query parameters capable of overriding the database target are rejected.
- A real connection must return `current_database() = qingyu_test` before tests run.
- The persistent application database `qingyu` is not used by pytest.
