# Phase 3 Audit Remediation

| Audit | Status | Commit | Tests | Result |
|---|---|---|---|---|
| AUD-01 | fixed / verified | pending | test database guard + full pytest | TEST_DATABASE_URL is mandatory and must contain `test`; destructive fixtures refuse other databases |
| AUD-02 | fixed / verified | 01824e1 | tests/test_aud02.py | SourceAccount scoped; synthetic identities for missing IDs |`r`| AUD-03 | fixed / verified | pending | tests/test_revision_fingerprint.py | canonical full revision fingerprint |`r`| AUD-04..AUD-18 | open | — | — | queued in mandated order |

## AUD-01 verification

- Test database: `qingyu_test`
- Test URL: `postgresql+psycopg://qingyu:PASSWORD@127.0.0.1:5432/qingyu_test`
- Persistent application database `qingyu` was not used by pytest.
- Alembic migrations were applied to the isolated test database.


