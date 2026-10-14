# Core Database Safety Gate

Core database operations are fail-closed. The configured database URL must use
`CORE_DATABASE_URL`; a generic `DATABASE_URL` is never read by Core.

Before migrations, tests, acceptance fixtures, or destructive cleanup, the
process queries `current_database()` and compares it with the URL database name.
The following names are always rejected:

`qingyu`, `qingyu_test`, `postgres`, `template0`, `template1`, and any unknown
or non-Core database.

Automatic writes are permitted only for explicitly named Core test databases:
`qingyu_core_test` and `qingyu_core_acceptance`. Production and development
deployments require an external control-plane authority and never auto-create a
database or identity.

