# Control Plane Authority Runbook

The production authority is a PostgreSQL-backed service with its own database,
database owner, application credential, migration history, and backup policy.
It is a governance service, not a second Core database.  It stores identity and
continuity binding, storage and authority generations, owner/lease fencing,
recovery claims, operation state, and monotonic checkpoints.  It never stores
messages, Gateway evidence, user models, memory state, runtime transcripts, or
persona state.

## Database boundary

`CONTROL_PLANE_DATABASE_URL` must resolve to an explicitly provisioned Control
Plane database.  It must not target `qingyu`, `qingyu_test`, `postgres`,
`template0`, `template1`, Core databases, or Gateway databases.  Migration and
destructive acceptance fixtures must first execute `SELECT current_database()`
and compare the result with the approved allow-list.  The Core backup unit does
not include this database.

The migration credential owns the Control Plane schema and its Alembic history.
The application credential can perform only normal authority operations; it has
no database creation, drop, schema ownership, migration DDL, Gateway, Core
migration, or superuser privileges.  Credentials are supplied through the
environment or a secret store and are never committed or logged.

## Authority lifecycle and CAS

Enrollment is explicit: the authority binds the opaque identity UUID, opaque
continuity UUID, GENESIS fingerprint, initial owner fingerprint, and storage
generation.  Migration creates no Qingyu identity.  `qingyu-main` is an alias
outside this authority key space.

Recovery operations use a stable operation ID.  The transition is strictly
`PREPARED -> COMMITTED` or `PREPARED -> ABORTED`.  A conditional PostgreSQL
update or unique recovery-claim constraint under a row lock is the
linearization point: the transaction that first commits the current-continuity
claim is the sole winner.  A second operation receives a deterministic conflict
and cannot activate a writer.  A repeated operation ID returns its existing
state, allowing clients to reconcile uncertain responses without creating a
second generation or epoch.

Authority commit is separate from Core local finalization.  The service records
operation ID, authority state, Core mutation receipt, and audit checkpoint, then
reconciles after restart.  A timeout never permits a guessed epoch or a new
operation.  If authority is unavailable, governance writes fail closed; no
memory, local-file, Core-row, or cached-authority fallback is valid.

## Backup and disaster recovery

Authority backups are a separate unit from Core backups.  Restoring a database
dump does not by itself activate an authority.  An operator must verify the
latest monotonic checkpoint, generation, owner record, and audit/provenance
checkpoint, then issue an explicitly authorized activation for a newly
identified authority instance.  The old authority endpoint must be revoked or
fenced before the restored authority becomes active.  Until that ceremony is
complete, Core writers remain read-only/fail-closed.  This prevents an old and
restored authority from both granting writer leases.

## Acceptance evidence

Run the opt-in PostgreSQL tests with a newly migrated database:

```powershell
$env:CONTROL_PLANE_DATABASE_URL = "postgresql+psycopg://<app>@127.0.0.1:5432/<fresh-control-db>"
python -m pytest tests/test_control_plane_postgres.py -q
```

The test module rejects protected database names, verifies migration isolation,
checks restart persistence, and exercises concurrent recovery.  Do not use a
Gateway/Core database as the acceptance target, and remove the temporary
acceptance database only after its resolved name has been revalidated.
