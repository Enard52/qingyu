# PostgreSQL Control Plane

The production authority is a PostgreSQL database owned by the control-plane
service and separate from the Core database. Configure:

```text
CORE_CONTROL_PLANE_BACKEND=postgres
CORE_CONTROL_PLANE_STORE=postgresql://.../qingyu_control_plane
```

The database name is an explicit allow-list (`qingyu_control_test`,
`qingyu_control_acceptance`, or `qingyu_control_prod`). Runtime configuration
rejects Gateway/Core databases, unknown names, and shared `qingyu`/`postgres`
credentials. Run migrations with a dedicated admin/migration credential, then
grant the Core runtime a separate least-privilege application role; the
runtime role must not own the schema or execute DDL.

Run the authority migration explicitly:

```text
python -m app.control_plane.migration --dsn "$CORE_CONTROL_PLANE_STORE"
python -m app.control_plane.migration --dsn "$CORE_CONTROL_PLANE_STORE" --heads
python -m app.control_plane.migration --dsn "$CORE_CONTROL_PLANE_STORE" --current --check
```

The adapter uses row locks and conditional updates for every epoch, lease,
owner, recovery, and mutation transition. Each governance operation records a
durable decision acknowledgement from two of three configured witness slots in
the independent Control Plane database; a decision is not successful without
that quorum. The authority schema is independent of Core Alembic revision
`0001_core_foundation`. The exact mutation linearization point is the commit of
the conditional `cp_domains` update; recovery claims linearize at the locked
continuity row plus the unique `cp_recovery_claims` insert.
