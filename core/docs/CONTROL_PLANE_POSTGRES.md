# PostgreSQL Control Plane

The production authority is a PostgreSQL database owned by the control-plane
service and separate from the Core database. Configure:

```text
CORE_CONTROL_PLANE_BACKEND=postgres
CORE_CONTROL_PLANE_STORE=postgresql://.../qingyu_control_plane
```

Run the authority migration explicitly:

```text
python -m app.control_plane.migration --dsn "$CORE_CONTROL_PLANE_STORE"
```

The adapter uses row locks and conditional updates for every epoch, lease,
owner, recovery, and mutation transition. `CORE_CONTROL_PLANE_STORE` must not
equal `CORE_DATABASE_URL`, and forbidden Gateway databases are rejected by
configuration validation. The authority schema is independent of Core Alembic
revision `0001_core_foundation`.
