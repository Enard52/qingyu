"""lease fencing token"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
revision: str = "0007_import_lease_fencing"
down_revision: Union[str, None] = "0006_import_job_leases"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None
def upgrade() -> None:
    op.add_column("import_jobs", sa.Column("lease_token", postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("import_jobs", sa.Column("first_started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("import_jobs", sa.Column("last_attempt_started_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_import_jobs_lease_token", "import_jobs", ["lease_token"])
def downgrade() -> None:
    op.drop_index("ix_import_jobs_lease_token", table_name="import_jobs")
    for c in ("last_attempt_started_at", "first_started_at", "lease_token"): op.drop_column("import_jobs", c)
