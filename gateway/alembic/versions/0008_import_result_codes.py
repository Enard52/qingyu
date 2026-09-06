"""separate lifecycle and result codes"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
revision: str = "0008_import_result_codes"
down_revision: Union[str, None] = "0007_import_lease_fencing"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None
def upgrade() -> None:
    op.add_column("import_jobs", sa.Column("result_code", sa.String(64), nullable=True))
    op.add_column("import_jobs", sa.Column("error_code", sa.String(64), nullable=True))
def downgrade() -> None:
    op.drop_column("import_jobs", "error_code"); op.drop_column("import_jobs", "result_code")
