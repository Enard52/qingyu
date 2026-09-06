"""add import stable identity constraints"""
from alembic import op

revision = "0012_import_identity_constraints"
down_revision = "0011_integrity_checked_at"
branch_labels = None
depends_on = None


def upgrade():
    op.create_unique_constraint("uq_source_accounts_platform_label", "source_accounts", ["platform", "account_label"])
    op.create_unique_constraint("uq_messages_conversation_external", "messages", ["conversation_id", "external_message_id"])
    op.create_unique_constraint("uq_message_revisions_fingerprint", "message_revisions", ["message_id", "revision_fingerprint"])
    op.create_unique_constraint("uq_message_observations_job_revision_node", "message_observations", ["import_job_id", "message_revision_id", "external_node_id"])


def downgrade():
    op.drop_constraint("uq_message_observations_job_revision_node", "message_observations", type_="unique")
    op.drop_constraint("uq_message_revisions_fingerprint", "message_revisions", type_="unique")
    op.drop_constraint("uq_messages_conversation_external", "messages", type_="unique")
    op.drop_constraint("uq_source_accounts_platform_label", "source_accounts", type_="unique")
