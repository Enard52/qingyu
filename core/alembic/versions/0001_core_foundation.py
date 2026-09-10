"""create Core identity, continuity, control-plane and audit foundation

Revision ID: 0001_core_foundation
Revises:
"""
from __future__ import annotations

from alembic import op
from sqlalchemy import insert

from app.models import Base, CoreMetadata


revision = "0001_core_foundation"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The model metadata is intentionally foundation-only. It creates schema,
    # never a Qingyu identity or Genesis record.
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)
    bind.execute(
        insert(CoreMetadata).values(
            id=1,
            status="UNINITIALIZED",
            current_state_version=0,
            audit_seq=0,
        )
    )


def downgrade() -> None:
    raise RuntimeError("Core migrations are forward-only; downgrade is fail-closed")

