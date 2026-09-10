from __future__ import annotations

from pathlib import Path

from app.db import Base
from app.models import (
    AuditLedger,
    ContinuityRegistry,
    CoreMetadata,
    GenesisRecord,
    IdentityRegistry,
)


def test_foundation_migration_is_pinned_and_does_not_seed_identity():
    migration = Path(__file__).parents[1] / "alembic" / "versions" / "0001_core_foundation.py"
    text = migration.read_text(encoding="utf-8")
    assert "revision = \"0001_core_foundation\"" in text
    assert "IdentityRegistry(" not in text
    assert "GenesisRecord(" not in text
    expected = {"core_metadata", "genesis_records", "identity_registry", "continuity_registry", "audit_ledger"}
    assert expected.issubset(set(Base.metadata.tables))
    env_text = (Path(__file__).parents[1] / "alembic" / "env.py").read_text(encoding="utf-8")
    assert "assert_database_safe" in env_text
    assert 'operation="migration"' in env_text
    assert "downgrade is fail-closed" in text
