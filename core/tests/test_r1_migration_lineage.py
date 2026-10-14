"""R1 lineage and origin-admission checks; no database or DDL execution."""

from pathlib import Path
from types import SimpleNamespace

from alembic.config import Config
from alembic.script import ScriptDirectory
import pytest

from app.control_plane.r1_provisioning import INITIAL_REVISION


ROOT = Path(__file__).resolve().parents[1]


def _script(config_name: str, script_location: str) -> ScriptDirectory:
    cfg = Config(str(ROOT / config_name))
    cfg.set_main_option("script_location", str(ROOT / script_location))
    return ScriptDirectory.from_config(cfg)


def test_r1_initial_is_parentless_and_disjoint_from_core_and_legacy() -> None:
    r1 = _script("control_plane_alembic.ini", "control_plane_alembic")
    core = _script("alembic.ini", "alembic")
    assert r1.get_bases() == [INITIAL_REVISION]
    assert r1.get_heads() == [INITIAL_REVISION]
    assert core.get_bases() == ["0001_core_foundation"]
    assert INITIAL_REVISION not in {rev.revision for rev in core.walk_revisions()}
    assert "0001_control_plane" not in {rev.revision for rev in r1.walk_revisions()}
    initial = r1.get_revision(INITIAL_REVISION)
    assert initial.down_revision is None
    assert initial.module.revision == INITIAL_REVISION


def test_origin_guard_rejects_absence_before_migration_sql(monkeypatch) -> None:
    initial = _script("control_plane_alembic.ini", "control_plane_alembic").get_revision(
        INITIAL_REVISION).module

    class NoSqlOp:
        @staticmethod
        def get_context():
            return SimpleNamespace(config=SimpleNamespace(attributes={}))

        @staticmethod
        def get_bind():
            raise AssertionError("missing origin must fail before SQL")

        @staticmethod
        def execute(_sql):
            raise AssertionError("missing origin must fail before DDL")

    monkeypatch.setattr(initial, "op", NoSqlOp)
    with pytest.raises(RuntimeError, match="preflight-verified signed origin"):
        initial.upgrade()


def test_downgrade_fails_closed() -> None:
    initial = _script("control_plane_alembic.ini", "control_plane_alembic").get_revision(
        INITIAL_REVISION).module
    with pytest.raises(RuntimeError, match="forward-only"):
        initial.downgrade()
