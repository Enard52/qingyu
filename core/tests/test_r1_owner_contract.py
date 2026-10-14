"""Static owner-contract checks; these are not PostgreSQL privilege tests."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "docs" / "CONTROL_PLANE_R1_OWNER_CONTRACT.md"


def _table_rows(section: str) -> list[list[str]]:
    document = CONTRACT.read_text(encoding="utf-8")
    body = document.split(f"## {section}\n", 1)[1].split("\n## ", 1)[0]
    rows = []
    for line in body.splitlines():
        if line.startswith("| ") and not line.startswith("| ---"):
            rows.append([cell.strip() for cell in line.strip("| ").split("|")])
    return rows[1:]


def test_owner_contract_freezes_five_distinct_duties():
    rows = _table_rows("Canonical roles")
    actual = {row[0].strip("`"): row[1].strip("`") for row in rows}
    assert actual == {
        "owner": "control_plane_owner",
        "migrator": "control_plane_migrator",
        "service": "control_plane_app",
        "read_only": "control_plane_reader",
        "operator": "control_plane_operator",
    }
    assert len(set(actual.values())) == 5


def test_owner_contract_covers_version_table_and_object_classes():
    rows = _table_rows("Ownership matrix")
    actual = {row[0].strip("`"): row[1].strip("`") for row in rows}
    for object_class in (
        "New R1 database", "`control_plane` schema",
        "All `control_plane.cp_*` base/partition tables",
        "All Authority sequences and identity generators",
        "All Authority functions/procedures", "All restricted Authority views",
        "`public.cp_alembic_version`",
    ):
        assert actual[object_class.strip("`")] == "control_plane_owner"


def test_owner_contract_keeps_unimplemented_migration_closed():
    document = CONTRACT.read_text(encoding="utf-8")
    env_source = (ROOT / "control_plane_alembic" / "env.py").read_text(encoding="utf-8")
    assert "Choose **B:" in document
    assert "Reject A" in document
    assert 'raise RuntimeError("R1 independent target inspector is not yet installed")' in env_source
