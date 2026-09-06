import hashlib
from pathlib import Path
import pytest
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session
from app.models import ArchiveObject
from app.db import Base
from app.archive.service import ArchiveService

DB_URL = "postgresql+psycopg://qingyu:PASSWORD@127.0.0.1:5432/qingyu"

@pytest.fixture()
def archive_env(tmp_path: Path):
    engine = create_engine(DB_URL)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.execute(delete(ArchiveObject))
        db.commit()
        yield tmp_path, db
    engine.dispose()

def test_archive_and_idempotent_duplicate(archive_env):
    root, db = archive_env
    src = root / "same.txt"
    src.write_bytes(b"hello archive")
    service = ArchiveService(root, db)
    first = service.archive_file(src, "same.txt", "test")
    second = service.archive_file(src, "same.txt", "test")
    assert first.sha256 == hashlib.sha256(src.read_bytes()).hexdigest()
    assert first.size_bytes == 13
    assert first.duplicate is False and second.duplicate is True
    assert first.object_id == second.object_id
    target = root / first.relative_path
    assert target.read_bytes() == src.read_bytes()
    assert first.manifest_path.exists()

def test_same_name_different_content_and_empty_file(archive_env):
    root, db = archive_env
    service = ArchiveService(root, db)
    a, b = root / "a", root / "b"
    a.write_bytes(b"one")
    b.write_bytes(b"")
    r1 = service.archive_file(a, "same.bin", "test")
    r2 = service.archive_file(b, "same.bin", "test")
    assert r1.sha256 != r2.sha256
    assert r2.size_bytes == 0

def test_large_file_and_content_immutable(archive_env):
    root, db = archive_env
    src = root / "large.bin"
    src.write_bytes(b"x" * (2 * 1024 * 1024))
    result = ArchiveService(root, db).archive_file(src)
    target = root / result.relative_path
    before = target.read_bytes()
    src.write_bytes(b"changed")
    assert target.read_bytes() == before

def test_invalid_names_path_traversal_and_staging_cleanup(archive_env):
    root, db = archive_env
    src = root / "ok.txt"
    src.write_text("x", encoding="utf-8")
    service = ArchiveService(root, db)
    for name in ("../escape.txt", "a/b.txt", "bad?.txt"):
        with pytest.raises(ValueError):
            service.archive_file(src, name)
    stale = service.staging / "stale.tmp"
    stale.parent.mkdir(parents=True)
    stale.write_bytes(b"stale")
    assert service.cleanup_staging() == 1
    assert not stale.exists()

def test_database_and_disk_manifest_match(archive_env):
    import json
    root, db = archive_env
    src = root / "report.json"
    src.write_text("{}", encoding="utf-8")
    result = ArchiveService(root, db).archive_file(src, source_platform="chatgpt", media_type="application/json")
    record = db.get(ArchiveObject, result.object_id)
    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    target = root / record.relative_path
    assert target.exists()
    assert record.sha256 == manifest["sha256"] == hashlib.sha256(target.read_bytes()).hexdigest()
    assert record.size_bytes == manifest["size_bytes"] == target.stat().st_size
    assert record.source_platform == "chatgpt"
