from __future__ import annotations

from collections.abc import Generator
from functools import lru_cache

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import Settings
from .errors import CoreError


class Base(DeclarativeBase):
    pass


@lru_cache
def get_engine(database_url: str) -> Engine:
    return create_engine(
        database_url,
        pool_pre_ping=True,
        hide_parameters=True,
        future=True,
    )


def current_database(engine: Engine) -> str:
    if engine.dialect.name == "sqlite":
        return engine.url.database or ":memory:"
    with engine.connect() as connection:
        return str(connection.execute(text("SELECT current_database()")).scalar_one())


def assert_database_safe(
    settings: Settings,
    engine: Engine,
    *,
    operation: str,
    require_write_safe_name: bool = True,
) -> str:
    configured = settings.database_name
    actual = current_database(engine)
    if not configured or configured.lower() != actual.lower():
        raise CoreError("DATABASE_SAFETY_VIOLATION")
    if actual.lower() in {
        "qingyu",
        "qingyu_test",
        "postgres",
        "template0",
        "template1",
    }:
        raise CoreError("DATABASE_SAFETY_VIOLATION")
    if require_write_safe_name and not settings.writes_allowed_database:
        raise CoreError("DATABASE_SAFETY_VIOLATION")
    if operation in {"migration", "destructive-test", "acceptance"} and not settings.writes_allowed_database:
        raise CoreError("DATABASE_SAFETY_VIOLATION")
    return actual


def session_factory(settings: Settings) -> sessionmaker[Session]:
    if not settings.core_database_url:
        raise CoreError("CORE_DATABASE_URL_REQUIRED")
    engine = get_engine(settings.core_database_url)
    assert_database_safe(
        settings,
        engine,
        operation="runtime",
        require_write_safe_name=True,
    )
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db(settings: Settings) -> Generator[Session, None, None]:
    factory = session_factory(settings)
    db = factory()
    try:
        yield db
    finally:
        db.close()
