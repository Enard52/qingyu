import os

import pytest
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError

ALLOWED_TEST_DATABASES = {"qingyu_test"}
FORBIDDEN_DATABASE_QUERY_KEYS = {"dbname", "database", "service", "servicefile"}


def get_expected_alembic_head() -> str:
    gateway_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    alembic_dir = os.path.join(gateway_dir, "alembic")
    script = ScriptDirectory(alembic_dir)
    return script.get_current_head()


def verify_database_migrations(engine, expected_head: str | None = None) -> str:
    if expected_head is None:
        expected_head = get_expected_alembic_head()
    with engine.connect() as connection:
        try:
            has_table = inspect(connection).has_table("alembic_version")
        except (AttributeError, TypeError, ValueError, SQLAlchemyError):
            has_table = True
        current_rev = (
            connection.scalar(text("SELECT version_num FROM alembic_version"))
            if has_table
            else None
        )
    if current_rev != expected_head:
        raise RuntimeError(
            f"Database schema is not at migration head (current: {current_rev!r}, expected: {expected_head!r}); "
            "run: DATABASE_URL=$TEST_DATABASE_URL APP_ENV=test alembic upgrade head"
        )
    return current_rev


def validate_test_database_url(raw_url: str):
    if not raw_url:
        raise RuntimeError("TEST_DATABASE_URL is required for database tests")
    url = make_url(raw_url)
    forbidden = FORBIDDEN_DATABASE_QUERY_KEYS.intersection(key.lower() for key in url.query)
    if forbidden:
        raise RuntimeError(f"TEST_DATABASE_URL contains forbidden database override: {sorted(forbidden)}")
    if url.database not in ALLOWED_TEST_DATABASES:
        raise RuntimeError(f"Refusing tests: configured database {url.database!r} is not allowlisted")
    return url


def verify_connected_database(engine) -> str:
    with engine.connect() as connection:
        actual = connection.scalar(text("SELECT current_database()"))
    if actual not in ALLOWED_TEST_DATABASES:
        raise RuntimeError(f"Refusing destructive tests: connected database {actual!r} is not allowlisted")
    return actual


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL")
validated_url = validate_test_database_url(TEST_DATABASE_URL)
os.environ["DATABASE_URL"] = validated_url.render_as_string(hide_password=False)
os.environ["APP_ENV"] = "test"
os.environ["API_TOKEN"] = os.getenv("TEST_API_TOKEN", "qingyu-test-token-only")
os.environ["EVIDENCE_READ_API_TOKEN"] = os.getenv(
    "TEST_EVIDENCE_READ_API_TOKEN", "qingyu-test-evidence-read-token-only"
)
os.environ["EVIDENCE_CURSOR_SIGNING_KEY"] = os.getenv(
    "TEST_EVIDENCE_CURSOR_SIGNING_KEY", "qingyu-test-server-only-cursor-signing-key"
)


@pytest.fixture(scope="session", autouse=True)
def verified_test_database():
    engine = create_engine(validated_url)
    try:
        assert verify_connected_database(engine) == "qingyu_test"
        try:
            verify_database_migrations(engine)
        except RuntimeError as exc:
            pytest.fail(str(exc), pytrace=False)
        yield engine
    finally:
        engine.dispose()
