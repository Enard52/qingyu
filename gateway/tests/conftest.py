import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

ALLOWED_TEST_DATABASES = {"qingyu_test"}
FORBIDDEN_DATABASE_QUERY_KEYS = {"dbname", "database", "service", "servicefile"}


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


@pytest.fixture(scope="session", autouse=True)
def verified_test_database():
    engine = create_engine(validated_url)
    try:
        assert verify_connected_database(engine) == "qingyu_test"
        yield engine
    finally:
        engine.dispose()
