import os
from urllib.parse import urlparse

test_url = os.getenv("TEST_DATABASE_URL", "postgresql+psycopg://qingyu:PASSWORD@127.0.0.1:5432/qingyu_test")
name = urlparse(test_url.replace("+psycopg", "")).path.lstrip("/")
if not name or "test" not in name.lower():
    raise RuntimeError(f"Refusing tests: TEST_DATABASE_URL must target a test database, got {name!r}")
os.environ["TEST_DATABASE_URL"] = test_url
os.environ["DATABASE_URL"] = test_url
