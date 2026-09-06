import pytest

from conftest import validate_test_database_url, verify_connected_database


class _Connection:
    def __init__(self, database): self.database = database
    def __enter__(self): return self
    def __exit__(self, *args): return None
    def scalar(self, statement): return self.database


class _Engine:
    def __init__(self, database): self.database = database
    def connect(self): return _Connection(self.database)


def test_rejects_persistent_database_url():
    with pytest.raises(RuntimeError):
        validate_test_database_url("postgresql+psycopg://u:PASSWORD@localhost/qingyu")


def test_allows_exact_test_database_and_runtime_target():
    url = validate_test_database_url("postgresql+psycopg://u:PASSWORD@localhost/qingyu_test")
    assert url.database == "qingyu_test"
    assert verify_connected_database(_Engine("qingyu_test")) == "qingyu_test"


def test_rejects_query_database_override():
    with pytest.raises(RuntimeError, match="forbidden database override"):
        validate_test_database_url("postgresql+psycopg://u:PASSWORD@localhost/qingyu_test?dbname=qingyu")


def test_rejects_runtime_database_mismatch():
    with pytest.raises(RuntimeError, match="connected database 'qingyu'"):
        verify_connected_database(_Engine("qingyu"))


def test_rejects_similarly_named_database():
    with pytest.raises(RuntimeError):
        validate_test_database_url("postgresql+psycopg://u:PASSWORD@localhost/my_test_backup")
