from alembic.config import Config

from .config import get_settings


class DatabaseConfigurationError(RuntimeError):
    """A safe, non-secret-bearing database configuration failure."""


def configured_database_url() -> str:
    """The single runtime and migration database URL source."""
    url = get_settings().database_url
    if url is None or not url.strip():
        raise DatabaseConfigurationError("database_url_required")
    return url


def apply_alembic_database_url(config: Config) -> str:
    url = configured_database_url()
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return url
