from alembic.config import Config

from .config import get_settings


def configured_database_url() -> str:
    """The single runtime and migration database URL source."""
    return get_settings().database_url


def apply_alembic_database_url(config: Config) -> str:
    url = configured_database_url()
    config.set_main_option("sqlalchemy.url", url.replace("%", "%%"))
    return url
