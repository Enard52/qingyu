from __future__ import annotations

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.config import get_settings
from app.db import assert_database_safe
from app.models import Base


config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

settings = get_settings()
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    if not settings.core_database_url:
        raise RuntimeError("CORE_DATABASE_URL_REQUIRED")
    context.configure(
        url=settings.core_database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    if not settings.core_database_url:
        raise RuntimeError("CORE_DATABASE_URL_REQUIRED")
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = settings.core_database_url.replace("%", "%%")
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        hide_parameters=True,
    )
    with connectable.connect() as connection:
        assert_database_safe(
            settings,
            connectable,
            operation="migration",
            require_write_safe_name=True,
        )
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

