from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "Qingyu Memory Gateway"
    app_env: str = "development"
    host: str = "127.0.0.1"
    port: int = 8000
    api_token: str = "change-this-local-token"
    database_url: str = "postgresql+psycopg://qingyu:PASSWORD@localhost:5432/qingyu"
    log_level: str = "INFO"
    archive_root: str = "<repo>/data"
    staging_failed_retention_days: int = 7
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

@lru_cache
def get_settings() -> Settings:
    return Settings()
