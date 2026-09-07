from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator

class Settings(BaseSettings):
    app_name: str = "Qingyu Memory Gateway"
    app_env: str = "development"
    host: str = "127.0.0.1"
    port: int = 8000
    api_token: str = ""
    database_url: str | None = None
    log_level: str = "INFO"
    archive_root: str = "<repo>/data"
    staging_failed_retention_days: int = 7
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @model_validator(mode="after")
    def secure_api_token(self):
        normalized = self.api_token.strip().lower()
        forbidden = {"", "changeme", "example", "change-this-local-token", "change-me"}
        if self.app_env.lower() != "test" and normalized in forbidden:
            raise ValueError("API_TOKEN must be a non-example secret")
        return self

@lru_cache
def get_settings() -> Settings:
    return Settings()
