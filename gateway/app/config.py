from functools import lru_cache
import secrets
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, model_validator

class Settings(BaseSettings):
    app_name: str = "Qingyu Memory Gateway"
    app_env: str = "development"
    host: str = "127.0.0.1"
    port: int = 8000
    api_token: str = ""
    evidence_read_api_token: str = ""
    evidence_cursor_signing_key: str = ""
    database_url: str | None = None
    log_level: str = "INFO"
    archive_root: str = "<repo>/data"
    staging_failed_retention_days: int = Field(default=7, ge=0)
    staging_cleanup_interval_seconds: float = Field(default=300.0, gt=0)
    staging_cleanup_max_candidates: int = Field(default=100, gt=0)
    import_upload_max_bytes: int = Field(default=512 * 1024 * 1024, gt=0)
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    @model_validator(mode="after")
    def secure_api_token(self):
        normalized = self.api_token.strip().lower()
        normalized_evidence = self.evidence_read_api_token.strip().lower()
        normalized_cursor_key = self.evidence_cursor_signing_key.strip().lower()
        forbidden = {"", "changeme", "example", "change-this-local-token", "change-me"}
        if self.app_env.lower() != "test":
            if normalized in forbidden:
                raise ValueError("API_TOKEN must be a non-example secret")
            if normalized_evidence in forbidden:
                raise ValueError("EVIDENCE_READ_API_TOKEN must be a non-example secret")
            if normalized_cursor_key in forbidden:
                raise ValueError("EVIDENCE_CURSOR_SIGNING_KEY must be a non-example secret")
            if secrets.compare_digest(self.api_token, self.evidence_read_api_token):
                raise ValueError("EVIDENCE_READ_API_TOKEN must differ from API_TOKEN")
            if secrets.compare_digest(self.evidence_cursor_signing_key, self.api_token):
                raise ValueError("EVIDENCE_CURSOR_SIGNING_KEY must differ from API_TOKEN")
            if secrets.compare_digest(
                self.evidence_cursor_signing_key, self.evidence_read_api_token
            ):
                raise ValueError(
                    "EVIDENCE_CURSOR_SIGNING_KEY must differ from EVIDENCE_READ_API_TOKEN"
                )
        return self

@lru_cache
def get_settings() -> Settings:
    return Settings()
