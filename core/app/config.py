from __future__ import annotations

from functools import lru_cache
import os
import secrets

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


FORBIDDEN_DATABASE_NAMES = frozenset(
    {"qingyu", "qingyu_test", "postgres", "template0", "template1"}
)
CORE_WRITE_DATABASE_NAMES = frozenset({"qingyu_core_test", "qingyu_core_acceptance"})
CONTROL_PLANE_WRITE_DATABASE_NAMES = frozenset(
    {"qingyu_control_test", "qingyu_control_acceptance", "qingyu_control_prod"}
)


class Settings(BaseSettings):
    app_name: str = "Qingyu Core"
    app_env: str = "development"
    host: str = "127.0.0.1"
    port: int = 8010
    core_database_url: str | None = Field(
        default=None, validation_alias="CORE_DATABASE_URL"
    )
    gateway_evidence_api_base_url: str | None = Field(
        default=None, validation_alias="GATEWAY_EVIDENCE_API_BASE_URL"
    )
    gateway_evidence_read_token: str | None = Field(
        default=None, validation_alias="GATEWAY_EVIDENCE_READ_TOKEN"
    )
    control_plane_backend: str = Field(
        default="unavailable", validation_alias="CORE_CONTROL_PLANE_BACKEND"
    )
    control_plane_store: str | None = Field(
        default=None, validation_alias="CORE_CONTROL_PLANE_STORE"
    )
    control_plane_token: str | None = Field(
        default=None, validation_alias="CORE_CONTROL_PLANE_TOKEN"
    )
    log_level: str = "INFO"
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    @field_validator("app_env", mode="before")
    @classmethod
    def normalize_env(cls, value: str) -> str:
        return str(value).strip().lower()

    @model_validator(mode="after")
    def validate_boundary(self) -> "Settings":
        # A generic Gateway-style DATABASE_URL must never be consumed by Core.
        if self.core_database_url is None and os.environ.get("DATABASE_URL"):
            raise ValueError("CORE_DATABASE_URL is required; DATABASE_URL is not accepted")
        if self.core_database_url:
            try:
                parsed = make_url(self.core_database_url)
            except ArgumentError as exc:
                raise ValueError("CORE_DATABASE_URL is invalid") from exc
            if not parsed.database:
                raise ValueError("CORE_DATABASE_URL database name is required")
            if parsed.database.lower() in FORBIDDEN_DATABASE_NAMES:
                raise ValueError("CORE_DATABASE_URL targets a forbidden database")
        if self.control_plane_backend not in {"unavailable", "memory", "postgres"}:
            raise ValueError("unsupported control-plane backend")
        if self.app_env not in {"test", "development"} and self.control_plane_backend == "memory":
            raise ValueError("memory control-plane backend is test/development only")
        if self.app_env == "production" and self.control_plane_backend == "unavailable":
            raise ValueError("production requires an external control-plane backend")
        if self.control_plane_backend == "postgres":
            if not self.control_plane_store:
                raise ValueError("CORE_CONTROL_PLANE_STORE is required for postgres backend")
            try:
                cp_url = make_url(self.control_plane_store)
            except ArgumentError as exc:
                raise ValueError("CORE_CONTROL_PLANE_STORE is invalid") from exc
            if not cp_url.database or cp_url.database.lower() in FORBIDDEN_DATABASE_NAMES:
                raise ValueError("CORE_CONTROL_PLANE_STORE targets a forbidden database")
            if cp_url.database.lower() not in CONTROL_PLANE_WRITE_DATABASE_NAMES:
                raise ValueError(
                    "CORE_CONTROL_PLANE_STORE targets an unauthorized database"
                )
            if cp_url.username and cp_url.username.lower() in {"postgres", "qingyu"}:
                raise ValueError(
                    "CORE_CONTROL_PLANE_STORE requires a dedicated application credential"
                )
            if self.core_database_url and cp_url.render_as_string(hide_password=True) == make_url(self.core_database_url).render_as_string(hide_password=True):
                raise ValueError("control-plane store must be independent from Core database")
        return self

    @property
    def database_name(self) -> str | None:
        if not self.core_database_url:
            return None
        return make_url(self.core_database_url).database

    @property
    def writes_allowed_database(self) -> bool:
        return bool(
            self.database_name
            and self.database_name.lower() in CORE_WRITE_DATABASE_NAMES
        )

    def safe_log_identity(self) -> dict[str, str | None]:
        return {
            "database": self.database_name,
            "gateway_api": self.gateway_evidence_api_base_url,
            "control_plane_backend": self.control_plane_backend,
        }


@lru_cache
def get_settings() -> Settings:
    return Settings()


def require_capability_token(settings: Settings, supplied: str | None) -> None:
    expected = settings.control_plane_token
    if not expected or not supplied or not secrets.compare_digest(supplied, expected):
        raise PermissionError("governance_capability_required")
