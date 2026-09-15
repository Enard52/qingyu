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
    control_plane_api_base_url: str | None = Field(default=None, validation_alias="CORE_CONTROL_PLANE_API_BASE_URL")
    control_plane_ca_file: str | None = Field(default=None, validation_alias="CORE_CONTROL_PLANE_CA_FILE")
    control_plane_credential_reference: str | None = Field(default=None, validation_alias="CORE_CONTROL_PLANE_CREDENTIAL_REFERENCE")
    control_plane_domain_id: str | None = Field(default=None, validation_alias="CORE_CONTROL_PLANE_DOMAIN_ID")
    control_plane_instance_id: str | None = Field(default=None, validation_alias="CORE_CONTROL_PLANE_INSTANCE_ID")
    control_plane_generation: int | None = Field(default=None, validation_alias="CORE_CONTROL_PLANE_GENERATION")
    control_plane_spki_sha256: str | None = Field(default=None, validation_alias="CORE_CONTROL_PLANE_SPKI_SHA256")
    control_plane_receipt_key_id: str | None = Field(default=None, validation_alias="CORE_CONTROL_PLANE_RECEIPT_KEY_ID")
    control_plane_root_key_id: str | None = Field(default=None, validation_alias="CORE_CONTROL_PLANE_ROOT_KEY_ID")
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
        if self.control_plane_backend not in {"unavailable", "memory", "r1_https"}:
            raise ValueError("unsupported control-plane backend")
        if self.app_env not in {"test", "development"} and self.control_plane_backend == "memory":
            raise ValueError("memory control-plane backend is test/development only")
        if self.app_env == "production" and self.control_plane_backend == "unavailable":
            raise ValueError("production requires an external control-plane backend")
        if self.control_plane_store:
            raise ValueError("Core must not hold a Control Plane database URL")
        if self.control_plane_backend == "r1_https":
            fields = ("control_plane_api_base_url", "control_plane_ca_file", "control_plane_credential_reference",
                "control_plane_domain_id", "control_plane_instance_id", "control_plane_generation",
                "control_plane_spki_sha256", "control_plane_receipt_key_id", "control_plane_root_key_id")
            if any(getattr(self, field) in (None, "") for field in fields):
                raise ValueError("complete R1 HTTPS trust configuration required; configuration is not admission")
            if not self.control_plane_api_base_url.startswith("https://") or self.control_plane_generation != 1:
                raise ValueError("R1 requires pinned HTTPS generation 1; later lifecycle is unsupported")
            if not self.control_plane_credential_reference.startswith("secret://"):
                raise ValueError("R1 outbound credential must be an explicit secret reference")
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
