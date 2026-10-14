from __future__ import annotations

import os

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine

from app.config import Settings
from app.db import assert_database_safe
from app.errors import CoreError


def test_settings_rejects_gateway_database_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://x:PASSWORD@localhost/qingyu")
    with pytest.raises(ValidationError, match="CORE_DATABASE_URL"):
        Settings()


def test_settings_rejects_forbidden_core_database():
    with pytest.raises(ValidationError, match="forbidden"):
        Settings(CORE_DATABASE_URL="postgresql+psycopg://x:PASSWORD@localhost/qingyu")


def test_settings_rejects_unimplemented_control_plane_backend():
    with pytest.raises(ValidationError, match="unsupported control-plane backend"):
        Settings(CORE_CONTROL_PLANE_BACKEND="sqlite-quorum")


def test_core_rejects_legacy_direct_authority_database():
    with pytest.raises(ValidationError, match="unsupported control-plane backend"):
        Settings(CORE_CONTROL_PLANE_BACKEND="postgres",
                 CORE_CONTROL_PLANE_STORE="postgresql+psycopg://x:PASSWORD@localhost/qingyu_control_r1_acceptance")
    with pytest.raises(ValidationError, match="must not hold a Control Plane database URL"):
        Settings(CORE_CONTROL_PLANE_STORE="postgresql+psycopg://x:PASSWORD@localhost/qingyu_control_r1_acceptance")


def test_database_safety_requires_explicit_core_name():
    settings = Settings(CORE_DATABASE_URL="sqlite+pysqlite:///:memory:")
    engine = create_engine("sqlite+pysqlite:///:memory:")
    with pytest.raises(CoreError, match="DATABASE_SAFETY_VIOLATION"):
        assert_database_safe(settings, engine, operation="migration")
