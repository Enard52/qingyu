from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

import pytest

from tests.r1_private_config import (
    ENV_NAME,
    Slice03PrivateConfigError,
    resolve_slice03_private_config,
    sanitized_config_summary,
)


ROOT = Path(__file__).resolve().parents[1]


def _folder():
    path = ROOT / ".tmp" / ("r1-s03-resolver-" + uuid.uuid4().hex[:12])
    path.mkdir(parents=True)
    return path


def _config(folder: Path):
    owner = folder.name
    return {
        "owner": owner,
        "folder": str(folder),
        "host": "127.0.0.1",
        "port": 49995,
        "dbname": "r1_slice03",
        "admin_password": "a" * 32,
        "app_password": "b" * 32,
        "migrator_password": "c" * 32,
        "container": owner + "-pg",
    }


def _write(folder: Path, data: dict):
    path = folder / "private-config.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_slice03_private_config_resolver_accepts_owner_controlled_path_without_leaking_secret():
    folder = _folder()
    try:
        config = _config(folder)
        path = _write(folder, config)
        resolved = resolve_slice03_private_config({ENV_NAME: str(path)})
        summary = sanitized_config_summary(resolved)

        assert resolved.path == path.resolve()
        assert summary["secret_values_omitted"] is True
        assert config["admin_password"] not in json.dumps(summary)
        assert config["app_password"] not in json.dumps(summary)
        assert config["migrator_password"] not in json.dumps(summary)
    finally:
        shutil.rmtree(folder)


@pytest.mark.parametrize(
    "env, expected",
    [
        ({}, "OWNER_PRIVATE_CONFIG_REQUIRED"),
        ({ENV_NAME: str(ROOT / ".tmp" / "missing" / "private-config.json")}, "OWNER_PRIVATE_CONFIG_PATH_INVALID"),
    ],
)
def test_slice03_private_config_resolver_missing_and_wrong_path(env, expected):
    with pytest.raises(Slice03PrivateConfigError, match=expected):
        resolve_slice03_private_config(env)


def test_slice03_private_config_resolver_rejects_malformed_and_unsafe_values():
    folder = _folder()
    try:
        bad_json = folder / "private-config.json"
        bad_json.write_text("{not-json", encoding="utf-8")
        with pytest.raises(Slice03PrivateConfigError, match="OWNER_PRIVATE_CONFIG_MALFORMED"):
            resolve_slice03_private_config({ENV_NAME: str(bad_json)})

        config = _config(folder)
        config["host"] = "prod-db.example"
        _write(folder, config)
        with pytest.raises(Slice03PrivateConfigError, match="OWNER_PRIVATE_CONFIG_HOST_INVALID"):
            resolve_slice03_private_config({ENV_NAME: str(folder / "private-config.json")})

        config = _config(folder)
        config["admin_password"] = "short"
        _write(folder, config)
        with pytest.raises(Slice03PrivateConfigError, match="OWNER_PRIVATE_CONFIG_SECRET_INVALID"):
            resolve_slice03_private_config({ENV_NAME: str(folder / "private-config.json")})
    finally:
        shutil.rmtree(folder)


def test_slice03_private_config_resolver_rejects_out_of_scope_filename(tmp_path):
    folder = tmp_path / "r1-s03-outside"
    folder.mkdir()
    path = folder / "private-config.json"
    data = _config(folder)
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(Slice03PrivateConfigError, match="OWNER_PRIVATE_CONFIG_FOLDER_SCOPE_INVALID"):
        resolve_slice03_private_config({ENV_NAME: str(path)})
