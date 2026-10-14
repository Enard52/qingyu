from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Any


class Slice03PrivateConfigError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(f"TEST SETUP ERROR: {code}")
        self.code = code


@dataclass(frozen=True)
class Slice03PrivateConfig:
    path: Path
    data: Mapping[str, Any]

    @property
    def owner(self) -> str:
        return str(self.data["owner"])

    @property
    def folder(self) -> Path:
        return Path(str(self.data["folder"])).resolve()

    @property
    def container(self) -> str:
        return str(self.data["container"])


REQUIRED_KEYS = frozenset({
    "owner",
    "folder",
    "host",
    "port",
    "dbname",
    "admin_password",
    "app_password",
    "migrator_password",
    "container",
})
SECRET_KEYS = frozenset({"admin_password", "app_password", "migrator_password", "runtime_credential", "operator_credential"})
ENV_NAME = "R1_SLICE03_PRIVATE_CONFIG"


def resolve_slice03_private_config(environ: Mapping[str, str] | None = None) -> Slice03PrivateConfig:
    env = os.environ if environ is None else environ
    raw = env.get(ENV_NAME)
    if not raw:
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_REQUIRED")
    path = Path(raw).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_PATH_INVALID") from exc
    if resolved.name != "private-config.json":
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_FILENAME_INVALID")
    try:
        text = resolved.read_text(encoding="utf-8")
        data = json.loads(text)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_MALFORMED") from exc
    if not isinstance(data, dict):
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_MALFORMED")
    missing = REQUIRED_KEYS.difference(data)
    if missing:
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_REQUIRED_FIELDS_MISSING")
    owner = data.get("owner")
    folder = data.get("folder")
    host = data.get("host")
    port = data.get("port")
    container = data.get("container")
    if not isinstance(owner, str) or not owner.startswith("r1-s03-"):
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_OWNER_INVALID")
    try:
        folder_path = Path(str(folder)).resolve(strict=True)
    except OSError as exc:
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_FOLDER_INVALID") from exc
    if resolved.parent != folder_path:
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_FOLDER_MISMATCH")
    if folder_path.parent != (Path(__file__).resolve().parents[1] / ".tmp").resolve():
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_FOLDER_SCOPE_INVALID")
    if host != "127.0.0.1":
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_HOST_INVALID")
    if not isinstance(port, int) or port <= 0 or port > 65535:
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_PORT_INVALID")
    if container != owner + "-pg":
        raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_CONTAINER_INVALID")
    for key in SECRET_KEYS.intersection(data):
        if not isinstance(data[key], str) or len(data[key]) < 16:
            raise Slice03PrivateConfigError("OWNER_PRIVATE_CONFIG_SECRET_INVALID")
    return Slice03PrivateConfig(path=resolved, data=data)


def sanitized_config_summary(config: Slice03PrivateConfig) -> dict[str, Any]:
    return {
        "owner": config.owner,
        "path": str(config.path),
        "host": config.data["host"],
        "port": config.data["port"],
        "dbname": config.data["dbname"],
        "container": config.container,
        "secret_values_omitted": True,
    }

