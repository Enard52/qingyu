from __future__ import annotations

from typing import Any

import httpx
from pydantic import ValidationError

from .canonical import sha256_hex
from .errors import CoreError
from .schemas import CoreReadModel


class CoreReadModelClient:
    """GET-only client for the public Core Read Model API."""

    schema_version = "core-read-model-v1"

    def __init__(
        self,
        *,
        base_url: str,
        governance_capability: str,
        timeout: float = 5.0,
        transport: httpx.BaseTransport | None = None,
    ):
        if not base_url or not governance_capability:
            raise ValueError("Core read model endpoint and governance capability are required")
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"X-Core-Governance-Capability": governance_capability},
            timeout=timeout,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def read(self) -> CoreReadModel:
        try:
            response = self._client.get("/api/v1/core/read-model")
        except httpx.HTTPError as exc:
            raise CoreError("CORE_READ_MODEL_UNAVAILABLE") from exc
        if response.status_code >= 400:
            code: str | None = None
            try:
                detail = response.json().get("detail")
                if isinstance(detail, dict):
                    code = detail.get("code")
            except ValueError:
                pass
            raise CoreError(code or "CORE_READ_MODEL_UNAVAILABLE")
        try:
            body: dict[str, Any] = response.json()
            model = CoreReadModel.model_validate(body)
        except (ValueError, ValidationError) as exc:
            raise CoreError("CORE_READ_MODEL_MALFORMED") from exc
        self._validate(model)
        return model

    def _validate(self, model: CoreReadModel) -> None:
        if model.schema_version != self.schema_version:
            raise CoreError("CORE_READ_MODEL_SCHEMA_UNSUPPORTED")
        if model.read_only is not True:
            raise CoreError("CORE_READ_MODEL_NOT_READ_ONLY")
        version = model.generation.get("state_version")
        if not isinstance(version, int) or version < 0:
            raise CoreError("CORE_READ_MODEL_STATE_VERSION_INVALID")
        if not model.identity_reference.get("continuity_id"):
            raise CoreError("CORE_READ_MODEL_IDENTITY_REFERENCE_INVALID")
        payload = model.model_dump(mode="json", exclude={"read_model_hash"})
        if sha256_hex(payload) != model.read_model_hash:
            raise CoreError("CORE_READ_MODEL_HASH_MISMATCH")

