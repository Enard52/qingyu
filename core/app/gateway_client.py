from __future__ import annotations

from typing import Any
import uuid

import httpx

from .errors import CoreError


class GatewayEvidenceClient:
    """GET-only client for the frozen Gateway Evidence Query API."""

    contract_version = "evidence-query-v1"

    def __init__(
        self,
        *,
        base_url: str,
        read_token: str,
        timeout: float = 10.0,
        transport: httpx.BaseTransport | None = None,
    ):
        if not base_url or not read_token:
            raise ValueError("Gateway Evidence API endpoint and read capability are required")
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {read_token}"},
            timeout=timeout,
            transport=transport,
        )

    def close(self) -> None:
        self._client.close()

    def _get(self, path: str, **params: Any) -> dict[str, Any]:
        response = self._client.get(path, params=params)
        if response.status_code >= 400:
            code = None
            try:
                code = response.json().get("detail", {}).get("code")
            except ValueError:
                pass
            raise CoreError(code or "GATEWAY_EVIDENCE_QUERY_FAILED")
        body = response.json()
        if body.get("contract_version") != self.contract_version:
            raise CoreError("GATEWAY_EVIDENCE_CONTRACT_MISMATCH")
        return body

    def list_conversation_observations(
        self,
        *,
        source_account_id: uuid.UUID | None = None,
        conversation_id: uuid.UUID | None = None,
        limit: int = 50,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if source_account_id:
            params["source_account_id"] = str(source_account_id)
        if conversation_id:
            params["conversation_id"] = str(conversation_id)
        if cursor:
            params["cursor"] = cursor
        return self._get("/api/v1/evidence/conversation-observations", **params)

    def list_nodes(
        self, observation_id: uuid.UUID, *, limit: int = 100, cursor: str | None = None
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._get(
            f"/api/v1/evidence/conversation-observations/{observation_id}/nodes",
            **params,
        )

    def list_attachment_observations(
        self,
        observation_id: uuid.UUID,
        attachment_id: uuid.UUID,
        *,
        limit: int = 100,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit}
        if cursor:
            params["cursor"] = cursor
        return self._get(
            f"/api/v1/evidence/conversation-observations/{observation_id}"
            f"/attachments/{attachment_id}/observations",
            **params,
        )

