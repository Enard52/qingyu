from __future__ import annotations

from typing import Any
import uuid

import httpx
from pydantic import ValidationError

from .errors import CoreError
from .value_poc import GatewayEvidence


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
        try:
            response = self._client.get(path, params=params)
        except httpx.HTTPError as exc:
            raise CoreError("GATEWAY_EVIDENCE_QUERY_UNAVAILABLE") from exc
        if response.status_code >= 400:
            code = None
            try:
                detail = response.json().get("detail")
                if isinstance(detail, dict):
                    code = detail.get("code")
                elif isinstance(response.json(), dict):
                    code = response.json().get("code")
            except ValueError:
                pass
            raise CoreError(code or "GATEWAY_EVIDENCE_QUERY_FAILED")
        try:
            body = response.json()
        except ValueError as exc:
            raise CoreError("GATEWAY_EVIDENCE_RESPONSE_MALFORMED") from exc
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


    def read_value_evidence_set(self, *, limit: int = 50) -> list[GatewayEvidence]:
        """Read normalized Value PoC evidence items through the existing evidence query surface."""
        body = self.list_conversation_observations(limit=limit)
        items = body.get("items")
        if not isinstance(items, list) or not items:
            raise CoreError("GATEWAY_EVIDENCE_NOT_FOUND")
        evidence: list[GatewayEvidence] = []
        for item in items:
            if not isinstance(item, dict):
                raise CoreError("GATEWAY_EVIDENCE_RESPONSE_MALFORMED")
            try:
                evidence.append(GatewayEvidence.model_validate(item))
            except ValidationError as exc:
                raise CoreError("GATEWAY_EVIDENCE_RESPONSE_MALFORMED") from exc
        return evidence
    def read_value_evidence(self, *, limit: int = 1) -> GatewayEvidence:
        """Read one Value PoC evidence item through the existing evidence query surface."""
        body = self.list_conversation_observations(limit=limit)
        items = body.get("items")
        if not isinstance(items, list) or not items:
            raise CoreError("GATEWAY_EVIDENCE_NOT_FOUND")
        item = items[0]
        if not isinstance(item, dict):
            raise CoreError("GATEWAY_EVIDENCE_RESPONSE_MALFORMED")
        try:
            return GatewayEvidence.model_validate(item)
        except ValidationError as exc:
            raise CoreError("GATEWAY_EVIDENCE_RESPONSE_MALFORMED") from exc

