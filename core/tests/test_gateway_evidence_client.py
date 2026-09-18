from __future__ import annotations

import httpx
import pytest

from app.canonical import sha256_hex
from app.errors import CoreError
from app.gateway_client import GatewayEvidenceClient


def _evidence(read_model):
    return {
        "evidence_id": "gateway-evidence-1",
        "evidence_hash": sha256_hex({"evidence": 1}),
        "core_read_model_hash": read_model.read_model_hash,
        "core_state_version": read_model.generation["state_version"],
        "continuity_id": read_model.identity_reference["continuity_id"],
        "source_epistemic_status": "USER_STATED",
        "source_reference": {"observation_id": "obs-1"},
        "facts": [{"assertion_kind": "DERIVED", "domain": "preference", "value": "quiet"}],
    }


def test_gateway_evidence_client_reads_existing_query_surface(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    payload = {"contract_version": "evidence-query-v1", "items": [_evidence(service.core_read_model())]}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/evidence/conversation-observations"
        assert request.headers["authorization"] == "Bearer read-token"
        assert request.url.params["limit"] == "1"
        return httpx.Response(200, json=payload)

    client = GatewayEvidenceClient(base_url="https://gateway.test", read_token="read-token", transport=httpx.MockTransport(handler))

    assert client.read_value_evidence().evidence_id == "gateway-evidence-1"


def test_gateway_evidence_client_negatives_fail_closed(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    good = {"contract_version": "evidence-query-v1", "items": [_evidence(service.core_read_model())]}
    cases = [
        (httpx.Response(403, json={"detail": {"code": "GATEWAY_FORBIDDEN"}}), "GATEWAY_FORBIDDEN"),
        (httpx.Response(200, json={"contract_version": "future", "items": []}), "GATEWAY_EVIDENCE_CONTRACT_MISMATCH"),
        (httpx.Response(200, json={"contract_version": "evidence-query-v1", "items": []}), "GATEWAY_EVIDENCE_NOT_FOUND"),
        (httpx.Response(200, json={"contract_version": "evidence-query-v1", "items": [{"evidence_id": "bad"}]}), "GATEWAY_EVIDENCE_RESPONSE_MALFORMED"),
        (httpx.Response(200, json={**good, "items": ["bad"]}), "GATEWAY_EVIDENCE_RESPONSE_MALFORMED"),
    ]
    for response, code in cases:
        client = GatewayEvidenceClient(
            base_url="https://gateway.test",
            read_token="read-token",
            transport=httpx.MockTransport(lambda _request, response=response: response),
        )
        with pytest.raises(CoreError, match=code):
            client.read_value_evidence()


def test_gateway_evidence_client_requires_explicit_inputs():
    with pytest.raises(ValueError):
        GatewayEvidenceClient(base_url="", read_token="token")
    with pytest.raises(ValueError):
        GatewayEvidenceClient(base_url="https://gateway.test", read_token="")
