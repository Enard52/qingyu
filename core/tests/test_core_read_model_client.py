from __future__ import annotations

import json

import httpx
import pytest

from app.canonical import sha256_hex
from app.core_read_model_client import CoreReadModelClient
from app.errors import CoreError


def _body(read_model):
    return read_model.model_dump(mode="json")


def test_core_read_model_client_reads_authenticated_validated_boundary(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    body = _body(service.core_read_model())

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-core-governance-capability"] == "token"
        return httpx.Response(200, json=body)

    client = CoreReadModelClient(base_url="https://core.test", governance_capability="token", transport=httpx.MockTransport(handler))

    assert client.read().read_model_hash == body["read_model_hash"]


def test_core_read_model_client_negatives_fail_closed(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    good = _body(service.core_read_model())

    cases = [
        (httpx.Response(503, json={"detail": {"code": "CORE_DOWN"}}), "CORE_DOWN"),
        (httpx.Response(200, json={"schema_version": "wrong"}), "CORE_READ_MODEL_MALFORMED"),
        (httpx.Response(200, json={**good, "schema_version": "future"}), "CORE_READ_MODEL_SCHEMA_UNSUPPORTED"),
        (httpx.Response(200, json={**good, "read_model_hash": "0" * 64}), "CORE_READ_MODEL_HASH_MISMATCH"),
        (httpx.Response(200, json={**good, "generation": {**good["generation"], "state_version": -1}}), "CORE_READ_MODEL_STATE_VERSION_INVALID"),
    ]
    for response, code in cases:
        client = CoreReadModelClient(
            base_url="https://core.test",
            governance_capability="token",
            transport=httpx.MockTransport(lambda _request, response=response: response),
        )
        with pytest.raises(CoreError, match=code):
            client.read()


def test_core_read_model_client_requires_explicit_inputs():
    with pytest.raises(ValueError):
        CoreReadModelClient(base_url="", governance_capability="token")
    with pytest.raises(ValueError):
        CoreReadModelClient(base_url="https://core.test", governance_capability="")
