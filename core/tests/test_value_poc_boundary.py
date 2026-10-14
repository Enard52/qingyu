from __future__ import annotations

import ast
from pathlib import Path

import pytest

from app.canonical import sha256_hex
from app.errors import CoreError
from app.value_poc import (
    GatewayEvidence,
    ReadOnlyMemoryAdapter,
    project_context,
    project_hermes,
    reject_direct_core_database_uri,
)


def test_value_poc_derives_rebuildable_memory_with_provenance(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    evidence = GatewayEvidence(
        evidence_id="gateway-1",
        evidence_hash=sha256_hex({"gateway": 1}),
        core_read_model_hash=read_model.read_model_hash,
        facts=[{"assertion_kind": "DERIVED", "domain": "preference", "value": "quiet"}],
    )

    records = ReadOnlyMemoryAdapter().derive(read_model, evidence)
    context = project_context(records)
    hermes = project_hermes(context, read_model)

    assert records[0].rebuildable is True
    assert records[0].assertion_kind == "DERIVED"
    assert {p.source_type for p in records[0].provenance} == {"core_read_model", "gateway_evidence"}
    assert hermes.identity_authority == "core_read_model"
    assert hermes.content["continuity_id"] == str(genesis_request.continuity_id)


def test_value_poc_rejects_unproven_user_stated_and_mismatched_core_hash(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    read_model = service.core_read_model()
    adapter = ReadOnlyMemoryAdapter()

    with pytest.raises(CoreError, match="VALUE_POC_PROVENANCE_MISMATCH"):
        adapter.derive(read_model, GatewayEvidence(
            evidence_id="bad-core",
            evidence_hash=sha256_hex({"gateway": 2}),
            core_read_model_hash="0" * 64,
        ))

    with pytest.raises(CoreError, match="VALUE_POC_USER_STATED"):
        adapter.derive(read_model, GatewayEvidence(
            evidence_id="bad-user-stated",
            evidence_hash=sha256_hex({"gateway": 3}),
            core_read_model_hash=read_model.read_model_hash,
            facts=[{"assertion_kind": "USER_STATED", "value": "claimed"}],
        ))


def test_value_poc_has_no_direct_database_boundary():
    with pytest.raises(CoreError, match="VALUE_POC_DIRECT_CORE_DB_FORBIDDEN"):
        reject_direct_core_database_uri("postgresql://core-db")

    tree = ast.parse(Path("app/value_poc.py").read_text(encoding="utf-8"))
    forbidden = {"sqlalchemy", "psycopg", "app.db", "app.models"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name not in forbidden for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.module not in forbidden
