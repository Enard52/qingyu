from __future__ import annotations

from sqlalchemy import select
import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.errors import CoreError
from app.main import create_app, get_service
from app.models import CoreMetadata
from app.schemas import MutationRequest
from app.services import CoreFoundationService


def mutation(genesis_request, lease, name="read-model-mutation"):
    return MutationRequest(
        continuity_id=genesis_request.continuity_id,
        continuity_epoch=0,
        lease_id=lease,
        mutation_id=name,
        actor_principal_id="owner-1",
        capability="core_writer",
        payload={"kind": "read-model-test", "name": name},
    )


def test_read_model_is_deterministic_versioned_and_read_only(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)

    first = service.core_read_model()
    second = service.core_read_model()

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert first.schema_version == "core-read-model-v1"
    assert first.read_only is True
    assert first.generation["state_version"] == 0
    assert first.identity_reference["continuity_id"] == str(genesis_request.continuity_id)
    assert first.provenance["checkpoint_hash"]


def test_read_model_survives_service_restart(foundation, genesis_request):
    service, factory, authority = foundation
    service.bootstrap_genesis(genesis_request)
    before = service.core_read_model()

    restarted = CoreFoundationService(factory, authority)

    assert restarted.core_read_model().model_dump(mode="json") == before.model_dump(mode="json")


def test_read_model_version_advances_after_governed_state_change(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    lease = service.acquire_owner_lease(genesis_request.continuity_id)
    before = service.core_read_model()

    service.governed_mutation(mutation(genesis_request, lease))
    after = service.core_read_model()

    assert after.generation["state_version"] == before.generation["state_version"] + 1
    assert after.governed_state["audit_high_water"] == before.governed_state["audit_high_water"] + 1
    assert after.read_model_hash != before.read_model_hash


def test_read_model_fails_closed_on_partial_state(foundation, genesis_request):
    service, factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    with factory.begin() as session:
        metadata = session.scalar(select(CoreMetadata).where(CoreMetadata.id == 1))
        metadata.current_state_version = 999

    with pytest.raises(CoreError, match="RESTORE_STATE_GAP"):
        service.core_read_model()


def test_read_model_http_projection_uses_governance_capability(foundation, genesis_request):
    service, _factory, _authority = foundation
    service.bootstrap_genesis(genesis_request)
    application = create_app(settings=Settings(app_env="test", CORE_CONTROL_PLANE_TOKEN="read-token"))
    application.dependency_overrides[get_service] = lambda: service

    with TestClient(application) as web:
        denied = web.get("/api/v1/core/read-model")
        allowed = web.get("/api/v1/core/read-model", headers={"X-Core-Governance-Capability": "read-token"})

    assert denied.status_code == 403
    assert allowed.status_code == 200
    assert allowed.json()["read_model_hash"] == service.core_read_model().read_model_hash
