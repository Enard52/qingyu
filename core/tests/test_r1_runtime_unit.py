"""Pure pre-effect configuration/proposal checks, not PostgreSQL evidence."""
from dataclasses import replace
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
import pytest

from app.config import Settings
from app.control_plane.r1_admission import AdmissionError
from app.control_plane.r1_coordinator import R1Coordinator
from app.control_plane.r1_commands import MutationIntent
from app.control_plane.r1_postgres_store import StoreProposal
from app.control_plane.r1_protocol import AuthorityPin, ProtocolError, canonical_bytes, key_id
from app.control_plane.r1_server import create_authority_runtime
from app.main import create_app
from app.service_factory import build_core_service
from r1_f3_helpers import mutation_envelope, uid


def r1_settings():
    return Settings(app_env="production", CORE_DATABASE_URL="postgresql+psycopg://core@127.0.0.1/qingyu_core_test",
        CORE_CONTROL_PLANE_BACKEND="r1_https", CORE_CONTROL_PLANE_API_BASE_URL="https://authority.invalid",
        CORE_CONTROL_PLANE_CA_FILE="not-resolved-before-admission", CORE_CONTROL_PLANE_CREDENTIAL_REFERENCE="secret://core/scope",
        CORE_CONTROL_PLANE_DOMAIN_ID=uid(1), CORE_CONTROL_PLANE_INSTANCE_ID=uid(2), CORE_CONTROL_PLANE_GENERATION=1,
        CORE_CONTROL_PLANE_SPKI_SHA256="a"*64, CORE_CONTROL_PLANE_RECEIPT_KEY_ID="b"*64, CORE_CONTROL_PLANE_ROOT_KEY_ID="c"*64)


def test_production_factories_refuse_missing_admission_before_core_db_or_secret(monkeypatch):
    import app.service_factory as factory
    monkeypatch.setattr(factory, "session_factory", lambda _: pytest.fail("Core DB opened without admission"))
    with pytest.raises(AdmissionError):
        build_core_service(r1_settings())
    with pytest.raises(AdmissionError):
        create_authority_runtime()
    with pytest.raises(AdmissionError):
        with TestClient(create_app(settings=r1_settings())):
            pytest.fail("production startup served without admission")


def test_core_app_factory_rebinds_configuration_and_capability_dependencies():
    from app.main import get_service
    application = create_app(settings=Settings(app_env="test",CORE_CONTROL_PLANE_TOKEN="factory-only-token"))
    application.dependency_overrides[get_service] = lambda: object()
    with TestClient(application) as web:
        denied = web.post("/internal/v1/mutations",json={})
        wrong = web.post("/internal/v1/mutations",json={},
            headers={"X-Core-Governance-Capability":"wrong-token"})
        allowed = web.post("/internal/v1/mutations",json={},
            headers={"X-Core-Governance-Capability":"factory-only-token"})
    assert denied.status_code == 403
    assert wrong.status_code == 403
    assert allowed.status_code == 422  # Passed capability; body remains invalid.


def unsigned_proposal(intent, *, terminal=False):
    e, p = intent.envelope, intent.payload
    common = {name: e[name] for name in ("authority_domain_id", "authority_instance_id", "authority_generation",
        "qingyu_identity_id", "continuity_id", "operation_id", "operation_type")}
    shared = {"request_envelope_hash": intent.request_hash, **{name: p[name] for name in (
        "staged_result_hash", "core_audit_predecessor_hash", "core_audit_candidate_hash")}}
    if not terminal:
        return {"ack_version":1, **common, **shared, **{name:e[name] for name in ("caller_runtime_id",
            "storage_generation_id", "expected_continuity_epoch", "expected_owner_version", "expected_state_version")},
            "state":"PREPARED", "prepared_at":"2026-09-14T00:00:00Z"}
    return {"receipt_version":1,"schema_version":1,**common,**shared,"result_state":"COMMITTED", "result_code":"COMMITTED",
        "actor_or_owner_identity":e["actor_or_owner_identity"],"continuity_epoch":e["expected_continuity_epoch"],
        "storage_generation_id":e["storage_generation_id"],"control_plane_generation_id":p["control_plane_generation_id"],
        "owner_version":e["expected_owner_version"],"lease_generation":p["lease_generation"],"authority_sequence":2,
        "previous_receipt_hash":"a"*64,"result_payload_hash":intent.result_hash("COMMITTED"),"decided_at":"2026-09-14T00:00:00Z",
        "signed_provisioning_origin_digest":None,"previous_generation":None,"previous_generation_sequence":None,
        "previous_generation_head_hash":None,"signed_dr_artifact_digest":None}


@pytest.mark.parametrize("terminal,field,value", [
    (False,"caller_runtime_id",uid(90)), (False,"storage_generation_id",uid(90)),
    (False,"expected_continuity_epoch",99), (False,"expected_state_version",99),
    (False,"expected_owner_version",99), (False,"prepared_at","yesterday"),
    (True,"continuity_epoch",99), (True,"owner_version",99), (True,"lease_generation",99),
    (True,"control_plane_generation_id",uid(90)), (True,"result_code","UNREVIEWED"),
    (True,"decided_at","not-utc"), (True,"result_payload_hash","f"*64),
])
def test_invalid_unsigned_proposal_never_calls_receipt_signer(terminal,field,value):
    private = Ed25519PrivateKey.generate()
    pin = AuthorityPin(uid(1),uid(2),1,private.public_key(),key_id(private.public_key()),1,"https://authority.invalid","a"*64,"b"*64)
    intent = MutationIntent.from_envelope(mutation_envelope())
    coord = object.__new__(R1Coordinator)  # Isolate pure pre-sign validator only.
    coord.admission = SimpleNamespace(public=SimpleNamespace(pin=pin))
    coord.signer = SimpleNamespace(sign=lambda _: pytest.fail("signer called for invalid proposal"))
    message = {**unsigned_proposal(intent,terminal=terminal),"receipt_key_id":pin.receipt_key_id,field:value}
    target = "COMMITTED" if terminal else "PREPARED"
    tx = SimpleNamespace(proposal=StoreProposal(intent.operation_id,target,canonical_bytes(message),False))
    with pytest.raises(ProtocolError):
        coord._finish(tx,intent,target)


def test_new_proposal_cannot_change_authenticated_decision_before_signing():
    coord = object.__new__(R1Coordinator)
    intent = MutationIntent.from_envelope(mutation_envelope())
    tx = SimpleNamespace(proposal=StoreProposal(intent.operation_id,"ABORTED",b"{}",False))
    with pytest.raises(ProtocolError,match="authenticated decision"):
        coord._finish(tx,intent,"COMMITTED")
