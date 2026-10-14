"""Signed origin acceptance tests use ephemeral test keys only."""

from __future__ import annotations

from copy import deepcopy
import ast
from dataclasses import fields
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from app.control_plane.r1_protocol import canonical_bytes, decode_canonical_wire, key_id, sha256_hex
from app.control_plane.r1_provisioning import (
    ACCEPTANCE_DATABASE, COMPLETION_PREFIX, INITIAL_ATTESTATION_PREFIX,
    INITIAL_REVISION, INTENT_PREFIX, KEY_CREATION_POLICY, ROLE_POLICY,
    ObservedInitialState, ObservedProvisionedTarget, ProvisioningError,
    verify_initial_migration_attestation, verify_pre_migration_target,
    verify_signed_intent, verify_signed_origin, verify_signed_origin_wire,
    verify_signed_initial_migration_intent, cluster_binding_fingerprint,
)
from app.control_plane import r1_schema_snapshot as snapshot


def signed(payload: dict, root: Ed25519PrivateKey, prefix: bytes) -> dict:
    envelope = {"version": 2 if prefix in (INTENT_PREFIX, COMPLETION_PREFIX) else 1,
                "key_id": key_id(root.public_key()), "payload": payload}
    envelope["signature"] = root.sign(prefix + canonical_bytes(envelope)).hex()
    return envelope


@pytest.fixture
def origin_parts():
    root = Ed25519PrivateKey.generate()  # Test-only; no operator root leaves this test.
    roles = {
        "owner": "control_plane_owner", "migrator": "control_plane_migrator",
        "service": "control_plane_app", "operator": "control_plane_operator",
        "read_only": "control_plane_reader",
    }
    intent = {
        "provisioning_uuid": "11111111-1111-4111-8111-111111111111",
        "authority_domain_id": "22222222-2222-4222-8222-222222222222",
        "authority_instance_id": "33333333-3333-4333-8333-333333333333",
        "authority_generation": 1, "environment": "acceptance",
        "profile": "R1_PERSONAL_PRODUCTION",
        "isolated_cluster_deployment_id": "44444444-4444-4444-8444-444444444444",
        "database_name": ACCEPTANCE_DATABASE,
        "planned_tls_origin": "https://authority-r1.test:8443",
        "canonical_initial_revision": INITIAL_REVISION,
        "initial_migration_artifact_digest": "a" * 64,
        "authored_ddl_snapshot_digest": snapshot.EXPECTED_SNAPSHOT_SHA256,
        "initial_migration_dependency_version": snapshot.INITIAL_MIGRATION_DEPENDENCY_VERSION,
        "initial_migration_dependency_digest": "d" * 64,
        "schema_contract_version": snapshot.SCHEMA_CONTRACT_VERSION,
        "schema_contract_digest": "e" * 64,
        "operator_approval": {
            "approval_id": "66666666-6666-4666-8666-666666666666",
            "decision": "APPROVE_R1_INITIAL_PROVISIONING_AND_MIGRATION",
            "approved_at": "2026-09-12T00:00:00Z",
        },
        "expected_fingerprint_version": 1,
        "expected_schema_fingerprint": "b" * 64,
        "roles": roles, "role_policy": ROLE_POLICY,
        "receipt_key_slot_reference": "dpapi-localmachine://qingyu/r1/test",
        "receipt_key_creation_policy": KEY_CREATION_POLICY,
        "operator_root_key_id": key_id(root.public_key()), "test_only": True,
    }
    completion = {
        "provisioning_uuid": intent["provisioning_uuid"],
        "authority_domain_id": intent["authority_domain_id"],
        "authority_instance_id": intent["authority_instance_id"],
        "authority_generation": 1, "environment": "acceptance",
        "isolated_cluster_deployment_id": intent["isolated_cluster_deployment_id"],
        "database_name": ACCEPTANCE_DATABASE,
        "observed_tls_origin": intent["planned_tls_origin"],
        "canonical_initial_revision": intent["canonical_initial_revision"],
        "initial_migration_artifact_digest": intent["initial_migration_artifact_digest"],
        "authored_ddl_snapshot_digest": intent["authored_ddl_snapshot_digest"],
        "initial_migration_dependency_version": intent["initial_migration_dependency_version"],
        "initial_migration_dependency_digest": intent["initial_migration_dependency_digest"],
        "schema_contract_version": intent["schema_contract_version"],
        "schema_contract_digest": intent["schema_contract_digest"],
        "operator_approval": intent["operator_approval"],
        "expected_fingerprint_version": intent["expected_fingerprint_version"],
        "expected_schema_fingerprint": intent["expected_schema_fingerprint"],
        "server_system_identifier": "9876543210123456789",
        "database_oid": 16384, "owner_oid": 16385,
        "role_oids": {"owner": 16385, "migrator": 16386,
                      "service": 16387, "operator": 16388,
                      "read_only": 16389},
        "roles": roles, "creation_event_timestamp": "2026-09-13T00:00:00Z",
        "receipt_key_slot_reference": intent["receipt_key_slot_reference"],
        "receipt_key_id": "c" * 64,
        "external_storage_identity": "55555555-5555-4555-8555-555555555555",
        "test_only": True,
    }
    completion["cluster_binding_fingerprint"] = cluster_binding_fingerprint(
        isolated_cluster_deployment_id=completion["isolated_cluster_deployment_id"],
        server_system_identifier=completion["server_system_identifier"],
        database_name=completion["database_name"], database_oid=completion["database_oid"],
        owner_oid=completion["owner_oid"], role_oids=completion["role_oids"],
        receipt_key_id=completion["receipt_key_id"],
        external_storage_identity=completion["external_storage_identity"],
        observed_tls_origin=completion["observed_tls_origin"])
    return root, intent, completion


def make_attestation(origin, root):
    payload = {
        "provisioning_uuid": origin.intent["provisioning_uuid"],
        "signed_provisioning_origin_digest": origin.signed_provisioning_origin_digest,
        "canonical_initial_revision": INITIAL_REVISION,
        "fingerprint_version": origin.intent["expected_fingerprint_version"],
        "schema_fingerprint": origin.intent["expected_schema_fingerprint"],
        "initial_migration_artifact_digest": origin.intent["initial_migration_artifact_digest"],
        "database_name": origin.intent["database_name"],
        "server_system_identifier": origin.completion["server_system_identifier"],
        "cluster_binding_fingerprint": origin.completion["cluster_binding_fingerprint"],
        "authority_domain_id": origin.intent["authority_domain_id"],
        "authority_instance_id": origin.intent["authority_instance_id"],
        "authority_generation": 1, "receipt_key_id": origin.completion["receipt_key_id"],
        "observed_at": "2026-09-13T00:10:00Z", "test_only": True,
    }
    observed = ObservedInitialState(**{
        field.name: payload[field.name] if field.name in payload else origin.completion[field.name]
        for field in fields(ObservedInitialState)
    })
    return signed(payload, root, INITIAL_ATTESTATION_PREFIX), observed


def test_full_signed_origin_and_attested_catalog(origin_parts):
    root, intent, completion = origin_parts
    signed_intent = signed(intent, root, INTENT_PREFIX)
    signed_completion = signed(completion, root, COMPLETION_PREFIX)
    origin = verify_signed_origin(signed_intent, signed_completion, root.public_key())
    observed_target = ObservedProvisionedTarget(**{
        field.name: completion[field.name] for field in fields(ObservedProvisionedTarget)
    })
    verify_pre_migration_target(origin, observed_target)
    expected_digest = sha256_hex(b"QINGYU-CP-R1-PROVISIONING-ORIGIN\x00" + canonical_bytes({
        "intent": signed_intent, "completion": signed_completion,
    }))
    assert origin.signed_provisioning_origin_digest == expected_digest
    assert origin.signed_provisioning_origin_digest != sha256_hex(canonical_bytes(completion))
    attestation, observed = make_attestation(origin, root)
    verify_initial_migration_attestation(origin, attestation, root.public_key(), observed)
    assert verify_signed_origin_wire(canonical_bytes(signed_intent), canonical_bytes(signed_completion),
                                     root.public_key()) == origin


def test_v1_draft_intent_has_no_executable_authority(origin_parts):
    root, intent, _ = origin_parts
    envelope = signed(intent, root, INTENT_PREFIX)
    envelope["version"] = 1
    envelope["signature"] = root.sign(INTENT_PREFIX + canonical_bytes({
        "version": 1, "key_id": envelope["key_id"], "payload": intent,
    })).hex()
    with pytest.raises(ProvisioningError, match="version"):
        verify_signed_intent(envelope, root.public_key())
    with pytest.raises(ProvisioningError, match="version"):
        verify_signed_initial_migration_intent(envelope, root.public_key())


def _release_intent(origin_parts):
    root, intent, _ = origin_parts
    intent["initial_migration_artifact_digest"] = snapshot.initial_migration_artifact_sha256()
    intent["authored_ddl_snapshot_digest"] = snapshot.verify_schema_snapshot()
    intent["initial_migration_dependency_digest"] = snapshot.initial_migration_dependency_sha256()
    intent["schema_contract_digest"] = snapshot.schema_contract_sha256()
    return root, signed(intent, root, INTENT_PREFIX)


def test_v2_signature_and_exact_release_bytes_are_both_required(origin_parts):
    root, envelope = _release_intent(origin_parts)
    verified = verify_signed_initial_migration_intent(envelope, root.public_key())
    assert verified["operator_approval"]["decision"] == "APPROVE_R1_INITIAL_PROVISIONING_AND_MIGRATION"
    envelope["payload"]["operator_approval"]["decision"] = "DENY"
    with pytest.raises(ProvisioningError, match="signature"):
        verify_signed_initial_migration_intent(envelope, root.public_key())


@pytest.mark.parametrize("source", [
    "control_plane_alembic/versions/0001_control_plane_r1_initial.py",
    "app/control_plane/r1_schema_snapshot.py",
    "app/control_plane/r1_provisioning.py",
    "app/control_plane/authority.py",
    "app/control_plane/__init__.py",
    "docs/CONTROL_PLANE_R1_OWNER_CONTRACT.md",
    "docs/CONTROL_PLANE_R1_SIGNED_INTENT_CONTRACT.md",
])
def test_signed_v2_rejects_tampered_revision_snapshot_dependency_or_contract(
        origin_parts, monkeypatch, source):
    root, envelope = _release_intent(origin_parts)
    target = (Path(__file__).resolve().parents[1] / source).resolve()
    read_bytes = Path.read_bytes

    def tampered(path):
        value = read_bytes(path)
        return value + b"\n# changed after operator approval\n" if path.resolve() == target else value

    monkeypatch.setattr(Path, "read_bytes", tampered)
    with pytest.raises(ProvisioningError, match="signed initial migration artifact digest mismatch"):
        verify_signed_initial_migration_intent(envelope, root.public_key())


@pytest.mark.parametrize("field", [
    "initial_migration_artifact_digest", "authored_ddl_snapshot_digest",
    "initial_migration_dependency_digest", "schema_contract_digest",
])
def test_each_signed_digest_is_independently_checked(origin_parts, field):
    root, envelope = _release_intent(origin_parts)
    payload = deepcopy(envelope["payload"])
    payload[field] = "f" * 64 if payload[field] != "f" * 64 else "e" * 64
    with pytest.raises(ProvisioningError, match="digest mismatch"):
        verify_signed_initial_migration_intent(signed(payload, root, INTENT_PREFIX),
                                               root.public_key())


def test_read_only_role_must_be_signed_in_intent_and_completion(origin_parts):
    root, intent, completion = origin_parts
    unsigned_role_intent = deepcopy(intent)
    del unsigned_role_intent["roles"]["read_only"]
    with pytest.raises(ProvisioningError):
        verify_signed_intent(signed(unsigned_role_intent, root, INTENT_PREFIX), root.public_key())
    missing_role_completion = deepcopy(completion)
    del missing_role_completion["role_oids"]["read_only"]
    with pytest.raises(ProvisioningError):
        verify_signed_origin(signed(intent, root, INTENT_PREFIX),
                             signed(missing_role_completion, root, COMPLETION_PREFIX),
                             root.public_key())


@pytest.mark.parametrize("replacement", ["postgres", "qingyu_gateway", "qingyu_control_app"])
def test_operator_role_must_be_dedicated(origin_parts, replacement):
    root, intent, _ = origin_parts
    intent["roles"]["operator"] = replacement
    with pytest.raises(ProvisioningError):
        verify_signed_intent(signed(intent, root, INTENT_PREFIX), root.public_key())


def test_verified_origin_detaches_and_freezes_signed_inputs(origin_parts):
    root, intent, completion = origin_parts
    signed_intent = signed(intent, root, INTENT_PREFIX)
    signed_completion = signed(completion, root, COMPLETION_PREFIX)
    origin = verify_signed_origin(signed_intent, signed_completion, root.public_key())
    original_digest = origin.signed_provisioning_origin_digest
    signed_intent["payload"]["database_name"] = "attacker_database"
    signed_completion["payload"]["role_oids"]["owner"] = 99999
    assert origin.intent["database_name"] == ACCEPTANCE_DATABASE
    assert origin.completion["role_oids"]["owner"] == 16385
    assert origin.signed_provisioning_origin_digest == original_digest
    with pytest.raises(TypeError):
        origin.intent["database_name"] = "attacker_database"
    with pytest.raises(TypeError):
        origin.completion["role_oids"]["owner"] = 99999


def test_pre_migration_requires_independent_matching_target(origin_parts):
    root, intent, completion = origin_parts
    origin = verify_signed_origin(signed(intent, root, INTENT_PREFIX),
                                  signed(completion, root, COMPLETION_PREFIX), root.public_key())
    observed = {field.name: completion[field.name] for field in fields(ObservedProvisionedTarget)}
    observed["database_oid"] += 1
    with pytest.raises(ProvisioningError):
        verify_pre_migration_target(origin, ObservedProvisionedTarget(**observed))
    observed["database_oid"] -= 1
    observed["external_storage_identity"] = "66666666-6666-4666-8666-666666666666"
    with pytest.raises(ProvisioningError):
        verify_pre_migration_target(origin, ObservedProvisionedTarget(**observed))
    with pytest.raises(ProvisioningError):
        verify_pre_migration_target(origin, None)


@pytest.mark.parametrize("field,value", [
    ("authority_generation", 2), ("canonical_initial_revision", "0001_control_plane"),
    ("database_name", "qingyu_control_acceptance"), ("test_only", False),
    ("receipt_key_creation_policy", "CREATE_ON_STARTUP"),
    ("expected_fingerprint_version", True),
])
def test_intent_rejects_noncanonical_or_legacy_origin(origin_parts, field, value):
    root, intent, _ = origin_parts
    intent[field] = value
    with pytest.raises(ProvisioningError):
        verify_signed_intent(signed(intent, root, INTENT_PREFIX), root.public_key())


def test_wrong_root_or_signature_rejected(origin_parts):
    root, intent, _ = origin_parts
    envelope = signed(intent, root, INTENT_PREFIX)
    with pytest.raises(ProvisioningError):
        verify_signed_intent(envelope, Ed25519PrivateKey.generate().public_key())
    envelope["payload"]["database_name"] = "different_database"
    with pytest.raises(ProvisioningError):
        verify_signed_intent(envelope, root.public_key())


@pytest.mark.parametrize("field,value", [
    ("database_name", "qingyu_control_acceptance"),
    ("server_system_identifier", "not-a-system-id"),
    ("receipt_key_id", "E" * 64),
    ("external_storage_identity", "66666666-6666-4666-8666-666666666666"),
    ("test_only", False),
])
def test_completion_must_match_exact_signed_plan(origin_parts, field, value):
    root, intent, completion = origin_parts
    completion[field] = value
    with pytest.raises(ProvisioningError):
        verify_signed_origin(signed(intent, root, INTENT_PREFIX),
                             signed(completion, root, COMPLETION_PREFIX), root.public_key())


def test_completion_cannot_substitute_intent_or_wrong_prefix(origin_parts):
    root, intent, completion = origin_parts
    signed_intent = signed(intent, root, INTENT_PREFIX)
    with pytest.raises(ProvisioningError):
        verify_signed_origin(signed_intent, signed(completion, root, INTENT_PREFIX),
                             root.public_key())
    with pytest.raises(ProvisioningError):
        verify_signed_origin(signed_intent, signed(completion, root, COMPLETION_PREFIX),
                             Ed25519PrivateKey.generate().public_key())


def test_completion_v1_draft_has_no_initial_authority(origin_parts):
    root, intent, completion = origin_parts
    old = signed(completion, root, COMPLETION_PREFIX)
    old["version"] = 1
    old["signature"] = root.sign(COMPLETION_PREFIX + canonical_bytes({
        "version": old["version"], "key_id": old["key_id"],
        "payload": old["payload"],
    })).hex()
    with pytest.raises(ProvisioningError, match="unsupported signed provenance version"):
        verify_signed_origin(signed(intent, root, INTENT_PREFIX), old,
                             root.public_key())


@pytest.mark.parametrize("bad_field", [
    "authored_ddl_snapshot_digest", "initial_migration_dependency_digest",
    "schema_contract_digest",
])
def test_alembic_entrypoint_rejects_wrong_signed_digest_before_origin_or_connection(
        origin_parts, bad_field):
    root, intent, _ = origin_parts
    intent[bad_field] = "f" * 64
    signed_intent = canonical_bytes(signed(intent, root, INTENT_PREFIX))
    env_file = Path(__file__).parents[1] / "control_plane_alembic" / "env.py"
    tree = ast.parse(env_file.read_text(encoding="utf-8"))
    verified = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "_verified_origin")
    namespace = {
        "__file__": str(env_file), "Path": Path, "snapshot": snapshot,
        "load_operator_root_pin": lambda _: SimpleNamespace(
            test_only=True, public_key=root.public_key(), key_id=key_id(root.public_key())),
        "_required_file": lambda name: signed_intent if name == "R1_SIGNED_INTENT_FILE" else b"{}",
        "decode_canonical_wire": decode_canonical_wire,
        "verify_signed_initial_migration_intent": verify_signed_initial_migration_intent,
        "verify_signed_origin_wire": lambda *_: pytest.fail("origin accepted before digest check"),
        "verify_initial_migration_artifact": lambda *_: pytest.fail("artifact after bad digest"),
    }
    exec(compile(ast.Module(body=[verified], type_ignores=[]), str(env_file), "exec"), namespace)
    with pytest.raises(ProvisioningError, match="signed .* digest mismatch"):
        namespace["_verified_origin"]()


def test_alembic_online_entrypoint_verifies_before_engine_creation():
    env_file = Path(__file__).parents[1] / "control_plane_alembic" / "env.py"
    tree = ast.parse(env_file.read_text(encoding="utf-8"))
    online = next(node for node in tree.body
                  if isinstance(node, ast.FunctionDef) and node.name == "run_migrations_online")
    calls = [node.func.id for node in ast.walk(online)
             if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
    assert calls.index("_verified_origin") < calls.index("create_engine")


def test_unattested_or_mismatched_catalog_is_not_ready(origin_parts):
    root, intent, completion = origin_parts
    origin = verify_signed_origin(signed(intent, root, INTENT_PREFIX),
                                  signed(completion, root, COMPLETION_PREFIX), root.public_key())
    attestation, observed = make_attestation(origin, root)
    with pytest.raises(ProvisioningError):
        verify_initial_migration_attestation(origin, {}, root.public_key(), observed)
    with pytest.raises(ProvisioningError):
        verify_initial_migration_attestation(origin, attestation, root.public_key(), None)
    changed = {field.name: getattr(observed, field.name) for field in fields(ObservedInitialState)}
    changed["schema_fingerprint"] = "f" * 64
    with pytest.raises(ProvisioningError):
        verify_initial_migration_attestation(origin, attestation, root.public_key(),
                                             ObservedInitialState(**changed))
    changed["schema_fingerprint"] = observed.schema_fingerprint
    changed["external_storage_identity"] = "66666666-6666-4666-8666-666666666666"
    with pytest.raises(ProvisioningError):
        verify_initial_migration_attestation(origin, attestation, root.public_key(),
                                             ObservedInitialState(**changed))


def test_attestation_binds_origin_and_artifact(origin_parts):
    root, intent, completion = origin_parts
    origin = verify_signed_origin(signed(intent, root, INTENT_PREFIX),
                                  signed(completion, root, COMPLETION_PREFIX), root.public_key())
    attestation, observed = make_attestation(origin, root)
    altered = deepcopy(attestation["payload"])
    altered["initial_migration_artifact_digest"] = "f" * 64
    with pytest.raises(ProvisioningError):
        verify_initial_migration_attestation(origin,
            signed(altered, root, INITIAL_ATTESTATION_PREFIX), root.public_key(), observed)
    altered = deepcopy(attestation["payload"])
    altered["signed_provisioning_origin_digest"] = "f" * 64
    with pytest.raises(ProvisioningError):
        verify_initial_migration_attestation(origin,
            signed(altered, root, INITIAL_ATTESTATION_PREFIX), root.public_key(), observed)


def test_raw_wire_rejects_noncanonical_or_duplicate_keys(origin_parts):
    root, intent, completion = origin_parts
    signed_intent = signed(intent, root, INTENT_PREFIX)
    signed_completion = signed(completion, root, COMPLETION_PREFIX)
    with pytest.raises(ValueError):
        verify_signed_origin_wire(b'{"version":1,"version":1}',
                                  canonical_bytes(signed_completion), root.public_key())
    with pytest.raises(ValueError):
        verify_signed_origin_wire(canonical_bytes(signed_intent) + b" ",
                                  canonical_bytes(signed_completion), root.public_key())
