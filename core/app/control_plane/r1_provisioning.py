"""Pure verification of the R1 Authority's signed, non-legacy origin.

No database, Docker, key creation, or private operator-root operation belongs
here. Callers must obtain observed catalog/cluster facts from a trusted
read-only inspector; an envelope cannot attest to its own observations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import re
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .r1_protocol import canonical_bytes, decode_canonical_wire, key_id, sha256_hex


INTENT_PREFIX = b"QINGYU-CP-R1-PROVISIONING-INTENT\x00"
COMPLETION_PREFIX = b"QINGYU-CP-R1-PROVISIONING-COMPLETION\x00"
ORIGIN_PREFIX = b"QINGYU-CP-R1-PROVISIONING-ORIGIN\x00"
INITIAL_ATTESTATION_PREFIX = b"QINGYU-CP-R1-INITIAL-MIGRATION-ATTESTATION\x00"
INITIAL_REVISION = "0001_control_plane_r1_initial"
ACCEPTANCE_DATABASE = "qingyu_control_r1_acceptance"
ROLE_POLICY = "R1_RESTRICTED_V2"
KEY_CREATION_POLICY = "CREATE_AFTER_SIGNED_INTENT_IN_SECRET_BOUNDARY"

_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,62}\Z")
_KEY_REF = re.compile(r"dpapi-localmachine://[a-zA-Z0-9/_-]+\Z")
_DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ROLES = frozenset({"owner", "migrator", "service", "operator", "read_only"})
_ENVELOPE = frozenset({"version", "key_id", "payload", "signature"})
_INTENT = frozenset({
    "provisioning_uuid", "authority_domain_id", "authority_instance_id",
    "authority_generation", "environment", "profile",
    "isolated_cluster_deployment_id", "database_name", "planned_tls_origin",
    "canonical_initial_revision", "initial_migration_artifact_digest",
    "authored_ddl_snapshot_digest", "initial_migration_dependency_version",
    "initial_migration_dependency_digest", "schema_contract_version",
    "schema_contract_digest", "operator_approval",
    "expected_fingerprint_version", "expected_schema_fingerprint", "roles",
    "role_policy", "receipt_key_slot_reference", "receipt_key_creation_policy",
    "operator_root_key_id", "test_only",
})
_COMPLETION = frozenset({
    "provisioning_uuid", "authority_domain_id", "authority_instance_id",
    "authority_generation", "environment", "isolated_cluster_deployment_id",
    "database_name", "observed_tls_origin", "server_system_identifier",
    "canonical_initial_revision", "initial_migration_artifact_digest",
    "authored_ddl_snapshot_digest", "initial_migration_dependency_version",
    "initial_migration_dependency_digest", "schema_contract_version",
    "schema_contract_digest", "operator_approval",
    "expected_fingerprint_version", "expected_schema_fingerprint",
    "database_oid", "owner_oid", "role_oids", "roles",
    "creation_event_timestamp", "receipt_key_slot_reference",
    "receipt_key_id", "external_storage_identity", "cluster_binding_fingerprint", "test_only",
})
_ATTESTATION = frozenset({
    "provisioning_uuid", "signed_provisioning_origin_digest",
    "canonical_initial_revision", "fingerprint_version", "schema_fingerprint",
    "initial_migration_artifact_digest", "database_name", "server_system_identifier",
    "cluster_binding_fingerprint", "authority_domain_id", "authority_instance_id",
    "authority_generation", "receipt_key_id", "observed_at", "test_only",
})


class ProvisioningError(ValueError):
    """A required signature, origin binding, or observed fact is absent."""


def _snapshot(value: Mapping[str, Any]) -> dict[str, Any]:
    """Detach signed input from caller-owned mutable dictionaries before use."""
    return decode_canonical_wire(canonical_bytes(value))


def _freeze(value: Any) -> Any:
    """Recursively make validated provenance observations immutable."""
    if isinstance(value, Mapping):
        return MappingProxyType({name: _freeze(item) for name, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _exact(value: Any, fields: frozenset[str]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise ProvisioningError("missing or unexpected provenance field")
    return value


def _uuid(value: Any) -> None:
    try:
        valid = type(value) is str and str(UUID(value)) == value
    except ValueError:
        valid = False
    if not valid:
        raise ProvisioningError("non-canonical provenance UUID")


def _hash(value: Any) -> None:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise ProvisioningError("invalid provenance digest")


def _positive(value: Any) -> None:
    if type(value) is not int or value < 1:
        raise ProvisioningError("invalid positive catalog value")


def _timestamp(value: Any) -> None:
    if type(value) is not str or not value.endswith("Z"):
        raise ProvisioningError("timestamp must be UTC")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProvisioningError("invalid UTC timestamp") from exc
    if parsed.tzinfo != timezone.utc or parsed.isoformat().replace("+00:00", "Z") != value:
        raise ProvisioningError("non-canonical UTC timestamp")


def _tls_origin(value: Any) -> None:
    if type(value) is not str:
        raise ProvisioningError("invalid planned TLS origin")
    try:
        parsed = urlsplit(value)
        host, port = parsed.hostname, parsed.port
    except ValueError as exc:
        raise ProvisioningError("invalid planned TLS origin") from exc
    if (parsed.scheme != "https" or not host or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or parsed.netloc.endswith(":")
            or value != f"https://{parsed.netloc}"):
        raise ProvisioningError("invalid planned TLS origin")
    if ":" in host:
        try:
            if "%" in host or str(ipaddress.IPv6Address(host)) != host:
                raise ProvisioningError("invalid planned TLS origin")
        except ValueError as exc:
            raise ProvisioningError("invalid planned TLS origin") from exc
        expected_netloc = f"[{host}]" + (f":{port}" if port is not None else "")
    else:
        if not all(_DNS_LABEL.fullmatch(part) for part in host.split(".")):
            raise ProvisioningError("invalid planned TLS origin")
        expected_netloc = host + (f":{port}" if port is not None else "")
    if (port is not None and not 1 <= port <= 65535) or parsed.netloc != expected_netloc:
        raise ProvisioningError("non-canonical planned TLS origin")


def cluster_binding_fingerprint(*, isolated_cluster_deployment_id: str,
                                server_system_identifier: str, database_name: str,
                                database_oid: int, owner_oid: int,
                                role_oids: Mapping[str, int], receipt_key_id: str,
                                external_storage_identity: str,
                                observed_tls_origin: str) -> str:
    """Versioned binding to PG and external storage observations.

    PostgreSQL cannot prove ``external_storage_identity`` on its own. A
    separately trusted read-only deployment inspector must obtain and compare
    the actual volume/storage identity; the signed claim alone is insufficient.
    """
    _uuid(isolated_cluster_deployment_id)
    _uuid(external_storage_identity)
    if type(server_system_identifier) is not str or not server_system_identifier.isdigit():
        raise ProvisioningError("invalid PostgreSQL system identifier")
    if type(database_name) is not str or _NAME.fullmatch(database_name) is None:
        raise ProvisioningError("invalid Authority database name")
    _positive(database_oid)
    _positive(owner_oid)
    role_oids = _exact(role_oids, _ROLES)
    for oid in role_oids.values():
        _positive(oid)
    if len(set(role_oids.values())) != 5 or role_oids["owner"] != owner_oid:
        raise ProvisioningError("role identities or owner OID differ")
    _hash(receipt_key_id)
    _tls_origin(observed_tls_origin)
    return sha256_hex(b"QINGYU-CP-R1-CLUSTER-BINDING-V1\x00" + canonical_bytes({
        "isolated_cluster_deployment_id": isolated_cluster_deployment_id,
        "server_system_identifier": server_system_identifier,
        "database_name": database_name,
        "database_oid": database_oid,
        "owner_oid": owner_oid,
        "role_oids": dict(role_oids),
        "receipt_key_id": receipt_key_id,
        "external_storage_identity": external_storage_identity,
        "observed_tls_origin": observed_tls_origin,
    }))


def _roles(value: Any) -> Mapping[str, str]:
    roles = _exact(value, _ROLES)
    for name in roles.values():
        if type(name) is not str or _NAME.fullmatch(name) is None:
            raise ProvisioningError("invalid role name")
    if len(set(roles.values())) != 5 or "qingyu_control_app" in roles.values():
        raise ProvisioningError("roles must be separate from one another and legacy")
    if (roles["owner"] != "control_plane_owner"
            or roles["migrator"] != "control_plane_migrator"
            or roles["service"] != "control_plane_app"
            or roles["operator"] != "control_plane_operator"
            or roles["read_only"] != "control_plane_reader"):
        raise ProvisioningError("R1 role policy names differ")
    return roles


def _verify_envelope(envelope: Any, root: Ed25519PublicKey, prefix: bytes,
                     *, expected_version: int = 1) -> Mapping[str, Any]:
    item = _exact(envelope, _ENVELOPE)
    if type(item["version"]) is not int or item["version"] != expected_version:
        raise ProvisioningError("unsupported signed provenance version")
    if item["key_id"] != key_id(root):
        raise ProvisioningError("wrong immutable operator root")
    signature = item["signature"]
    if type(signature) is not str or re.fullmatch(r"[0-9a-f]{128}", signature) is None:
        raise ProvisioningError("invalid provenance signature encoding")
    try:
        root.verify(bytes.fromhex(signature), prefix + canonical_bytes({
            "version": item["version"], "key_id": item["key_id"],
            "payload": item["payload"],
        }))
    except InvalidSignature as exc:
        raise ProvisioningError("invalid operator-root signature") from exc
    return item


def verify_signed_intent(envelope: Mapping[str, Any], root: Ed25519PublicKey) -> Mapping[str, Any]:
    """Verify one Root-signed V2 intent; V1 draft has no executable authority.

    This verifies signature and signed structure only. The separate release
    check must compare all signed digests with independently read local bytes
    before any provisioning or migration action.
    """
    item = _verify_envelope(_snapshot(envelope), root, INTENT_PREFIX,
                            expected_version=2)
    p = _exact(item["payload"], _INTENT)
    for name in ("provisioning_uuid", "authority_domain_id", "authority_instance_id",
                 "isolated_cluster_deployment_id"):
        _uuid(p[name])
    if type(p["authority_generation"]) is not int or p["authority_generation"] != 1:
        raise ProvisioningError("initial origin must start at generation 1")
    if p["environment"] not in ("acceptance", "production") or p["profile"] != "R1_PERSONAL_PRODUCTION":
        raise ProvisioningError("unsupported Authority environment/profile")
    if type(p["test_only"]) is not bool or (p["environment"] == "acceptance") != p["test_only"]:
        raise ProvisioningError("test-only origin must be explicit")
    if type(p["database_name"]) is not str or _NAME.fullmatch(p["database_name"]) is None:
        raise ProvisioningError("invalid Authority database name")
    if (p["database_name"] in {"qingyu_control_acceptance", "qingyu_core", "qingyu_gateway",
                                 "postgres", "template0", "template1"}
            or p["environment"] == "acceptance" and p["database_name"] != ACCEPTANCE_DATABASE):
        raise ProvisioningError("legacy or non-isolated database target")
    _tls_origin(p["planned_tls_origin"])
    if p["canonical_initial_revision"] != INITIAL_REVISION:
        raise ProvisioningError("wrong initial migration lineage")
    _hash(p["initial_migration_artifact_digest"])
    _hash(p["authored_ddl_snapshot_digest"])
    if p["initial_migration_dependency_version"] != 1 or type(
            p["initial_migration_dependency_version"]) is not int:
        raise ProvisioningError("unsupported migration dependency digest version")
    _hash(p["initial_migration_dependency_digest"])
    if p["schema_contract_version"] != 1 or type(p["schema_contract_version"]) is not int:
        raise ProvisioningError("unsupported schema contract digest version")
    _hash(p["schema_contract_digest"])
    approval = _exact(p["operator_approval"], frozenset({"approval_id", "decision", "approved_at"}))
    _uuid(approval["approval_id"])
    if approval["decision"] != "APPROVE_R1_INITIAL_PROVISIONING_AND_MIGRATION":
        raise ProvisioningError("missing explicit operator approval")
    _timestamp(approval["approved_at"])
    _positive(p["expected_fingerprint_version"])
    _hash(p["expected_schema_fingerprint"])
    _roles(p["roles"])
    if p["role_policy"] != ROLE_POLICY:
        raise ProvisioningError("wrong role policy")
    if (type(p["receipt_key_slot_reference"]) is not str
            or _KEY_REF.fullmatch(p["receipt_key_slot_reference"]) is None
            or p["receipt_key_creation_policy"] != KEY_CREATION_POLICY):
        raise ProvisioningError("receipt key must be created after signed intent in secret boundary")
    if p["operator_root_key_id"] != key_id(root):
        raise ProvisioningError("operator root identity mismatch")
    return _freeze(p)


def verify_signed_initial_migration_intent(
        envelope: Mapping[str, Any], root: Ed25519PublicKey) -> Mapping[str, Any]:
    """Verify the V2 signature plus exact local release-byte bindings.

    This is a necessary cryptographic check, never sufficient admission for
    cluster/DB/role/key creation or migration. It does not prove the owner
    contract is executable, the expected catalog fingerprint is attainable,
    the installed third-party wheels are frozen, or that the root/target are
    independently trusted. Callers must enforce those separate gates.
    """
    intent = verify_signed_intent(envelope, root)
    from . import r1_schema_snapshot as snapshot

    if snapshot.initial_migration_artifact_sha256() != intent["initial_migration_artifact_digest"]:
        raise ProvisioningError("signed initial migration artifact digest mismatch")
    if snapshot.verify_schema_snapshot() != intent["authored_ddl_snapshot_digest"]:
        raise ProvisioningError("signed authored-DDL snapshot digest mismatch")
    if (snapshot.initial_migration_dependency_sha256()
            != intent["initial_migration_dependency_digest"]):
        raise ProvisioningError("signed migration dependency digest mismatch")
    if snapshot.schema_contract_sha256() != intent["schema_contract_digest"]:
        raise ProvisioningError("signed schema contract digest mismatch")
    return intent


@dataclass(frozen=True, slots=True)
class VerifiedOrigin:
    intent: Mapping[str, Any]
    completion: Mapping[str, Any]
    signed_provisioning_origin_digest: str


@dataclass(frozen=True, slots=True)
class ObservedProvisionedTarget:
    """Independent PG, key-store, TLS and external-storage observations.

    The caller must not construct this from the signed completion manifest
    itself. In particular, PostgreSQL does not attest to its Docker volume.
    """

    isolated_cluster_deployment_id: str
    database_name: str
    observed_tls_origin: str
    server_system_identifier: str
    database_oid: int
    owner_oid: int
    role_oids: Mapping[str, int]
    roles: Mapping[str, str]
    receipt_key_slot_reference: str
    receipt_key_id: str
    external_storage_identity: str


def verify_pre_migration_target(origin: VerifiedOrigin,
                                observed: ObservedProvisionedTarget) -> None:
    """Fail closed before Alembic if the signed origin is not this live target."""
    if not isinstance(origin, VerifiedOrigin) or not isinstance(observed, ObservedProvisionedTarget):
        raise ProvisioningError("missing signed origin or live target observations")
    for field in ObservedProvisionedTarget.__dataclass_fields__:
        if getattr(observed, field) != origin.completion[field]:
            raise ProvisioningError("live pre-migration target differs from signed origin")
    if cluster_binding_fingerprint(
            isolated_cluster_deployment_id=observed.isolated_cluster_deployment_id,
            server_system_identifier=observed.server_system_identifier,
            database_name=observed.database_name,
            database_oid=observed.database_oid,
            owner_oid=observed.owner_oid,
            role_oids=observed.role_oids,
            receipt_key_id=observed.receipt_key_id,
            external_storage_identity=observed.external_storage_identity,
            observed_tls_origin=observed.observed_tls_origin) != origin.completion["cluster_binding_fingerprint"]:
        raise ProvisioningError("live pre-migration physical-cluster binding differs")


def verify_signed_origin(intent_envelope: Mapping[str, Any],
                         completion_envelope: Mapping[str, Any],
                         root: Ed25519PublicKey) -> VerifiedOrigin:
    """Both full signed envelopes, including signatures, form the origin."""
    intent_envelope = _snapshot(intent_envelope)
    completion_envelope = _snapshot(completion_envelope)
    intent = verify_signed_intent(intent_envelope, root)
    completion = _verify_envelope(completion_envelope, root, COMPLETION_PREFIX,
                                  expected_version=2)["payload"]
    p = _exact(completion, _COMPLETION)
    for field in ("provisioning_uuid", "authority_domain_id", "authority_instance_id",
                  "isolated_cluster_deployment_id"):
        _uuid(p[field])
    for field in ("provisioning_uuid", "authority_domain_id", "authority_instance_id",
                  "authority_generation", "environment", "isolated_cluster_deployment_id",
                  "database_name", "canonical_initial_revision",
                  "initial_migration_artifact_digest", "expected_fingerprint_version",
                  "expected_schema_fingerprint", "roles", "receipt_key_slot_reference", "test_only",
                  "authored_ddl_snapshot_digest", "initial_migration_dependency_version",
                  "initial_migration_dependency_digest", "schema_contract_version",
                  "schema_contract_digest", "operator_approval"):
        if p[field] != intent[field]:
            raise ProvisioningError("completion does not bind exact signed intent")
    if p["observed_tls_origin"] != intent["planned_tls_origin"]:
        raise ProvisioningError("observed TLS origin differs from signed plan")
    if type(p["server_system_identifier"]) is not str or not p["server_system_identifier"].isdigit():
        raise ProvisioningError("invalid PostgreSQL system identifier")
    for field in ("database_oid", "owner_oid"):
        _positive(p[field])
    role_oids = _exact(p["role_oids"], _ROLES)
    for oid in role_oids.values():
        _positive(oid)
    if len(set(role_oids.values())) != 5 or role_oids["owner"] != p["owner_oid"]:
        raise ProvisioningError("role identities or owner OID differ")
    _roles(p["roles"])
    _timestamp(p["creation_event_timestamp"])
    _hash(p["receipt_key_id"])
    _uuid(p["external_storage_identity"])
    _hash(p["cluster_binding_fingerprint"])
    if p["cluster_binding_fingerprint"] != cluster_binding_fingerprint(
            isolated_cluster_deployment_id=p["isolated_cluster_deployment_id"],
            server_system_identifier=p["server_system_identifier"],
            database_name=p["database_name"], database_oid=p["database_oid"],
            owner_oid=p["owner_oid"], role_oids=p["role_oids"],
            receipt_key_id=p["receipt_key_id"],
            external_storage_identity=p["external_storage_identity"],
            observed_tls_origin=p["observed_tls_origin"]):
        raise ProvisioningError("incorrect physical-cluster binding")
    digest = sha256_hex(ORIGIN_PREFIX + canonical_bytes({
        "intent": intent_envelope, "completion": completion_envelope,
    }))
    return VerifiedOrigin(intent=intent, completion=_freeze(p),
                          signed_provisioning_origin_digest=digest)


@dataclass(frozen=True, slots=True)
class ObservedInitialState:
    """Facts supplied by a separate trusted, read-only PostgreSQL inspector."""

    provisioning_uuid: str
    signed_provisioning_origin_digest: str
    canonical_initial_revision: str
    fingerprint_version: int
    schema_fingerprint: str
    database_name: str
    server_system_identifier: str
    cluster_binding_fingerprint: str
    authority_domain_id: str
    authority_instance_id: str
    authority_generation: int
    receipt_key_id: str
    isolated_cluster_deployment_id: str
    database_oid: int
    owner_oid: int
    role_oids: Mapping[str, int]
    roles: Mapping[str, str]
    receipt_key_slot_reference: str
    external_storage_identity: str
    observed_tls_origin: str


def verify_initial_migration_attestation(origin: VerifiedOrigin,
                                         envelope: Mapping[str, Any],
                                         root: Ed25519PublicKey,
                                         observed: ObservedInitialState) -> None:
    """Readiness requires a signed attestation AND matching live catalog facts.

    A post-commit/pre-attestation crash is non-serving. The caller may only
    re-inspect the same revision/marker/fingerprint and resume this attestation.
    """
    if not isinstance(origin, VerifiedOrigin) or not isinstance(observed, ObservedInitialState):
        raise ProvisioningError("missing verified origin or observed catalog")
    p = _exact(_verify_envelope(envelope, root, INITIAL_ATTESTATION_PREFIX)["payload"],
               _ATTESTATION)
    _timestamp(p["observed_at"])
    if datetime.fromisoformat(p["observed_at"].replace("Z", "+00:00")) < datetime.fromisoformat(
            origin.completion["creation_event_timestamp"].replace("Z", "+00:00")):
        raise ProvisioningError("attestation predates creation")
    expected = {
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
        "authority_generation": 1,
        "receipt_key_id": origin.completion["receipt_key_id"],
        "test_only": origin.intent["test_only"],
    }
    for field, value in expected.items():
        if p[field] != value:
            raise ProvisioningError("attestation differs from signed origin")
        if field != "initial_migration_artifact_digest" and field != "test_only":
            if getattr(observed, field) != value:
                raise ProvisioningError("live catalog differs from attested origin")
    verify_pre_migration_target(origin, ObservedProvisionedTarget(**{
        field: getattr(observed, field)
        for field in ObservedProvisionedTarget.__dataclass_fields__
    }))


def verify_signed_origin_wire(intent_raw: bytes, completion_raw: bytes,
                              root: Ed25519PublicKey) -> VerifiedOrigin:
    return verify_signed_origin(decode_canonical_wire(intent_raw),
                                decode_canonical_wire(completion_raw), root)
