"""Synthetic runtime evidence providers; NEVER real acceptance/prod admission.

Production-shaped envelopes permit uniquely named disposable F3 targets without
changing the frozen acceptance verifier. Every key and external identity below
is synthetic test setup; live DB catalog observations are independently read.
"""
from dataclasses import fields, replace
from datetime import datetime, timezone
import hashlib
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.canonical import canonical_json
from app.control_plane.r1_admission import AuthorityAdmission, VerifiedCoreAdmission
from app.control_plane.r1_protocol import canonical_bytes, key_id
from app.control_plane.r1_provisioning import (ObservedInitialState, COMPLETION_PREFIX, INTENT_PREFIX,
    INITIAL_ATTESTATION_PREFIX, cluster_binding_fingerprint, verify_signed_origin)
from app.control_plane.r1_root_pin import OperatorRootPin, PRODUCTION, RootTrustRecord
from cryptography.hazmat.primitives import serialization
from app.control_plane.r1_candidate_schema import F3_SCHEMA_DIGEST
from test_r1_provisioning import origin_parts, signed
from r1_f3_helpers import uid


def catalog_fingerprint(connection):
    rows = connection.execute("""SELECT p.proname,p.prosrc,p.proargtypes::text,p.prorettype::text,
        p.prosecdef,p.proconfig::text,p.proacl::text,pg_get_userbyid(p.proowner)
        FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
        WHERE n.nspname='control_plane' ORDER BY p.proname,p.proargtypes::text""").fetchall()
    return hashlib.sha256(canonical_bytes([list(row) for row in rows])).hexdigest()


class SyntheticInspector:
    def __init__(self, database, observed, external):
        self.database, self.observed, self.external = database, observed, external
        self.available = True

    def observe_initial_state(self):
        if not self.available:
            raise RuntimeError("synthetic independent observations unavailable")
        with self.database.owner() as connection:
            name, oid, owner, system = connection.execute("""SELECT current_database(),d.oid,d.datdba,
                (SELECT system_identifier::text FROM pg_control_system()) FROM pg_database d WHERE d.datname=current_database()""").fetchone()
            schema = catalog_fingerprint(connection)
            roles = dict(connection.execute("SELECT rolname,oid FROM pg_roles WHERE rolname=ANY(%s)",
                          (list(self.observed.roles.values()),)).fetchall())
        return replace(self.observed, database_name=name, database_oid=oid, owner_oid=owner,
                       server_system_identifier=system, schema_fingerprint=schema,
                       role_oids={duty: roles[name] for duty, name in self.observed.roles.items()})

    def verify_runtime_prerequisites(self, origin, pin):
        if not self.available or pin.server_spki_sha256 != self.external["spki"]:
            raise RuntimeError("synthetic TLS/custody observation absent")
        if origin.intent["initial_migration_artifact_digest"] != F3_SCHEMA_DIGEST:
            raise RuntimeError("synthetic candidate source differs")
        # Explicit test-only provider. No claim of a real DPAPI/Windows identity
        # gate or formal signed migration is made by this fixture assertion.
        assert self.database.params["dbname"].startswith("r1_f3_test_")


def setup_runtime_admission(database):
    root, p, c = origin_parts.__wrapped__()
    pin = replace(database.pin, operator_root_key_id=key_id(root.public_key()))
    database.pin = pin
    with database.owner() as connection:
        name, oid, owner, system = connection.execute("""SELECT current_database(),d.oid,d.datdba,
            (SELECT system_identifier::text FROM pg_control_system()) FROM pg_database d WHERE d.datname=current_database()""").fetchone()
        roles = dict(connection.execute("SELECT rolname,oid FROM pg_roles WHERE rolname=ANY(%s)",
                      (list(p["roles"].values()),)).fetchall())
        catalog = catalog_fingerprint(connection)
    stamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    p.update(provisioning_uuid=uid(12), authority_domain_id=uid(1), authority_instance_id=uid(2),
             database_name=name, environment="production", test_only=False,
             planned_tls_origin=pin.https_origin, operator_root_key_id=pin.operator_root_key_id,
             expected_schema_fingerprint=catalog, initial_migration_artifact_digest=F3_SCHEMA_DIGEST)
    for key in set(c) & set(p):
        c[key] = p[key]
    c.update(observed_tls_origin=pin.https_origin, server_system_identifier=system, database_oid=oid,
             owner_oid=owner, role_oids={duty: roles[role] for duty, role in p["roles"].items()},
             receipt_key_id=pin.receipt_key_id, creation_event_timestamp=stamp)
    c["cluster_binding_fingerprint"] = cluster_binding_fingerprint(**{name: c[name] for name in (
        "isolated_cluster_deployment_id", "server_system_identifier", "database_name", "database_oid", "owner_oid",
        "role_oids", "receipt_key_id", "external_storage_identity", "observed_tls_origin")})
    iw, cw = signed(p, root, INTENT_PREFIX), signed(c, root, COMPLETION_PREFIX)
    origin = verify_signed_origin(iw, cw, root.public_key())
    ap = {"provisioning_uuid": p["provisioning_uuid"], "signed_provisioning_origin_digest": origin.signed_provisioning_origin_digest,
          "canonical_initial_revision": p["canonical_initial_revision"], "fingerprint_version": p["expected_fingerprint_version"],
          "schema_fingerprint": catalog, "initial_migration_artifact_digest": p["initial_migration_artifact_digest"],
          "database_name": name, "server_system_identifier": system, "cluster_binding_fingerprint": c["cluster_binding_fingerprint"],
          "authority_domain_id": pin.authority_domain_id, "authority_instance_id": pin.authority_instance_id,
          "authority_generation": 1, "receipt_key_id": pin.receipt_key_id, "observed_at": stamp, "test_only": False}
    observed = ObservedInitialState(**{f.name: ap[f.name] if f.name in ap else c[f.name] for f in fields(ObservedInitialState)})
    public = VerifiedCoreAdmission(pin, OperatorRootPin(PRODUCTION, False, key_id(root.public_key()), root.public_key()),
        canonical_bytes(iw), canonical_bytes(cw), canonical_bytes(signed(ap, root, INITIAL_ATTESTATION_PREFIX)))
    return AuthorityAdmission(public, SyntheticInspector(database, observed, {"spki": pin.server_spki_sha256}))


class SyntheticSigner:
    def __init__(self, key):
        self.key, self.calls = key, []

    @property
    def key_id(self):
        return key_id(self.key.public_key())

    def sign(self, message):
        self.calls.append(message)
        return self.key.sign(message)


class SyntheticRootSource:
    """Test-only independently supplied public pin; never reads actual HKLM/files."""
    def __init__(self, root):
        self.root = root

    def read(self, profile):
        return RootTrustRecord(1, self.root.profile, self.root.test_only, self.root.key_id,
            self.root.public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), True)


def initial_audit_record():
    return {"audit_seq": 1, "trust_domain_id": uid(1), "continuity_id": uid(4), "continuity_epoch": 1,
        "state_version": 1, "operation_type": "AUTHORITY_GENESIS_ACTIVATION", "actor_principal_id": "test-owner",
        "capability": "core_governance", "request_id": uid(11), "mutation_id": None, "result_code": "COMMITTED",
        "payload_hash": "a" * 64, "previous_record_hash": None, "created_at": "2026-09-13T00:00:00+00:00"}
