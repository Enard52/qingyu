"""Immutable activation dependencies, separate from the old rehearsal candidate.

Source stores and target contracts are protected composition inputs, never request
fields. Historical readback verifies the original public snapshots; live eligibility
is a separate check. All transactions use READ COMMITTED and ordinary SELECT.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib

from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from .b2_activation_readiness import SignedMigrationIntent, ProductionTargetContract
from .b2_signer_trust import (
    TrustRecord, ProductionSignerAdmissionRecord, ProductionSignerAdmissionTrustBinding,
    _trust_record_hash, _admission_record_hash, verify_smi_signature,
    smi_signing_bytes, SMI_SIGNATURE_DOMAIN_V1,
)
from .control_plane.r1_validation_codec import c2, decode, require, sha
from .errors import CoreError
from .control_plane.b2_activation_schema import SCHEMA_VERSION, CONTROL_REVISION


def activation_hash(kind, wire):
    return hashlib.sha256(b"QINGYU:B2:ACTIVATION:V2/" + kind.encode("ascii") + b"\0" + wire).hexdigest()


def utc(value):
    require(isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None,
            "activation requires an aware timestamp")
    return value.astimezone(timezone.utc).isoformat()


def provenance(value):
    require(type(value) is dict and bool(value) and len(c2(value)) <= 4096, "bounded provenance required")
    return decode(c2(value))


def database_error(exc):
    code = getattr(exc.orig, "sqlstate", None)
    return CoreError("B2_ACTIVATION_" + {
        "42P01": "SCHEMA_REQUIRED", "3F000": "SCHEMA_REQUIRED", "42501": "PERMISSION_DENIED",
        "23503": "SOURCE_REFERENCE_INVALID", "23514": "CONSTRAINT_VIOLATION",
        "23502": "CONSTRAINT_VIOLATION", "40001": "TRANSACTION_RECONCILIATION_REQUIRED",
        "40P01": "TRANSACTION_RECONCILIATION_REQUIRED", "55000": "IMMUTABLE_HISTORY",
    }.get(code, "DATABASE_ERROR"))


@dataclass(frozen=True)
class DurableActivationRecord:
    wire: bytes
    record_hash: str
    outcome: str

    @property
    def payload(self):
        return decode(self.wire)


class ActivationSourceRegistry:
    """Protected composition of existing durable Trust/Admission/Binding stores."""
    def __init__(self, *, trust_store, admission_store, binding_store, admission_reference):
        self.trust_store, self.admission_store = trust_store, admission_store
        self.binding_store, self.admission_reference = binding_store, admission_reference

    def load(self, target):
        trust = self.trust_store.resolve(target.signer_trust_reference)
        admission = self.admission_store.resolve(self.admission_reference)
        binding = self.binding_store.resolve(self.admission_reference)
        sources = {"trust": trust.model_dump(mode="json"), "admission": admission.model_dump(mode="json"),
                   "binding": binding.model_dump(mode="json")}
        validate_sources(sources, target, live=True)
        return sources


def validate_sources(sources, target, *, live):
    require(set(sources) == {"trust", "admission", "binding"}, "activation source fields")
    trust = TrustRecord.model_validate(sources["trust"])
    admission = ProductionSignerAdmissionRecord.model_validate(sources["admission"])
    binding = ProductionSignerAdmissionTrustBinding.model_validate(sources["binding"])
    require(binding.trust_reference == trust.trust_reference == target.signer_trust_reference
        and binding.admission_reference == admission.admission_reference
        and binding.trust_hash == _trust_record_hash(trust)
        and binding.admission_hash == _admission_record_hash(admission), "activation source binding hash mismatch")
    require(trust.environment == admission.environment == target.environment_identity
        and trust.target_reference == admission.target_reference == target.target_reference
        and trust.provider_reference == admission.provider_reference
        and trust.provider_backend_type == admission.provider_backend_type
        and trust.key_id == admission.key_id
        and trust.public_key_fingerprint == admission.public_key_fingerprint
        and trust.algorithm == admission.algorithm == "Ed25519", "activation source identity mismatch")
    if live:
        require(trust.status.value == admission.status.value == "ACTIVE", "activation sources not currently eligible")
    return trust


class ActivationControlStore:
    def __init__(self, url, *, database, target: ProductionTargetContract, sources: ActivationSourceRegistry, configuration):
        self.engine = create_engine(url, isolation_level="READ COMMITTED", pool_pre_ping=True)
        require(self.engine.dialect.name == "postgresql", "activation control requires PostgreSQL")
        self.database, self.target, self.sources = database, target.model_copy(deep=True), sources
        self.v2_configuration = decode(c2(configuration.authority_binding()))

    def _check(self, c):
        require(c.execute(text("SELECT current_database()")).scalar_one() == self.database, "activation control database mismatch")
        v = c.execute(text("SELECT version FROM governance.activation_migrations WHERE revision=:r"), {"r": CONTROL_REVISION}).scalar_one_or_none()
        require(v == SCHEMA_VERSION, "activation control migration required")

    def _read(self, c, kind, reference):
        table, key = ("activation_authorities", "authority_reference") if kind == "authority" else ("activation_smis", "intent_id")
        row = c.execute(text(f"SELECT * FROM governance.{table} WHERE {key}=:id"), {"id": reference}).mappings().one_or_none()
        if row is None:
            return None
        wire = bytes(row["record_wire"])
        body = decode(wire)
        require(activation_hash(kind, wire) == row["record_hash"] and body["schema_version"] == SCHEMA_VERSION,
                "activation durable hash/schema mismatch")
        if kind == "authority":
            require(set(body) == {"schema_version", "authority_reference", "target", "sources", "v2_configuration", "created_at", "provenance"}, "authority durable fields")
            require(body["authority_reference"] == reference and body["target"] == self.target.model_dump(mode="json")
                and row["environment"] == self.target.environment_identity and row["target_reference"] == self.target.target_reference
                and row["admission_reference"] == body["sources"]["admission"]["admission_reference"], "authority durable target mismatch")
            require(body["v2_configuration"] == self.v2_configuration, "authority fixed V2 configuration mismatch")
            require(utc(datetime.fromisoformat(body["created_at"])) == body["created_at"], "authority timestamp not canonical UTC")
            provenance(body["provenance"])
            validate_sources(body["sources"], self.target, live=False)
        else:
            require(set(body) == {"schema_version", "authority_reference", "authority_hash", "intent", "payload_hash", "signed_bytes_hash"}, "SMI durable fields")
            require(row["authority_reference"] == body["authority_reference"] and row["authority_hash"] == body["authority_hash"], "SMI durable projection mismatch")
            authority = self._read(c, "authority", body["authority_reference"])
            require(authority is not None and authority.record_hash == body["authority_hash"], "SMI durable authority missing/conflict")
            intent = SignedMigrationIntent.model_validate(body["intent"])
            require(intent.intent_id == reference and intent.canonical_payload_hash == body["payload_hash"]
                and sha(SMI_SIGNATURE_DOMAIN_V1 + smi_signing_bytes(intent.canonical_payload())) == body["signed_bytes_hash"], "SMI durable signing bytes mismatch")
            self._verify_intent(intent, authority, now=None)
        return DurableActivationRecord(wire, row["record_hash"], "READBACK")

    def read_authority(self, reference):
        return self._read_record("authority", reference)

    def read_smi(self, reference):
        return self._read_record("smi", reference)

    def _read_record(self, kind, reference):
        try:
            with self.engine.begin() as c:
                self._check(c)
                return self._read(c, kind, reference)
        except DBAPIError as exc:
            raise database_error(exc) from exc

    def preview_authority(self, *, authority_reference, created_at, provenance_record):
        require(authority_reference == self.target.authority_reference, "authority target reference mismatch")
        existing = self.read_authority(authority_reference)
        # Exact immutable replay is a historical read, not a new eligibility grant.
        sources = existing.payload["sources"] if existing else self.sources.load(self.target)
        body = {"schema_version": SCHEMA_VERSION, "authority_reference": authority_reference,
                "target": self.target.model_dump(mode="json"), "sources": sources,
                "v2_configuration": self.v2_configuration,
                "created_at": utc(created_at), "provenance": provenance(provenance_record)}
        wire = c2(body)
        return DurableActivationRecord(wire, activation_hash("authority",wire), "VALIDATED_NOT_DURABLE")

    def create_authority(self, **request):
        candidate = self.preview_authority(**request)
        return self._insert("authority", candidate.payload["authority_reference"], candidate.payload)

    def validate_preparation_request(self, *, authority_request, intent, now):
        candidate = self.preview_authority(**authority_request)
        intent = SignedMigrationIntent.model_validate(intent.model_dump(mode="json"))
        existing = self.read_smi(intent.intent_id)
        self._verify_intent(intent,candidate,now=None if existing else now)
        return candidate

    def _verify_intent(self, intent, authority, *, now):
        utc(intent.valid_from); utc(intent.expires_at)
        trust = validate_sources(authority.payload["sources"], self.target, live=False)
        require(intent.authority_trust_reference == trust.trust_reference and intent.signer_key_id == trust.key_id
            and intent.target_environment == self.target.environment_identity
            and intent.target_reference == self.target.target_reference
            and intent.target_schema_migration_version == self.target.migration_version, "SMI authority/target/key mismatch")
        verify_smi_signature(canonical_payload=intent.canonical_payload(), signature_hex=intent.signature_metadata.signature, trust_record=trust)
        if now is not None:
            utc(now)
            require(intent.valid_from <= now < intent.expires_at, "SMI not valid at execution time")
            require(self.sources.load(self.target) == authority.payload["sources"], "authority source identity changed")

    def persist_smi(self, intent, *, authority_reference, now):
        intent = SignedMigrationIntent.model_validate(intent.model_dump(mode="json"))
        authority = self.read_authority(authority_reference)
        require(authority is not None, "durable Authority required")
        existing = self.read_smi(intent.intent_id)
        self._verify_intent(intent, authority, now=None if existing else now)
        body = {"schema_version": SCHEMA_VERSION, "authority_reference": authority_reference,
                "authority_hash": authority.record_hash, "intent": intent.model_dump(mode="json"),
                "payload_hash": intent.canonical_payload_hash,
                "signed_bytes_hash": sha(SMI_SIGNATURE_DOMAIN_V1 + smi_signing_bytes(intent.canonical_payload()))}
        return self._insert("smi", intent.intent_id, body)

    def _insert(self, kind, reference, body):
        wire = c2(body); digest = activation_hash(kind, wire)
        try:
            with self.engine.begin() as c:
                self._check(c)
                if kind == "authority":
                    result = c.execute(text("""INSERT INTO governance.activation_authorities
                        (authority_reference,environment,target_reference,admission_reference,record_wire,record_hash)
                        VALUES (:id,:env,:target,:admission,:wire,:hash) ON CONFLICT DO NOTHING RETURNING authority_reference"""),
                        {"id":reference,"env":self.target.environment_identity,"target":self.target.target_reference,
                         "admission":body["sources"]["admission"]["admission_reference"],"wire":wire,"hash":digest}).scalar_one_or_none()
                else:
                    result = c.execute(text("""INSERT INTO governance.activation_smis
                        (intent_id,authority_reference,authority_hash,record_wire,record_hash)
                        VALUES (:id,:a,:ah,:wire,:hash) ON CONFLICT DO NOTHING RETURNING intent_id"""),
                        {"id":reference,"a":body["authority_reference"],"ah":body["authority_hash"],"wire":wire,"hash":digest}).scalar_one_or_none()
                # READ COMMITTED: this statement gets a new snapshot after INSERT waits.
                found = self._read(c, kind, reference)
                if found is None or found.wire != wire or found.record_hash != digest:
                    raise CoreError("B2_ACTIVATION_IDENTITY_CONFLICT")
                return DurableActivationRecord(wire, digest, "CREATED" if result else "EXACT_REPLAY")
        except DBAPIError as exc:
            raise database_error(exc) from exc

    def partial_state(self, *, authority_reference, intent_id):
        authority = self.read_authority(authority_reference)
        if authority is None:
            return "AUTHORITY_ABSENT"
        smi = self.read_smi(intent_id)
        return "AUTHORITY_DURABLE_SMI_ABSENT" if smi is None else "AUTHORITY_AND_SMI_DURABLE_GENESIS_ABSENT"
