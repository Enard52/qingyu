"""Scoped V2 PostgreSQL identity root; V1/SQLite is never a fallback.

The original V2 opening verifier owns protocol semantics. This adapter adds
durability and B2 dependency bindings, not a third signed GENESIS protocol.
Production execution remains behind a closed final-owner-confirmation gate.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace

from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from .b2_activation_lifecycle import activation_hash, database_error, utc
from .b2_signer_trust import AuthorityEnvironmentMode
from .b2_activation_readiness import SignedMigrationIntent, validate_owner_approval
from .control_plane.b2_activation_schema import SCHEMA_VERSION, CORE_REVISION
from .control_plane.r1_validation_codec import c2, decode, require, sha, h2, obj, s2
from .control_plane._r1_validation_restore import OpeningEvidence, _opening, _ArchiveRows
from .errors import CoreError

SCOPED_V2_POSTGRES = "SCOPED_V2_POSTGRES"
LEGACY_V1_SQLITE = "LEGACY_V1_SQLITE"


def encode_opening(proof):
    require(type(proof) is OpeningEvidence and proof.previous_source is None and proof.previous_trust is None,
            "NEW_GENESIS original opening proof required")
    names = ("authorization_wire", "prepare_wire", "receipt_wire", "audit_wire", "initializer_binding_wire", "initializer_component_bytes")
    body = {n: getattr(proof, n).hex() for n in names}
    for n in ("attempt_wires", "attempt_event_wires", "attempt_evidence_wires"):
        body[n] = [x.hex() for x in getattr(proof, n)]
    return c2(body)


def decode_opening(raw):
    body = decode(raw)
    names = ("authorization_wire", "prepare_wire", "receipt_wire", "audit_wire", "initializer_binding_wire", "initializer_component_bytes")
    tuples = ("attempt_wires", "attempt_event_wires", "attempt_evidence_wires")
    require(set(body) == set(names + tuples), "durable opening exact fields")
    proof = OpeningEvidence(**{**{n: bytes.fromhex(body[n]) for n in names},
                               **{n: tuple(bytes.fromhex(x) for x in body[n]) for n in tuples}})
    require(encode_opening(proof) == raw, "durable opening exact encoding")
    return proof


@dataclass(frozen=True)
class OpeningConfiguration:
    """Public configuration supplied by the protected initializer composition."""
    trust: object
    deployment: object
    initializer_binding_wire: bytes
    initializer_component_bytes: bytes
    signed_origin_digest: str

    def authority_binding(self):
        from dataclasses import fields
        from .control_plane._r1_validation_semantics import validate_pin_material
        validate_pin_material(self.trust.pin, self.deployment)
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        require(self.trust.operator_root_key_id != self.trust.receipt_key_id, "Root and receipt roles require distinct keys")
        root_der = Ed25519PublicKey.from_public_bytes(self.trust.root_public_key).public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
        receipt_der = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.trust.pin["receipt_public_key"])).public_bytes(Encoding.DER,PublicFormat.SubjectPublicKeyInfo)
        require(self.deployment.tls_spki_der not in (root_der,receipt_der), "TLS and signing roles require distinct keys")
        return {"authority_pin_wire":self.trust.pin_wire.hex(),"root_public_key":self.trust.root_public_key.hex(),
                "deployment":{f.name:(getattr(self.deployment,f.name).hex() if isinstance(getattr(self.deployment,f.name),bytes)
                    else getattr(self.deployment,f.name)) for f in fields(self.deployment)},
                "initializer_binding_hash":sha(self.initializer_binding_wire),
                "initializer_component_hash":sha(self.initializer_component_bytes),"signed_origin_digest":self.signed_origin_digest}


def verify_opening(proof, configuration):
    require(proof.initializer_binding_wire == configuration.initializer_binding_wire
        and proof.initializer_component_bytes == configuration.initializer_component_bytes,
        "opening initializer differs from protected registration")
    auth = decode(proof.authorization_wire)
    require(auth["opening_kind"] == "NEW_GENESIS" and auth["signed_origin_digest"] == configuration.signed_origin_digest,
            "opening is not admitted NEW_GENESIS")
    rows = _ArchiveRows()
    entries = {"OPENING_AUTHORIZATION": (proof.authorization_wire,), "OPENING_PREPARE": (proof.prepare_wire,),
               "AUTHORITY_RECEIPT": (proof.receipt_wire,), "CORE_AUDIT": (proof.audit_wire,),
               "INITIALIZER_ADMISSION": (proof.initializer_binding_wire,),
               "INITIALIZER_COMPONENT": (proof.initializer_component_bytes,), "GENESIS_ATTEMPT": proof.attempt_wires,
               "GENESIS_ATTEMPT_EVENT": proof.attempt_event_wires, "GENESIS_ATTEMPT_EVIDENCE": proof.attempt_evidence_wires}
    for role, values in entries.items():
        for i, value in enumerate(values):
            rows[(role, i)] = value
    # NEW_GENESIS has no previous source or history callback. The existing verifier
    # verifies Root/receipt signatures, attempts, origin seeds, deployment and Audit.
    return _opening(SimpleNamespace(opening=proof), configuration.trust, (configuration.deployment,), rows, None, 0)


def produce_new_genesis_proof(*, authorization_wire, configuration, receipt_signer, attempt_id,
                              prepared_event_id, succeeded_event_id, prepared_at, decided_at):
    """Bounded initializer producer; Root authorization is independently pre-signed.

    Signing a proposal is not a durable GENESIS. Persisted exact bytes are reused
    for retries; callers cannot recapture timestamps to change an existing root.
    """
    auth = decode(authorization_wire); pin = configuration.trust.pin
    from .control_plane.r1_validation_crypto import verify_signed
    verify_signed(authorization_wire, configuration.trust)
    require(auth["opening_kind"] == "NEW_GENESIS", "only NEW_GENESIS supported")
    origin = {"identity_digest": h2(auth["identity"]), "opening_authorization_digest": h2(auth),
              "signed_origin_digest": auth["signed_origin_digest"], "trust_config_digest": h2(pin)}
    previous_a = obj("authority_ref", wire_version=2, authority_generation=1, authority_sequence=0, receipt_hash=h2(obj("authority_origin", **origin)))
    previous_c = obj("audit_ref", wire_version=2, audit_sequence=0, audit_hash=h2(obj("audit_origin", **origin)))
    common = {"opening_id":auth["opening_id"], "opening_kind":"NEW_GENESIS", "identity_digest":h2(auth["identity"]),
              "opening_authorization_digest":h2(auth), "source_snapshot_digest":None, "state_version":0,
              "owner_identity":auth["initial_or_current_owner_identity"], "owner_version":1, "continuity_epoch":1}
    candidate = obj("opening_audit_content", **common, audit_sequence=1, previous_audit_ref=previous_c)
    attempt = obj("genesis_attempt", attempt_id=attempt_id, opening_id=auth["opening_id"], opening_authorization_digest=h2(auth),
                  identity_digest=h2(auth["identity"]), attempt_number=1, previous_attempt_digest=None, created_at=prepared_at)
    def sign(body):
        body["receipt_signature"] = receipt_signer.sign(s2(body)).hex()
        return c2(body)
    ack = obj("opening_prepare", opening_id=auth["opening_id"], opening_authorization_digest=h2(auth),
              audit_candidate_digest=h2(candidate), genesis_attempt_digest=h2(attempt),
              **{n:auth[n] for n in ("target_authority_domain_id", "target_authority_instance_id", "target_authority_generation")},
              prepared_at=prepared_at, receipt_key_id=pin["receipt_key_id"], receipt_signature="0"*128)
    ack_wire = sign(ack)
    receipt = obj("opening_receipt", **common, opening_prepare_digest=h2(ack), authority_sequence=1,
                  previous_authority_ref=previous_a, audit_candidate_digest=h2(candidate),
                  **{n:pin[n] for n in ("authority_domain_id", "authority_instance_id", "authority_generation", "receipt_key_id")},
                  decided_at=decided_at, receipt_signature="0"*128)
    receipt_wire = sign(receipt)
    audit = obj("audit_record", candidate=candidate, receipt_digest=h2(receipt))
    prepared = obj("genesis_attempt_event", event_id=prepared_event_id, attempt_id=attempt_id, previous_event_digest=None,
                   state="PREPARED", reason_code="PREPARE_PERSISTED", evidence_digest=sha(ack_wire), created_at=prepared_at)
    succeeded = obj("genesis_attempt_event", event_id=succeeded_event_id, attempt_id=attempt_id, previous_event_digest=h2(prepared),
                    state="SUCCEEDED", reason_code="OPENING_RECEIPT_PERSISTED", evidence_digest=sha(receipt_wire), created_at=decided_at)
    proof = OpeningEvidence(authorization_wire, ack_wire, receipt_wire, c2(audit), configuration.initializer_binding_wire,
                            configuration.initializer_component_bytes, (c2(attempt),), (c2(prepared), c2(succeeded)), ())
    verify_opening(proof, configuration)
    return proof


class ScopedV2PostgresCore:
    route = SCOPED_V2_POSTGRES

    def __init__(self, url, *, database, control, configuration, mode, recovery_verifier=None,
                 genesis_authorization_verifier=None):
        require(isinstance(mode, AuthorityEnvironmentMode), "explicit activation environment mode required")
        self.engine = create_engine(url, isolation_level="READ COMMITTED", pool_pre_ping=True)
        require(self.engine.dialect.name == "postgresql", "Scoped V2 Core requires PostgreSQL")
        self.database, self.control, self.configuration, self.mode = database, control, configuration, mode
        self.recovery_verifier = recovery_verifier
        # Protected composition dependency, never populated from request data.
        if genesis_authorization_verifier is not None:
            from .b2_genesis_authorization import GenesisAuthorizationVerifier, PRODUCTION, NON_PRODUCTION
            require(type(genesis_authorization_verifier) is GenesisAuthorizationVerifier,
                    "protected exact genesis verifier required")
            require(genesis_authorization_verifier.classification ==
                    (PRODUCTION if mode == AuthorityEnvironmentMode.REAL_PRODUCTION else NON_PRODUCTION),
                    "genesis verifier environment mismatch")
        self._genesis_authorization_verifier = genesis_authorization_verifier
        require(control.v2_configuration == configuration.authority_binding(), "Core/Authority fixed V2 configuration mismatch")
        if mode == AuthorityEnvironmentMode.REAL_PRODUCTION:
            require(database == "qingyu_prod", "production V2 target must be qingyu_prod")
        else:
            require(database not in {"qingyu_prod", "qingyu_control"}, "synthetic target cannot use real database identity")

    def _check(self, c):
        require(c.execute(text("SELECT current_database()")).scalar_one() == self.database, "V2 Core database mismatch")
        revision = c.execute(text("SELECT version FROM r1_core_v2.activation_migrations WHERE revision=:r"), {"r":CORE_REVISION}).scalar_one_or_none()
        require(revision == SCHEMA_VERSION, "V2 Core migration required")
        # Preserve the discovered legacy PRE_GENESIS assumptions without updating
        # legacy state or mistaking a migrated schema for an activated identity.
        if c.execute(text("SELECT to_regclass('public.genesis_records')")).scalar_one():
            require(c.execute(text("SELECT count(*) FROM public.genesis_records")).scalar_one() == 0, "legacy GENESIS already durable")
        if c.execute(text("SELECT to_regclass('public.core_metadata')")).scalar_one():
            legacy = c.execute(text("SELECT status, genesis_fingerprint, current_state_version, audit_seq FROM public.core_metadata")).all()
            require(all(s == "UNINITIALIZED" and f is None and v == a == 0 for s,f,v,a in legacy), "legacy Core not PRE_GENESIS")

    def _environment_source_guard(self, authority):
        from .b2_signer_trust import SignerProviderClassification
        classification = authority.payload["sources"]["trust"]["provider_classification"]
        if self.mode == AuthorityEnvironmentMode.REAL_PRODUCTION:
            require(classification == SignerProviderClassification.PRODUCTION_ELIGIBLE.value,
                    "synthetic signer source cannot enter production V2 activation")
        else:
            require(classification in (SignerProviderClassification.TEST_ONLY.value,
                    SignerProviderClassification.SYNTHETIC_PRODUCTION_TEST_ONLY.value),
                    "production signer source cannot enter synthetic V2 activation")

    def _state(self, c):
        # One READ COMMITTED statement/snapshot for the complete durable predicate.
        rows = c.execute(text("""SELECT 'identity' kind, to_jsonb(t) payload FROM r1_core_v2.identity t
            UNION ALL SELECT 'genesis', to_jsonb(t) FROM r1_core_v2.genesis t
            UNION ALL SELECT 'lifecycle', to_jsonb(t) FROM r1_core_v2.lifecycle t""")).all()
        groups = {"identity": [], "genesis": [], "lifecycle": []}
        for kind, row in rows:
            for field in ("record_wire", "proof_wire", "checkpoint_wire"):
                if field in row:
                    row[field] = bytes.fromhex(row[field][2:])
            groups[kind].append(row)
        identities, roots, markers = (groups[k] for k in ("identity", "genesis", "lifecycle"))
        if not identities and not roots and not markers:
            return {"status":"PRE_GENESIS"}
        require(len(identities) == len(roots) == len(markers) == 1, "GENESIS_DURABLE_CONFLICTING_STATE: partial root")
        identity, root, marker = identities[0], roots[0], markers[0]
        iw, pw, cw = bytes(identity["record_wire"]), bytes(root["proof_wire"]), bytes(marker["checkpoint_wire"])
        body, proof_body = decode(iw), decode(pw)
        require(set(body) == {"schema_version", "identity", "authority_reference", "authority_hash",
            "intent_id", "smi_hash", "genesis_hash", "environment", "target_reference", "created_at", "provenance"}
            and set(proof_body) == {"schema_version", "authority_wire", "smi_wire", "opening_wire", "owner_approval"},
            "V2 durable exact fields")
        require(activation_hash("core_identity", iw) == identity["record_hash"]
            and activation_hash("genesis", pw) == root["proof_hash"] == body["genesis_hash"]
            and root["identity_hash"] == identity["record_hash"] and sha(cw) == marker["checkpoint_hash"], "GENESIS_DURABLE_CONFLICTING_STATE: hash mismatch")
        require(body["schema_version"] == proof_body["schema_version"] == SCHEMA_VERSION
            and body["environment"] == self.control.target.environment_identity
            and body["target_reference"] == self.control.target.target_reference, "V2 durable environment/target/schema mismatch")
        proof = decode_opening(bytes.fromhex(proof_body["opening_wire"]))
        auth, receipt, audit, checkpoint = verify_opening(proof, self.configuration)
        require(cw == c2(checkpoint) and marker["state"] == "GENESIS_DURABLE", "V2 durable checkpoint mismatch")
        ids = auth["identity"]
        require(body["identity"] == ids and str(identity["identity_id"]) == ids["qingyu_identity_id"]
            and str(identity["continuity_id"]) == ids["continuity_id"]
            and str(identity["genesis_operation_id"]) == str(root["operation_id"]) == str(marker["genesis_operation_id"]) == ids["genesis_operation_id"], "V2 durable identity projection mismatch")
        authority = self.control.read_authority(body["authority_reference"])
        smi = self.control.read_smi(body["intent_id"])
        require(authority is not None and smi is not None and authority.record_hash == body["authority_hash"]
            and smi.record_hash == body["smi_hash"] and smi.payload["authority_hash"] == authority.record_hash
            and proof_body["authority_wire"] == authority.wire.hex() and proof_body["smi_wire"] == smi.wire.hex(), "V2 durable dependency mismatch")
        from .b2_activation_readiness import OwnerApproval
        validate_owner_approval(approval=OwnerApproval.model_validate(proof_body["owner_approval"]),
                               target=self.control.target, intent=SignedMigrationIntent.model_validate(smi.payload["intent"]))
        require(proof_body["owner_approval"]["approval_reference"] == smi.payload["intent"]["owner_approval_reference"],
                "durable owner approval reference mismatch")
        decision_time = datetime.fromtimestamp(receipt["decided_at"],timezone.utc)
        require(datetime.fromisoformat(authority.payload["created_at"]) <= decision_time
                and datetime.fromisoformat(proof_body["owner_approval"]["approved_at"]) <= decision_time,
                "durable GENESIS chronology mismatch")
        require(body["created_at"] == utc(datetime.fromtimestamp(receipt["decided_at"],timezone.utc))
            and body["provenance"] == {"opening_authorization_hash":h2(auth),"opening_receipt_hash":h2(receipt)}, "V2 durable immutable provenance mismatch")
        return {"status":"GENESIS_DURABLE_EXACT", "identity":body, "identity_hash":identity["record_hash"],
                "genesis_hash":root["proof_hash"], "proof_wire":pw.hex(), "checkpoint":checkpoint}

    def read_genesis_state(self):
        try:
            with self.engine.begin() as c:
                self._check(c)
                return self._state(c)
        except DBAPIError as exc:
            raise database_error(exc) from exc

    def read_pre_genesis_state(self):
        state = self.read_genesis_state()
        require(state["status"] == "PRE_GENESIS", "target is not PRE_GENESIS")
        return state

    def read_core_identity(self):
        return self.read_genesis_state().get("identity")

    def verify_core_identity(self):
        state = self.read_genesis_state()
        require(state["status"] == "GENESIS_DURABLE_EXACT", "durable Core identity required")
        return state

    def genesis_durable_predicate(self):
        """Read-only classification; storage unavailability is never ABSENT.

        Corrupt public proof/record bytes are a conflict. Database/schema/permission
        errors still propagate, so a failed query cannot masquerade as rollback.
        """
        from pydantic import ValidationError
        from .control_plane.r1_validation_codec import ContractError
        try:
            return self.read_genesis_state()
        except (ContractError, ValidationError, KeyError, TypeError, ValueError):
            return {"status":"GENESIS_DURABLE_CONFLICTING_STATE"}
        except CoreError as exc:
            if str(exc).startswith(("SMI_", "TRUST_RECORD_")):
                return {"status":"GENESIS_DURABLE_CONFLICTING_STATE"}
            raise

    @property
    def genesis_authorization_verifier(self):
        return self._genesis_authorization_verifier

    def _verify_genesis_authorization(self, authorization, *, authority_reference, intent_id, opening, owner_approval):
        from .b2_genesis_authorization import (GenesisAuthorizationVerifier, VerifiedGenesisAuthorization,
                                               genesis_authorization_context)
        if (type(authorization) is not VerifiedGenesisAuthorization
                or type(self.genesis_authorization_verifier) is not GenesisAuthorizationVerifier):
            raise CoreError("GENESIS_FINAL_OWNER_CONFIRMATION_REQUIRED")
        context = genesis_authorization_context(self, authority_reference=authority_reference,
            intent_id=intent_id, opening=opening, owner_approval=owner_approval)
        return self.genesis_authorization_verifier.revalidate(authorization, context)

    def execute_new_genesis(self, *, authority_reference, intent_id, opening, owner_approval, now, failure_hook=None,
                            authorization=None):
        if self.mode == AuthorityEnvironmentMode.REAL_PRODUCTION and authorization is None:
            raise CoreError("GENESIS_FINAL_OWNER_CONFIRMATION_REQUIRED")
        if self.mode == AuthorityEnvironmentMode.REAL_PRODUCTION or authorization is not None:
            self._verify_genesis_authorization(authorization, authority_reference=authority_reference,
                intent_id=intent_id, opening=opening, owner_approval=owner_approval)
        authority = self.control.read_authority(authority_reference); smi = self.control.read_smi(intent_id)
        require(authority is not None and smi is not None and smi.payload["authority_hash"] == authority.record_hash,
                "exact durable Authority and SMI required")
        self._environment_source_guard(authority)
        intent = SignedMigrationIntent.model_validate(smi.payload["intent"])
        validate_owner_approval(approval=owner_approval, target=self.control.target, intent=intent)
        require(owner_approval.approval_reference == intent.owner_approval_reference, "owner approval reference mismatch")
        auth, receipt, audit, checkpoint = verify_opening(opening, self.configuration)
        decision_time = datetime.fromtimestamp(receipt["decided_at"],timezone.utc)
        utc(owner_approval.approved_at); utc(now)
        require(datetime.fromisoformat(authority.payload["created_at"]) <= decision_time
                and owner_approval.approved_at <= decision_time <= now, "GENESIS chronology mismatch")
        proof_wire = c2({"schema_version":SCHEMA_VERSION, "authority_wire":authority.wire.hex(),
                         "smi_wire":smi.wire.hex(), "opening_wire":encode_opening(opening).hex(),
                         "owner_approval":owner_approval.model_dump(mode="json")})
        proof_hash = activation_hash("genesis", proof_wire)
        body = {"schema_version":SCHEMA_VERSION, "identity":auth["identity"],
                "authority_reference":authority_reference,"authority_hash":authority.record_hash,
                "intent_id":intent_id,"smi_hash":smi.record_hash,"genesis_hash":proof_hash,
                "environment":self.control.target.environment_identity,"target_reference":self.control.target.target_reference,
                "created_at":utc(datetime.fromtimestamp(receipt["decided_at"],timezone.utc)),
                "provenance":{"opening_authorization_hash":h2(auth),"opening_receipt_hash":h2(receipt)}}
        identity_wire = c2(body); identity_hash = activation_hash("core_identity", identity_wire)
        commit_attempted = False
        try:
            with self.engine.begin() as c:
                self._check(c)
                current = self._state(c)
                if current["status"] != "PRE_GENESIS":
                    require(current["identity"] == body and current["proof_wire"] == proof_wire.hex(), "B2_GENESIS_IDENTITY_CONFLICT")
                    return {**current,"outcome":"GENESIS_ALREADY_DURABLE"}
                self.control._verify_intent(intent, authority, now=now)
                require(auth["issued_at"] <= int(now.timestamp()) < auth["expires_at"], "opening not eligible now")
                identity = auth["identity"]
                inserted = c.execute(text("""INSERT INTO r1_core_v2.identity
                    (singleton,identity_id,continuity_id,genesis_operation_id,record_wire,record_hash)
                    VALUES (1,:id,:cont,:op,:wire,:hash) ON CONFLICT DO NOTHING RETURNING singleton"""),
                    {"id":identity["qingyu_identity_id"],"cont":identity["continuity_id"],"op":identity["genesis_operation_id"],"wire":identity_wire,"hash":identity_hash}).scalar_one_or_none()
                if inserted is None:
                    current = self._state(c)
                    require(current.get("identity") == body and current.get("proof_wire") == proof_wire.hex(), "B2_GENESIS_IDENTITY_CONFLICT")
                    return {**current,"outcome":"GENESIS_ALREADY_DURABLE"}
                if failure_hook: failure_hook("identity")
                c.execute(text("INSERT INTO r1_core_v2.genesis (singleton,operation_id,identity_hash,proof_wire,proof_hash) VALUES (1,:op,:ih,:wire,:hash)"),
                    {"op":identity["genesis_operation_id"],"ih":identity_hash,"wire":proof_wire,"hash":proof_hash})
                if failure_hook: failure_hook("genesis")
                cw = c2(checkpoint)
                c.execute(text("INSERT INTO r1_core_v2.lifecycle VALUES (1,:op,'GENESIS_DURABLE',:cw,:ch)"),
                    {"op":identity["genesis_operation_id"],"cw":cw,"ch":sha(cw)})
                if failure_hook: failure_hook("lifecycle")
                result = self._state(c)
                commit_attempted = True
            return {**result,"outcome":"GENESIS_DURABLE"}
        except DBAPIError as exc:
            # Commit-response loss is not inferred rollback. No retry is issued.
            if commit_attempted:
                raise CoreError("B2_GENESIS_OUTCOME_UNKNOWN_RECONCILIATION_REQUIRED") from exc
            raise database_error(exc) from exc

    def reconcile_new_genesis(self, expected_genesis_hash):
        state = self.genesis_durable_predicate()
        if state["status"] == "PRE_GENESIS":
            return "ABSENT"
        if state["status"] == "GENESIS_DURABLE_CONFLICTING_STATE":
            return "CONFLICT"
        return "EXACT" if state["genesis_hash"] == expected_genesis_hash else "CONFLICT"

    def final_owner_confirmation_gate(self, *, authority_reference, intent_id, now, authorization=None,
                                      opening=None, owner_approval=None):
        if authorization is not None:
            self._verify_genesis_authorization(authorization, authority_reference=authority_reference,
                intent_id=intent_id, opening=opening, owner_approval=owner_approval)
            authority = self.control.read_authority(authority_reference)
            smi = self.control.read_smi(intent_id)
            self._environment_source_guard(authority)
            self.control._verify_intent(SignedMigrationIntent.model_validate(smi.payload["intent"]), authority, now=now)
            self.read_pre_genesis_state()
            require(callable(self.recovery_verifier), "protected recovery verifier required")
            self.recovery_verifier()
            return {"status":"AUTHORIZATION_VERIFIED_FOR_CONTINUATION"}
        require(self.mode == AuthorityEnvironmentMode.REAL_PRODUCTION, "real final confirmation gate requires explicit production route")
        require(self.database == "qingyu_prod", "real final confirmation gate target mismatch")
        authority, smi = self.control.read_authority(authority_reference), self.control.read_smi(intent_id)
        require(authority is not None and smi is not None and smi.payload["authority_hash"] == authority.record_hash,
                "durable production dependencies required")
        self._environment_source_guard(authority)
        self.control._verify_intent(SignedMigrationIntent.model_validate(smi.payload["intent"]), authority, now=now)
        self.read_pre_genesis_state()
        require(callable(self.recovery_verifier), "protected recovery verifier required")
        self.recovery_verifier()  # protected composition dependency, not request data
        raise CoreError("GENESIS_FINAL_OWNER_CONFIRMATION_REQUIRED")
