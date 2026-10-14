"""Fixed migration plan capabilities; protected composition is the trust root.

No production pin is installed here. Future composition must independently
authorize/install the evidence digest and final amendment checkpoint. Hashes
bind immutable public execution metadata, not Owner authorship or credentials.
This is not an ops executor and grants no actor/ACL/confirmation authority.
Python private constructors are not a code-hostile-process security boundary.
"""
from dataclasses import dataclass
import re

from .control_plane.r1_validation_codec import c2, decode, sha
from .errors import CoreError

REAL_PRODUCTION = "REAL_PRODUCTION"
SYNTHETIC_TEST = "SYNTHETIC_TEST"
BASE_CHECKPOINT = "ff1fc37e6028aeef56ed7c41d5d2237cc59837b4"
POLICY_ID = "qingyu-fixed-b2-migration-plan-v1"


def fail(reason):
    raise CoreError("B2_MIGRATION_AUTHORIZATION_" + reason)


def _object(wire):
    if type(wire) is not bytes or len(wire) > 65536:
        fail("MALFORMED_EVIDENCE")
    try:
        body = decode(wire)
    except (ValueError, TypeError, UnicodeError):
        fail("MALFORMED_EVIDENCE")
    if type(body) is not dict:
        fail("MALFORMED_EVIDENCE")
    return body


@dataclass(frozen=True)
class PreparedMigrationPlan:
    wire: bytes

    @property
    def plan_hash(self):
        return sha(self.wire)


def prepare_migration_plan(*, database, kind, classification, environment,
                           base_checkpoint, amendment_checkpoint):
    """One ordered singleton bundle per canonical database; never cross-DB DDL.

    ABSENT_OR_EXACT is the existing ledger precondition: permits exact replay,
    with conflict/prerequisite enforcement left to the unchanged transaction.
    It does not assert that the ledger was read or that any migration ran.
    """
    from .control_plane.b2_activation_schema import CONTROL_REVISION, CORE_REVISION, SCHEMA_VERSION
    from .b2_signer_trust import (
        POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_MIGRATION_ID as prior,
        POSTGRES_PRODUCTION_SIGNER_ADMISSION_TRUST_BINDING_STORE_SCHEMA_VERSION as version,
    )
    if type(kind) is not str or kind not in {"control", "core"}:
        fail("BUNDLE_MISMATCH")
    expected_db = "qingyu_control" if kind == "control" else "qingyu_prod"
    if classification == REAL_PRODUCTION:
        if database != expected_db or environment != "PRODUCTION":
            fail("TARGET_MISMATCH")
        if base_checkpoint != BASE_CHECKPOINT or type(amendment_checkpoint) is not str or not re.fullmatch(r"[0-9a-f]{40}", amendment_checkpoint):
            fail("LINEAGE_MISMATCH")
    elif classification == SYNTHETIC_TEST:
        if (type(database) is not str or (database != expected_db and not re.fullmatch(r"synthetic_migration_[0-9a-f]{10}", database))
                or environment != "NON_PRODUCTION"):
            fail("TARGET_MISMATCH")
        if not all(type(x) is str and re.fullmatch(r"NON_PRODUCTION:[A-Za-z0-9_-]{1,80}", x)
                   for x in (base_checkpoint, amendment_checkpoint)):
            fail("LINEAGE_MISMATCH")
    else:
        fail("CLASSIFICATION_MISMATCH")
    schema = "governance" if kind == "control" else "r1_core_v2"
    revision = CONTROL_REVISION if kind == "control" else CORE_REVISION
    return PreparedMigrationPlan(c2({
        "version": POLICY_ID, "classification": classification,
        "base_checkpoint": base_checkpoint, "amendment_checkpoint": amendment_checkpoint,
        "database": database, "environment": environment, "family": "B2_ACTIVATION_" + kind.upper(),
        "ordered_migrations": [revision],
        "dependencies": [{"migration_id": prior, "schema_version": version}] if kind == "control" else [],
        "schema": schema, "ledger": schema + ".activation_migrations",
        "ledger_precondition": "ABSENT_OR_EXACT_SCHEMA_VERSION",
        "final_ledger": [{"revision": revision, "version": SCHEMA_VERSION}],
    }))


@dataclass(frozen=True)
class ProductionMigrationAuthorizationEvidence:
    wire: bytes


@dataclass(frozen=True, init=False)
class VerifiedProductionMigrationAuthorization:
    evidence: ProductionMigrationAuthorizationEvidence
    plan_hash: str

    def __init__(self, *args, **kwargs):
        fail("VERIFIER_REQUIRED")


@dataclass(frozen=True)
class ProductionMigrationAuthorizationVerifier:
    """Mandatory policy pins installed by trusted composition, never a request.

    The final amendment checkpoint is deliberately not defaulted or invented.
    An evidence digest is an authority pin only after independent installation;
    self-chosen pins and matching type do not establish governance authority.
    """
    classification: str
    base_checkpoint: str
    amendment_checkpoint: str
    approved_plan_hash: str
    evidence_sha256: str

    def verify(self, evidence, plan):
        if type(evidence) is not ProductionMigrationAuthorizationEvidence or type(plan) is not PreparedMigrationPlan:
            fail("MALFORMED_EVIDENCE")
        body, prepared = _object(evidence.wire), _object(plan.wire)
        if not all(type(x) is str and re.fullmatch(r"[0-9a-f]{64}", x)
                   for x in (self.approved_plan_hash, self.evidence_sha256)):
            fail("POLICY_PIN_MISMATCH")
        if (prepared.get("classification") != self.classification
                or prepared.get("base_checkpoint") != self.base_checkpoint
                or prepared.get("amendment_checkpoint") != self.amendment_checkpoint):
            fail("LINEAGE_OR_CLASSIFICATION_MISMATCH")
        family = prepared.get("family")
        kind = {"B2_ACTIVATION_CONTROL": "control", "B2_ACTIVATION_CORE": "core"}.get(family)
        canonical = prepare_migration_plan(database=prepared.get("database"), kind=kind,
            classification=self.classification, environment=prepared.get("environment"),
            base_checkpoint=self.base_checkpoint, amendment_checkpoint=self.amendment_checkpoint)
        if canonical.wire != plan.wire:
            fail("PLAN_MISMATCH")
        if plan.plan_hash != self.approved_plan_hash:
            fail("PLAN_PIN_MISMATCH")
        expected = {"policy_id": POLICY_ID, "classification": self.classification,
                    "base_checkpoint": self.base_checkpoint, "amendment_checkpoint": self.amendment_checkpoint,
                    "plan_hash": plan.plan_hash}
        if body != expected or sha(evidence.wire) != self.evidence_sha256:
            fail("EVIDENCE_PIN_MISMATCH")
        capability = object.__new__(VerifiedProductionMigrationAuthorization)
        object.__setattr__(capability, "evidence", evidence)
        object.__setattr__(capability, "plan_hash", plan.plan_hash)
        return capability

    def revalidate(self, capability, plan):
        if type(capability) is not VerifiedProductionMigrationAuthorization:
            raise CoreError("B2_REAL_MIGRATION_NOT_ENABLED")
        fresh = self.verify(getattr(capability, "evidence", None), plan)
        if getattr(capability, "plan_hash", None) != fresh.plan_hash:
            fail("CAPABILITY_PLAN_MISMATCH")


@dataclass(frozen=True)
class ProtectedMigrationTarget:
    """Engine and policy fixed at trusted composition, not execution arguments.

    Classification identifies that composition's runtime boundary. Synthetic
    production-shaped names do not convert a connection to production. The
    existing transaction still verifies current_database against the fixed DB.
    Actual production actor, credential and operational consent belong to ops.
    """
    engine: object
    database: str
    kind: str
    environment: str
    verifier: ProductionMigrationAuthorizationVerifier

    def prepared_plan(self):
        if type(self.verifier) is not ProductionMigrationAuthorizationVerifier:
            fail("PROTECTED_POLICY_REQUIRED")
        return prepare_migration_plan(database=self.database, kind=self.kind,
            classification=self.verifier.classification, environment=self.environment,
            base_checkpoint=self.verifier.base_checkpoint, amendment_checkpoint=self.verifier.amendment_checkpoint)

    def authorize_continuation(self, capability, *, database, kind):
        if database != self.database or kind != self.kind:
            fail("CURRENT_TARGET_OR_BUNDLE_MISMATCH")
        self.verifier.revalidate(capability, self.prepared_plan())
        return self.engine
