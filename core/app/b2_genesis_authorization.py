"""Request-specific Owner checkpoint capability, never a secret or CLI consent.

Verifier pins are a protected deployment composition dependency. They must be
installed from a separately Owner-authorized governance checkpoint, never from
execution request fields. No default production approval/pin exists. As in the
existing Owner checkpoint, commit and annotated tag anchor the approval hash.
Git hashes prove immutable content, not human authorship: the trusted pin
installation is the Owner provenance boundary. Python visibility is not one.
"""
from dataclasses import dataclass
from hashlib import sha1
import re

from .b2_activation_readiness import SignedMigrationIntent, activation_candidate_hash, validate_owner_approval
from .b2_activation_lifecycle import activation_hash
from .control_plane.r1_validation_codec import c2, decode, sha
from .errors import CoreError

FOUNDATION_CHECKPOINT = "a5508234d7a4c605815d8dea8b52e9edfa5ac02a"
PRODUCTION = "PRODUCTION"
NON_PRODUCTION = "NON_PRODUCTION"
DECISIONS = {PRODUCTION: "APPROVE_REAL_V2_NEW_GENESIS", NON_PRODUCTION: "APPROVE_SYNTHETIC_V2_NEW_GENESIS"}
FIELDS = frozenset(("schema_version", "classification", "decision", "foundation_checkpoint",
    "activation_request_hash", "authority_reference", "authority_hash", "intent_id", "smi_hash",
    "genesis_request_hash", "target_database", "environment", "adapter", "provenance"))


def fail(code):
    raise CoreError("GENESIS_AUTHORIZATION_" + code)


def git_object_id(kind, wire):
    if type(wire) is not bytes:
        fail("MALFORMED_APPROVAL")
    return sha1(kind.encode("ascii") + b" " + str(len(wire)).encode("ascii") + b"\0" + wire).hexdigest()


@dataclass(frozen=True)
class GenesisAuthorizationEvidence:
    approval_wire: bytes
    checkpoint_commit_wire: bytes
    checkpoint_tag_wire: bytes


@dataclass(frozen=True)
class GenesisAuthorizationContext:
    wire: bytes


@dataclass(frozen=True, init=False)
class VerifiedGenesisAuthorization:
    evidence: GenesisAuthorizationEvidence
    context_hash: str

    def __init__(self, *args, **kwargs):
        fail("VERIFIER_REQUIRED")


@dataclass(frozen=True)
class GenesisAuthorizationVerifier:
    """Pinned immutable approval authority; only protected Core configuration.

    All pins are mandatory. A request cannot install/replace this verifier.
    Verification and continuation re-check Git objects, approval bytes and
    current durable lineage. Matching Python class identity alone grants nothing.
    """
    classification: str
    owner_checkpoint: str
    owner_tag_object: str
    approval_sha256: str
    foundation_checkpoint: str

    def __post_init__(self):
        if self.classification not in DECISIONS:
            fail("MALFORMED_APPROVAL")
        if not all(type(x) is str and re.fullmatch(r"[0-9a-f]{40}", x)
                   for x in (self.owner_checkpoint, self.owner_tag_object)):
            fail("OWNER_CHECKPOINT_MISMATCH")
        if type(self.approval_sha256) is not str or not re.fullmatch(r"[0-9a-f]{64}", self.approval_sha256):
            fail("MALFORMED_APPROVAL")
        if self.classification == PRODUCTION and self.foundation_checkpoint != FOUNDATION_CHECKPOINT:
            fail("FOUNDATION_CHECKPOINT_MISMATCH")
        if self.classification == NON_PRODUCTION and not self.foundation_checkpoint.startswith("NON_PRODUCTION:"):
            fail("FOUNDATION_CHECKPOINT_MISMATCH")

    def verify(self, evidence, context):
        if type(evidence) is not GenesisAuthorizationEvidence or type(context) is not GenesisAuthorizationContext:
            fail("MALFORMED_APPROVAL")
        if any(type(wire) is not bytes or len(wire) > 1_048_576 for wire in
               (evidence.approval_wire, evidence.checkpoint_commit_wire, evidence.checkpoint_tag_wire, context.wire)):
            fail("MALFORMED_APPROVAL")
        try:
            body = decode(evidence.approval_wire)
            expected = decode(context.wire)
            commit = evidence.checkpoint_commit_wire.decode("utf-8", errors="strict")
            tag = evidence.checkpoint_tag_wire.decode("utf-8", errors="strict")
        except (ValueError, TypeError, UnicodeError, KeyError):
            fail("MALFORMED_APPROVAL")
        if (type(body) is not dict or type(expected) is not dict or set(body) != FIELDS
                or set(expected) != FIELDS - {"schema_version", "decision", "provenance"}
                or body["schema_version"] != "qingyu-genesis-owner-authorization-v1"):
            fail("MALFORMED_APPROVAL")
        if body["decision"] != DECISIONS[self.classification]:
            fail("OWNER_DECISION_MISMATCH")
        if body["classification"] != self.classification or expected["classification"] != self.classification:
            fail("CLASSIFICATION_MISMATCH")
        if (git_object_id("commit", evidence.checkpoint_commit_wire) != self.owner_checkpoint
                or git_object_id("tag", evidence.checkpoint_tag_wire) != self.owner_tag_object):
            fail("OWNER_CHECKPOINT_MISMATCH")
        tag_header, separator, tag_message = tag.partition("\n\n")
        commit_header, commit_separator, commit_message = commit.partition("\n\n")
        if (not separator or not commit_separator or not commit_header.startswith("tree ")
                or tag_header.splitlines()[:2] != ["object " + self.owner_checkpoint, "type commit"]):
            fail("OWNER_CHECKPOINT_MISMATCH")
        anchor = "OWNER_GENESIS_APPROVAL_SHA256: " + self.approval_sha256
        if anchor not in tag_message.splitlines() or anchor not in commit_message.splitlines():
            fail("OWNER_CHECKPOINT_MISMATCH")
        if sha(evidence.approval_wire) != self.approval_sha256:
            fail("MALFORMED_APPROVAL")
        if body["foundation_checkpoint"] != self.foundation_checkpoint:
            fail("FOUNDATION_CHECKPOINT_MISMATCH")
        purposes = {"foundation_checkpoint": "FOUNDATION_CHECKPOINT", "activation_request_hash": "ACTIVATION_REQUEST",
            "authority_reference": "AUTHORITY", "authority_hash": "AUTHORITY", "intent_id": "SMI", "smi_hash": "SMI",
            "genesis_request_hash": "GENESIS_REQUEST", "target_database": "TARGET", "environment": "ENVIRONMENT", "adapter": "ADAPTER"}
        for field, code in purposes.items():
            if body[field] != expected[field]:
                fail(code + "_MISMATCH")
        provenance = body["provenance"]
        if (type(provenance) is not dict or set(provenance) != {"version", "authorization_reference", "authorization_sha256"}
                or provenance["version"] != "thread-owner-checkpoint-v1"
                or type(provenance["authorization_reference"]) is not str
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9:/_.-]{0,255}", provenance["authorization_reference"])
                or type(provenance["authorization_sha256"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", provenance["authorization_sha256"])):
            fail("MALFORMED_APPROVAL")
        if self.classification == PRODUCTION:
            if body["target_database"] != "qingyu_prod" or body["environment"] != PRODUCTION or body["adapter"] != "SCOPED_V2_POSTGRES":
                fail("TARGET_MISMATCH")
        elif body["target_database"] in {"qingyu_prod", "qingyu_control"} or body["environment"] == PRODUCTION:
            fail("TARGET_MISMATCH")
        capability = object.__new__(VerifiedGenesisAuthorization)
        object.__setattr__(capability, "evidence", evidence)
        object.__setattr__(capability, "context_hash", sha(context.wire))
        return capability

    def revalidate(self, capability, context):
        if type(capability) is not VerifiedGenesisAuthorization:
            fail("VERIFIED_CAPABILITY_REQUIRED")
        try:
            fresh = self.verify(capability.evidence, context)
            if fresh.context_hash != capability.context_hash:
                fail("GENESIS_REQUEST_MISMATCH")
        except AttributeError:
            fail("MALFORMED_APPROVAL")
        return fresh


def genesis_authorization_context(core, *, authority_reference, intent_id, opening, owner_approval):
    """Build from current durable records and original opening, never a caller map.

    The prepared-request identity IS the existing frozen GENESIS proof hash.
    Authorization metadata is not added to that proof or the durable root.
    """
    from .r1_scoped_activation_core import encode_opening, verify_opening
    from .b2_signer_trust import AuthorityEnvironmentMode
    verifier = core.genesis_authorization_verifier
    if type(verifier) is not GenesisAuthorizationVerifier:
        fail("PROTECTED_VERIFIER_REQUIRED")
    real = core.mode == AuthorityEnvironmentMode.REAL_PRODUCTION
    if verifier.classification != (PRODUCTION if real else NON_PRODUCTION):
        fail("CLASSIFICATION_MISMATCH")
    authority, smi = core.control.read_authority(authority_reference), core.control.read_smi(intent_id)
    if authority is None or smi is None or smi.payload["authority_hash"] != authority.record_hash:
        fail("AUTHORITY_MISMATCH")
    intent = SignedMigrationIntent.model_validate(smi.payload["intent"])
    validate_owner_approval(approval=owner_approval, target=core.control.target, intent=intent)
    verify_opening(opening, core.configuration)
    proof_wire = c2({"schema_version": authority.payload["schema_version"], "authority_wire": authority.wire.hex(),
                    "smi_wire": smi.wire.hex(), "opening_wire": encode_opening(opening).hex(),
                    "owner_approval": owner_approval.model_dump(mode="json")})
    return GenesisAuthorizationContext(c2({"classification": verifier.classification,
        "foundation_checkpoint": verifier.foundation_checkpoint,
        "activation_request_hash": activation_candidate_hash(target=core.control.target, intent=intent),
        "authority_reference": authority_reference, "authority_hash": authority.record_hash,
        "intent_id": intent_id, "smi_hash": smi.record_hash, "genesis_request_hash": activation_hash("genesis", proof_wire),
        "target_database": core.database, "environment": PRODUCTION if real else core.control.target.environment_identity,
        "adapter": core.route}))
