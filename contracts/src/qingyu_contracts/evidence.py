from datetime import datetime
from enum import Enum
from typing import Literal
import uuid

from pydantic import Field, JsonValue, model_validator

from .common import ContractModel, Fingerprint, OpaqueCursor


EvidenceContractVersion = Literal["evidence-query-v1"]
EvidenceMeaning = Literal["gateway_recorded_historical_evidence"]
EvidenceConsistency = Literal["bounded_high_water_enumeration_v1"]


class ConversationObservationSummary(ContractModel):
    conversation_observation_id: uuid.UUID
    import_batch_commit_id: uuid.UUID
    conversation_id: uuid.UUID
    source_account_id: uuid.UUID
    archive_object_id: uuid.UUID
    source_platform: str
    parser_name: str
    parser_contract_version: str
    committed_at: datetime
    observed_at: datetime
    observed_title: str | None
    normalized_created_at: datetime | None
    normalized_updated_at: datetime | None
    create_time_parse_status: str
    update_time_parse_status: str
    current_conversation_node_id: uuid.UUID | None
    current_node_status: str
    source_observation_fingerprint: str
    canonical_fragment_fingerprint: str
    fragment_fingerprint_version: str


class AttachmentAttemptEvidence(ContractModel):
    attachment_observation_id: uuid.UUID
    attempt_number: int = Field(ge=1)
    availability: str
    archive_object_id: uuid.UUID | None
    observed_filename: str | None
    observed_media_type: str | None
    observed_size_bytes: int | None
    resolution_status: str | None
    canonical_fragment_fingerprint: str | None
    fragment_fingerprint_version: str | None
    observed_at: datetime


class AttachmentEvidence(ContractModel):
    attachment_id: uuid.UUID
    filename: str | None
    media_type: str | None
    size_bytes: int | None


class MessageRevisionEvidence(ContractModel):
    message_id: uuid.UUID
    message_revision_id: uuid.UUID
    revision_no: int = Field(ge=1)
    role: str
    content_text: str | None
    content_json: JsonValue | None
    content_type: str | None
    model: str | None
    raw_timestamp: str | None
    normalized_timestamp: datetime | None
    normalized_update_timestamp: datetime | None
    create_time_parse_status: str | None
    update_time_parse_status: str | None
    semantic_revision_fingerprint: str | None
    fingerprint_version: str | None
    revision_fingerprint: str | None
    message_observation_id: uuid.UUID | None
    source_observation_fingerprint: str | None
    canonical_fragment_fingerprint: str | None
    fragment_fingerprint_version: str | None
    attachments: list[AttachmentEvidence]


class NodeEvidence(ContractModel):
    mapping_node_observation_id: uuid.UUID
    conversation_node_id: uuid.UUID
    parent_conversation_node_id: uuid.UUID | None
    declared_child_conversation_node_ids: list[uuid.UUID] | None
    message_presence: Literal["absent", "null", "object"]
    observation_order: int = Field(ge=0)
    source_observation_fingerprint: str
    canonical_fragment_fingerprint: str
    fragment_fingerprint_version: str
    message: MessageRevisionEvidence | None


class ObservationPage(ContractModel):
    contract_version: EvidenceContractVersion = "evidence-query-v1"
    meaning: EvidenceMeaning = "gateway_recorded_historical_evidence"
    consistency: EvidenceConsistency = "bounded_high_water_enumeration_v1"
    items: list[ConversationObservationSummary]
    next_cursor: OpaqueCursor | None
    limit: int = Field(ge=1, le=100)


class NodePage(ContractModel):
    contract_version: EvidenceContractVersion = "evidence-query-v1"
    meaning: EvidenceMeaning = "gateway_recorded_historical_evidence"
    consistency: EvidenceConsistency = "bounded_high_water_enumeration_v1"
    observation: ConversationObservationSummary
    items: list[NodeEvidence]
    next_cursor: OpaqueCursor | None
    limit: int = Field(ge=1, le=100)


class AttachmentObservationPage(ContractModel):
    contract_version: EvidenceContractVersion = "evidence-query-v1"
    meaning: EvidenceMeaning = "gateway_recorded_historical_evidence"
    consistency: EvidenceConsistency = "bounded_high_water_enumeration_v1"
    attachment: AttachmentEvidence
    items: list[AttachmentAttemptEvidence]
    next_cursor: OpaqueCursor | None
    limit: int = Field(ge=1, le=100)


class EvidenceLocator(ContractModel):
    """Closed v1 locator profile; there is intentionally no generic object_id."""

    conversation_observation_id: uuid.UUID | None = None
    mapping_node_observation_id: uuid.UUID | None = None
    message_revision_id: uuid.UUID | None = None
    attachment_id: uuid.UUID | None = None
    attachment_observation_id: uuid.UUID | None = None


class EvidenceVerification(ContractModel):
    """Material used to verify a scoped ref after API re-resolution."""

    mode: Literal["FINGERPRINT_AND_SCOPE", "IDENTITY_AND_SCOPE"]
    source_observation_fingerprint: Fingerprint | None = None
    canonical_fragment_fingerprint: Fingerprint | None = None
    semantic_revision_fingerprint: Fingerprint | None = None
    revision_fingerprint: Fingerprint | None = None
    fingerprint_version: str | None = None
    fragment_fingerprint_version: str | None = None
    observed_at: datetime | None = None
    expected_fields: dict[str, JsonValue] | None = None

    @model_validator(mode="after")
    def validate_material(self) -> "EvidenceVerification":
        fingerprints = (
            self.source_observation_fingerprint,
            self.canonical_fragment_fingerprint,
            self.semantic_revision_fingerprint,
            self.revision_fingerprint,
        )
        if self.mode == "IDENTITY_AND_SCOPE":
            if any(fingerprints):
                raise ValueError("identity-and-scope verification cannot carry fingerprints")
            if not self.expected_fields:
                raise ValueError("identity-and-scope verification requires expected_fields")
        elif not any(fingerprints):
            raise ValueError("fingerprint-and-scope verification requires a fingerprint")
        if any(fingerprints) and not self.observed_at:
            raise ValueError("fingerprint verification requires observed_at")
        return self


class EvidenceRef(ContractModel):
    """A durable Gateway ref that can be re-resolved through Amendment #1."""

    layer: Literal["GATEWAY"] = "GATEWAY"
    object_type: Literal[
        "CONVERSATION_OBSERVATION",
        "MAPPING_NODE_OBSERVATION",
        "MESSAGE_REVISION",
        "ATTACHMENT_OBSERVATION",
    ]
    locator: EvidenceLocator
    verification: EvidenceVerification

    @model_validator(mode="after")
    def validate_scoped_locator(self) -> "EvidenceRef":
        expected = {
            "CONVERSATION_OBSERVATION": {
                "conversation_observation_id",
            },
            "MAPPING_NODE_OBSERVATION": {
                "conversation_observation_id",
                "mapping_node_observation_id",
            },
            "MESSAGE_REVISION": {
                "conversation_observation_id",
                "mapping_node_observation_id",
                "message_revision_id",
            },
            "ATTACHMENT_OBSERVATION": {
                "conversation_observation_id",
                "attachment_id",
                "attachment_observation_id",
            },
        }[self.object_type]
        actual = {
            name
            for name, value in self.locator.model_dump().items()
            if value is not None
        }
        if actual != expected:
            raise ValueError(
                f"{self.object_type} locator must contain exactly "
                f"{sorted(expected)}"
            )

        verification = self.verification
        if self.object_type in {
            "CONVERSATION_OBSERVATION",
            "MAPPING_NODE_OBSERVATION",
        }:
            if not (
                verification.source_observation_fingerprint
                and verification.canonical_fragment_fingerprint
                and verification.fragment_fingerprint_version
            ):
                raise ValueError(
                    "observation/node refs require source and canonical fingerprints"
                )
        elif self.object_type == "MESSAGE_REVISION":
            if not (
                verification.revision_fingerprint
                and verification.semantic_revision_fingerprint
                and verification.fingerprint_version
            ):
                raise ValueError(
                    "message refs require revision and semantic fingerprints"
                )
        elif self.object_type == "ATTACHMENT_OBSERVATION":
            if verification.mode == "FINGERPRINT_AND_SCOPE":
                if not (
                    verification.canonical_fragment_fingerprint
                    and verification.fragment_fingerprint_version
                ):
                    raise ValueError(
                        "fingerprinted attachment refs require canonical fingerprint"
                    )
            elif verification.mode != "IDENTITY_AND_SCOPE":
                raise ValueError("unsupported attachment verification mode")
        return self


class EvidenceErrorCode(str, Enum):
    """Stable error-code namespace; use the literal values in JSON responses."""

    EVIDENCE_CURSOR_INVALID = "evidence_cursor_invalid"
    AUTHENTICATION_REQUIRED = "authentication_required"
    EVIDENCE_OBSERVATION_NOT_FOUND = "evidence_observation_not_found"
    EVIDENCE_ATTACHMENT_NOT_FOUND = "evidence_attachment_not_found"
    DATABASE_OPERATION_FAILED = "database_operation_failed"
    EVIDENCE_INTEGRITY_VIOLATION = "evidence_integrity_violation"
    EVIDENCE_OPERATION_FAILED = "evidence_operation_failed"


class EvidenceErrorDetail(ContractModel):
    code: Literal[
        "evidence_cursor_invalid",
        "authentication_required",
        "evidence_observation_not_found",
        "evidence_attachment_not_found",
        "database_operation_failed",
        "evidence_integrity_violation",
        "evidence_operation_failed",
    ]
    request_id: str | None = None


class EvidenceErrorResponse(ContractModel):
    detail: EvidenceErrorDetail


class EvidenceCapability(ContractModel):
    """Logical auth contract for the Gateway Evidence read boundary."""

    capability: Literal["gateway.evidence.read"] = "gateway.evidence.read"
    credential_scheme: Literal["Bearer"] = "Bearer"
    route_prefix: Literal["/api/v1/evidence"] = "/api/v1/evidence"
    allowed_methods: tuple[Literal["GET"], ...] = ("GET",)
    read_only: Literal[True] = True
    cache_control: Literal["private, no-store"] = "private, no-store"
    cursor_signing_key_is_bearer: Literal[False] = False
