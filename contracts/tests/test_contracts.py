from datetime import datetime, timezone
import uuid

import pytest
from pydantic import ValidationError

from qingyu_contracts.evidence import (
    AttachmentAttemptEvidence,
    EvidenceCapability,
    EvidenceErrorResponse,
    EvidenceRef,
    EvidenceVerification,
    ObservationPage,
)
from qingyu_contracts.identity import IdentityContinuityEnvelope


def u() -> uuid.UUID:
    return uuid.uuid4()


def now() -> datetime:
    return datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)


def observation_summary() -> dict:
    timestamp = now()
    return {
        "conversation_observation_id": u(),
        "import_batch_commit_id": u(),
        "conversation_id": u(),
        "source_account_id": u(),
        "archive_object_id": u(),
        "source_platform": "chatgpt",
        "parser_name": "chatgpt-export",
        "parser_contract_version": "real-export-evidence-v1",
        "committed_at": timestamp,
        "observed_at": timestamp,
        "observed_title": "historical title",
        "normalized_created_at": timestamp,
        "normalized_updated_at": None,
        "create_time_parse_status": "parsed",
        "update_time_parse_status": "absent",
        "current_conversation_node_id": None,
        "current_node_status": "absent",
        "source_observation_fingerprint": "a" * 64,
        "canonical_fragment_fingerprint": "b" * 64,
        "fragment_fingerprint_version": "1",
    }


def test_gateway_page_requires_frozen_semantics_and_bounds_limit() -> None:
    page = ObservationPage(
        items=[observation_summary()],
        next_cursor="opaque.signed.cursor",
        limit=50,
    )
    assert page.contract_version == "evidence-query-v1"
    assert page.meaning == "gateway_recorded_historical_evidence"
    assert page.consistency == "bounded_high_water_enumeration_v1"
    with pytest.raises(ValidationError):
        ObservationPage(items=[], next_cursor=None, limit=101)
    with pytest.raises(ValidationError):
        ObservationPage(items=[], next_cursor=None, limit=0)
    with pytest.raises(ValidationError):
        ObservationPage(
            items=[],
            next_cursor=None,
            limit=50,
            source_conversation_json={"must": "not leak"},
        )


def test_attachment_attempt_matches_gateway_allow_list() -> None:
    item = AttachmentAttemptEvidence(
        attachment_observation_id=u(),
        attempt_number=1,
        availability="missing",
        archive_object_id=None,
        observed_filename="photo.png",
        observed_media_type="image/png",
        observed_size_bytes=None,
        resolution_status="missing",
        canonical_fragment_fingerprint=None,
        fragment_fingerprint_version=None,
        observed_at=now(),
    )
    assert item.model_dump()["attempt_number"] == 1
    with pytest.raises(ValidationError):
        AttachmentAttemptEvidence(
            attachment_observation_id=u(),
            attempt_number=0,
            availability="missing",
            archive_object_id=None,
            observed_filename=None,
            observed_media_type=None,
            observed_size_bytes=None,
            resolution_status=None,
            canonical_fragment_fingerprint=None,
            fragment_fingerprint_version=None,
            observed_at=now(),
        )


def verification(**overrides) -> dict:
    value = {
        "mode": "FINGERPRINT_AND_SCOPE",
        "source_observation_fingerprint": "a" * 64,
        "canonical_fragment_fingerprint": "b" * 64,
        "fragment_fingerprint_version": "1",
        "observed_at": now(),
    }
    value.update(overrides)
    return value


def test_evidence_ref_is_closed_and_observation_scoped() -> None:
    conversation_id = u()
    ref = EvidenceRef(
        object_type="CONVERSATION_OBSERVATION",
        locator={"conversation_observation_id": conversation_id},
        verification=verification(),
    )
    assert ref.locator.conversation_observation_id == conversation_id
    assert "object_id" not in ref.model_dump()
    with pytest.raises(ValidationError):
        EvidenceRef(
            object_type="CONVERSATION_OBSERVATION",
            locator={
                "conversation_observation_id": conversation_id,
                "mapping_node_observation_id": u(),
            },
            verification=verification(),
        )
    with pytest.raises(ValidationError):
        EvidenceRef(
            object_type="MESSAGE_REVISION",
            locator={
                "conversation_observation_id": u(),
                "mapping_node_observation_id": u(),
                "message_revision_id": u(),
            },
            verification=verification(),
        )


def test_each_v1_ref_has_the_verification_material_required_by_frozen_profile() -> None:
    base = {
        "conversation_observation_id": u(),
        "mapping_node_observation_id": u(),
        "message_revision_id": u(),
    }
    message = EvidenceRef(
        object_type="MESSAGE_REVISION",
        locator=base,
        verification=verification(
            source_observation_fingerprint=None,
            canonical_fragment_fingerprint=None,
            semantic_revision_fingerprint="c" * 64,
            revision_fingerprint="d" * 64,
            fingerprint_version="1",
            fragment_fingerprint_version=None,
        ),
    )
    assert message.object_type == "MESSAGE_REVISION"

    attachment_id = u()
    attempt_id = u()
    identity_only = EvidenceRef(
        object_type="ATTACHMENT_OBSERVATION",
        locator={
            "conversation_observation_id": u(),
            "attachment_id": attachment_id,
            "attachment_observation_id": attempt_id,
        },
        verification={
            "mode": "IDENTITY_AND_SCOPE",
            "expected_fields": {
                "attempt_number": 1,
                "availability": "missing",
                "observed_at": now().isoformat(),
            },
        },
    )
    assert identity_only.verification.mode == "IDENTITY_AND_SCOPE"
    with pytest.raises(ValidationError):
        EvidenceVerification(
            mode="IDENTITY_AND_SCOPE",
            expected_fields=None,
        )


def test_core_ids_are_opaque_uuid4_and_alias_is_not_identity() -> None:
    envelope = IdentityContinuityEnvelope(
        qingyu_identity_id=u(),
        continuity_id=u(),
        continuity_alias="qingyu-main",
        continuity_epoch=0,
        state_version=0,
    )
    assert envelope.continuity_alias == "qingyu-main"
    with pytest.raises(ValidationError):
        IdentityContinuityEnvelope(
            qingyu_identity_id=uuid.uuid1(),
            continuity_id=u(),
            continuity_alias="qingyu-main",
        )
    with pytest.raises(ValidationError):
        IdentityContinuityEnvelope(
            qingyu_identity_id=u(),
            continuity_id=u(),
            continuity_alias=str(u()),
        )
    with pytest.raises(ValidationError):
        IdentityContinuityEnvelope(
            qingyu_identity_id=u(),
            continuity_id=u(),
            continuity_alias="",
        )


def test_error_and_capability_contracts_are_explicit() -> None:
    error = EvidenceErrorResponse(
        detail={"code": "evidence_integrity_violation", "request_id": "abc123"}
    )
    assert error.detail.code == "evidence_integrity_violation"
    assert EvidenceCapability().allowed_methods == ("GET",)
    assert EvidenceCapability().read_only is True
    with pytest.raises(ValidationError):
        EvidenceErrorResponse(detail={"code": "secret_internal_error"})
