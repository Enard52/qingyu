from copy import deepcopy
from dataclasses import FrozenInstanceError

import pytest

from app.control_plane.r1_commands import (
    AbortAuthorization, AuthenticatedCaller, CommitAuthorization, MutationIntent,
)
from app.control_plane.r1_protocol import ProtocolError, canonical_bytes, sha256_hex
from r1_f3_helpers import authorization_value, mutation_envelope, uid


def test_intent_deeply_freezes_both_outcomes_and_original_request():
    envelope = mutation_envelope()
    intent = MutationIntent.from_envelope(envelope)
    original = intent.request_wire
    envelope["payload"]["staged_result"]["value"]["nested"].append("changed")
    intent.payload["abort_result"]["core_audit_candidate_hash"] = "f" * 64
    assert intent.request_wire == original
    assert intent.result_payload("COMMITTED")["state_version"] == 2
    assert intent.result_payload("ABORTED")["state_version"] == 1
    assert intent.result_hash("ABORTED") == intent.payload["abort_result_hash"]
    with pytest.raises(FrozenInstanceError):
        intent.request_wire = b"{}"


@pytest.mark.parametrize("change", [
    lambda e: e.update(operation_type="OWNER_TRANSFER"),
    lambda e: e["payload"].update(extra="unknown"),
    lambda e: e["payload"].update(payload_version=True),
    lambda e: e["payload"].update(lease_generation=0),
    lambda e: e["payload"].update(local_commit_id="not-uuid"),
    lambda e: e["payload"].update(staged_result_hash="f" * 64),
    lambda e: e["payload"]["staged_result"].update(state_version=7),
    lambda e: e["payload"]["abort_result"].update(state_version=2),
    lambda e: e["payload"].update(abort_result_hash="f" * 64),
    lambda e: e.update(expected_continuity_epoch=0),
    lambda e: e.update(expected_state_version=9007199254740991),
    lambda e: e["payload"]["staged_result"]["value"].update(nul="\x00"),
])
def test_invalid_or_mutated_intent_is_rejected_before_effects(change):
    envelope = mutation_envelope()
    change(envelope)
    with pytest.raises(ProtocolError):
        MutationIntent.from_envelope(envelope)


def test_command_requires_canonical_wire():
    intent = MutationIntent.from_envelope(mutation_envelope())
    with pytest.raises(ProtocolError):
        MutationIntent.from_wire(b" " + intent.request_wire)


def test_authenticated_scope_cannot_be_replaced_by_body():
    intent = MutationIntent.from_envelope(mutation_envelope())
    caller = AuthenticatedCaller(uid(1), uid(4), uid(5), uid(9), uid(6), "test-owner")
    caller.validate_for(intent)
    with pytest.raises(ProtocolError):
        AuthenticatedCaller(uid(1), uid(4), uid(5), uid(99), uid(6), "test-owner").validate_for(intent)
    with pytest.raises(ProtocolError):
        AuthenticatedCaller(uid(1), uid(4), uid(5), uid(9), uid(6), "forged-owner").validate_for(intent)


@pytest.mark.parametrize("decision,kind", [("COMMIT", CommitAuthorization), ("ABORT", AbortAuthorization)])
def test_attestation_freezes_exact_intent_and_local_commit_evidence(decision, kind):
    intent = MutationIntent.from_envelope(mutation_envelope())
    value = authorization_value(intent, decision)
    authorization = kind.from_mapping(value)
    authorization.validate_for(intent)
    value["local_commit_id"] = uid(123)
    with pytest.raises(ProtocolError):
        kind.from_mapping(value).validate_for(intent)
    value = authorization_value(intent, decision)
    value["unapproved_field"] = True
    with pytest.raises(ProtocolError):
        kind.from_mapping(value)


def test_abort_never_inferred_from_timeout_or_absent_evidence():
    intent = MutationIntent.from_envelope(mutation_envelope())
    value = authorization_value(intent, "ABORT")
    for invalid in (False, None, "true", 1):
        value["no_local_business_commit"] = invalid
        with pytest.raises(ProtocolError):
            AbortAuthorization.from_mapping(value)


def test_audit_candidates_cannot_be_substituted_after_request_freeze():
    intent = MutationIntent.from_envelope(mutation_envelope())
    altered = deepcopy(intent.envelope)
    altered["payload"]["abort_result"]["core_audit_candidate_hash"] = "f" * 64
    altered["payload"]["abort_result_hash"] = sha256_hex(canonical_bytes(altered["payload"]["abort_result"]))
    other = MutationIntent.from_envelope(altered)
    assert other.request_hash != intent.request_hash
    with pytest.raises(ProtocolError):
        CommitAuthorization.from_mapping(authorization_value(intent)).validate_for(other)
