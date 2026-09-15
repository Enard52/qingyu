from __future__ import annotations

from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import certifi
import httpx
import pytest

from app.control_plane import r1_client
from app.control_plane.r1_client import (
    AuthorityClient, AuthorityUnavailable, ChainCursor, OperationAttempt,
    ReconciliationRequired,
)
from app.control_plane.r1_protocol import (
    AuthorityPin, ExpectedIntent, ProtocolError, canonical_bytes,
    genesis_head_seed, key_id, request_envelope_hash, sign_prepare_ack,
    sign_terminal_receipt,
)


def u(number: int) -> str:
    return str(UUID(int=number))


@pytest.fixture
def setup(monkeypatch):
    signer = Ed25519PrivateKey.generate()
    pin = AuthorityPin(u(1), u(2), 1, signer.public_key(), key_id(signer.public_key()),
                       1, "https://authority.example", "e" * 64, "a" * 64)
    envelope = {
        "schema_version": 1, "authority_domain_id": u(1),
        "authority_instance_id": u(2), "authority_generation": 1,
        "qingyu_identity_id": u(3), "continuity_id": u(4),
        "operation_id": u(5), "operation_type": "AUTHORITY_GENESIS_ACTIVATION",
        "expected_continuity_epoch": 0, "expected_state_version": 0,
        "expected_owner_version": 0, "actor_or_owner_identity": "operator",
        "caller_runtime_id": u(6), "storage_generation_id": u(7),
        "payload": {"origin": "verified"}, "reason": "genesis",
    }
    intent = ExpectedIntent(request_envelope_hash(envelope), "b" * 64,
                            "c" * 64, "d" * 64)
    attempt = OperationAttempt.from_durable_intent(envelope, intent)
    seed = genesis_head_seed(
        authority_domain_id=pin.authority_domain_id,
        authority_instance_id=pin.authority_instance_id,
        provisioning_uuid=u(8), signed_provisioning_origin_digest="e" * 64,
        receipt_key_id=pin.receipt_key_id, operator_root_key_id=pin.operator_root_key_id,
    )
    cursor = ChainCursor(1, seed)
    ack = sign_prepare_ack({
        "ack_version": 1, **{name: envelope[name] for name in (
            "authority_domain_id", "authority_instance_id", "authority_generation",
            "qingyu_identity_id", "continuity_id", "operation_id", "operation_type",
            "caller_runtime_id", "storage_generation_id", "expected_continuity_epoch",
            "expected_owner_version", "expected_state_version")},
        "request_envelope_hash": intent.request_envelope_hash,
        "staged_result_hash": intent.staged_result_hash,
        "core_audit_predecessor_hash": intent.core_audit_predecessor_hash,
        "core_audit_candidate_hash": intent.core_audit_candidate_hash,
        "state": "PREPARED", "prepared_at": "2026-09-13T00:00:00Z",
    }, signer)
    receipt = sign_terminal_receipt({
        "receipt_version": 1, "schema_version": 1,
        **{name: envelope[name] for name in (
            "authority_domain_id", "authority_instance_id", "authority_generation",
            "qingyu_identity_id", "continuity_id", "operation_id", "operation_type",
            "actor_or_owner_identity", "storage_generation_id")},
        "request_envelope_hash": intent.request_envelope_hash,
        "result_state": "COMMITTED", "result_code": "ACTIVATED",
        "continuity_epoch": 1, "control_plane_generation_id": u(9),
        "owner_version": 1, "lease_generation": None, "authority_sequence": 1,
        "previous_receipt_hash": seed, "result_payload_hash": "f" * 64,
        "staged_result_hash": intent.staged_result_hash,
        "core_audit_predecessor_hash": intent.core_audit_predecessor_hash,
        "core_audit_candidate_hash": intent.core_audit_candidate_hash,
        "decided_at": "2026-09-13T00:00:01Z",
        "signed_provisioning_origin_digest": "e" * 64,
        "previous_generation": None, "previous_generation_sequence": None,
        "previous_generation_head_hash": None, "signed_dr_artifact_digest": None,
    }, signer)

    def make_client(handler):
        # These tests cover signed response/reconciliation logic. Real peer
        # validation, without fabricated TLS metadata, lives in the TLS suite.
        class FakeConnection:
            def __init__(self, host, port, *, context, timeout, fingerprint):
                assert host == "authority.example"
                assert context.check_hostname is True
                assert context.minimum_version.name == "TLSv1_3"
                assert fingerprint == pin.server_spki_sha256
                self.connected = False

            def connect(self):
                self.connected = True

            def request(self, method, path, *, body, headers):
                assert self.connected
                request = httpx.Request(method, pin.https_origin + path, content=body,
                                        headers=headers)
                try:
                    self.result = handler(request)
                except httpx.RequestError:
                    raise TimeoutError("synthetic transport failure") from None

            def getresponse(self):
                return self.result

            def close(self):
                self.connected = False

        monkeypatch.setattr(r1_client, "_PinnedHTTPSConnection", FakeConnection)
        return AuthorityClient(pin=pin, ca_file=certifi.where(),
                               credential_provider=lambda: "scoped-credential")

    def response(message, status=200, *, raw=None):
        class FakeResponse:
            def __init__(self):
                self.status = status
                self.length = 0

            def getheader(self, name, default):
                return "application/json" if name == "Content-Type" else default

            def read(self, size):
                data = canonical_bytes(message) if raw is None else raw
                return data[:size]

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                pass

        return FakeResponse()

    return pin, envelope, attempt, cursor, ack, receipt, make_client, response


def test_prepare_and_same_id_query_after_timeout(setup) -> None:
    pin, envelope, attempt, cursor, ack, receipt, make_client, response = setup
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["authorization"] == "Bearer scoped-credential"
        assert request.url.host == "authority.example"
        if request.method == "POST":
            assert request.url.path == "/v1/operations"
            assert request.content == attempt.request_bytes
            raise httpx.ReadTimeout("unknown result", request=request)
        assert request.url.path == f"/v1/operations/{attempt.operation_id}"
        return response(receipt)

    with make_client(handler) as client:
        phase = client.prepare(attempt, cursor=cursor)
    assert phase.state == "COMMITTED"
    assert phase.terminal_receipt_hash
    assert [r.method for r in requests] == ["POST", "GET"]
    assert attempt.operation_id == envelope["operation_id"]


def test_prepared_ack_and_identical_retry_bytes(setup) -> None:
    _, _, attempt, cursor, ack, _, make_client, response = setup
    bodies = []

    def handler(request):
        bodies.append(request.content)
        return response(ack)

    with make_client(handler) as client:
        assert client.prepare(attempt, cursor=cursor).state == "PREPARED"
        assert client.prepare(attempt, cursor=cursor).state == "PREPARED"
    assert bodies == [attempt.request_bytes, attempt.request_bytes]


def test_unknown_response_fails_closed(setup) -> None:
    _, _, attempt, cursor, ack, _, make_client, response = setup
    tampered = dict(ack, state="COMMITTED")
    for handler in (
        lambda request: response(tampered),
        lambda request: response({"state": "COMMITTED"}),
    ):
        with make_client(handler) as client, pytest.raises((ProtocolError, AuthorityUnavailable)):
            client.prepare(attempt, cursor=cursor)


def test_unknown_post_and_query_never_infers_abort(setup) -> None:
    _, _, attempt, cursor, _, _, make_client, response = setup

    def handler(request):
        if request.method == "POST":
            raise httpx.ReadTimeout("unknown", request=request)
        return response({"not": "an operation"}, status=404)

    with make_client(handler) as client, pytest.raises(ReconciliationRequired):
        client.prepare(attempt, cursor=cursor)


def test_non_200_after_processed_post_queries_same_operation(setup) -> None:
    _, _, attempt, cursor, _, receipt, make_client, response = setup
    seen = []

    def handler(request):
        seen.append((request.method, request.url.path))
        if request.method == "POST":
            return response({"error": "response lost"}, status=503)
        return response(receipt)

    with make_client(handler) as client:
        assert client.prepare(attempt, cursor=cursor).state == "COMMITTED"
    assert seen == [("POST", "/v1/operations"),
                    ("GET", f"/v1/operations/{attempt.operation_id}")]


def test_attempt_rejects_local_mutation(setup) -> None:
    _, _, attempt, cursor, ack, _, make_client, response = setup
    mutable = dict(attempt.envelope)
    mutable["payload"] = {"origin": "changed"}
    broken = OperationAttempt(mutable, attempt.expected_intent,
                              attempt.request_bytes, attempt.operation_id)
    with make_client(lambda request: response(ack)) as client, pytest.raises(ProtocolError):
        client.prepare(broken, cursor=cursor)
    unsafe = OperationAttempt(dict(attempt.envelope, operation_id="../other"),
                              attempt.expected_intent, attempt.request_bytes, "../other")
    with make_client(lambda request: response(ack)) as client, pytest.raises(ProtocolError):
        client.query(unsafe, cursor=cursor)


def test_noncanonical_response_reject(setup) -> None:
    _, _, attempt, cursor, ack, _, make_client, response = setup
    with make_client(lambda request: response(ack, raw=b" " + canonical_bytes(ack))) as client:
        with pytest.raises(ProtocolError):
            client.query(attempt, cursor=cursor)
