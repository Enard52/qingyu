"""Fail-closed authenticated HTTPS client for the R1 Authority protocol.

The R1 frozen proposal requires the Authority Service to implement these same
version-1 shapes: POST /v1/operations with canonical request bytes and
GET /v1/operations/{operation_id}, each returning the direct signed PrepareAck
or terminal receipt as canonical JSON with HTTP 200. No HTTP status alone is a
governance result. F3 commit/abort extensions use the strict r1_commands v1
authorization envelopes through the same pinned transport.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import http.client
import math
import ssl
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from .r1_protocol import (
    AuthorityPin,
    ExpectedIntent,
    ProtocolError,
    canonical_bytes,
    decode_canonical_wire,
    request_envelope_hash,
    verify_prepare_ack,
    verify_terminal_receipt,
)


class AuthorityUnavailable(RuntimeError):
    """Authority could not provide a verified answer; writes remain closed."""


class AuthorityTransportUncertain(AuthorityUnavailable):
    """No trustworthy response to a sent request; same-ID query is required."""


class ReconciliationRequired(AuthorityUnavailable):
    """A request may have committed; only same-ID reconciliation is safe."""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Every connection must pass the pin before HTTPConnection can send."""

    def __init__(self, host: str, port: int | None, *, context: ssl.SSLContext,
                 timeout: float, fingerprint: str):
        super().__init__(host, port, context=context, timeout=timeout)
        self._fingerprint = fingerprint

    def connect(self) -> None:
        try:
            # Completes the TLS handshake, including CA and hostname validation.
            # Overriding connect also gates HTTPConnection's automatic open path.
            super().connect()
            if not isinstance(self.sock, ssl.SSLSocket) or self.sock.version() != "TLSv1.3":
                raise AuthorityUnavailable("Authority TLS peer identity unavailable")
            der_cert = self.sock.getpeercert(binary_form=True)
            if not isinstance(der_cert, bytes) or not der_cert:
                raise AuthorityUnavailable("Authority TLS peer identity unavailable")
            certificate = x509.load_der_x509_certificate(der_cert)
            spki = certificate.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if not hmac.compare_digest(hashlib.sha256(spki).hexdigest(), self._fingerprint):
                raise AuthorityUnavailable("Authority TLS peer pin mismatch")
        except AuthorityUnavailable:
            self.close()
            raise
        except (OSError, http.client.HTTPException, ValueError, TypeError):
            self.close()
            raise AuthorityUnavailable("Authority TLS connection unavailable") from None


@dataclass(frozen=True, slots=True)
class ChainCursor:
    """Locally verified next terminal position; not Authority-supplied input."""

    next_sequence: int
    previous_receipt_hash: str


@dataclass(frozen=True, slots=True)
class OperationAttempt:
    """Persisted request/INTENT projection with stable canonical retry bytes."""

    envelope: Mapping[str, Any]
    expected_intent: ExpectedIntent
    request_bytes: bytes
    operation_id: str

    @classmethod
    def from_durable_intent(cls, envelope: Mapping[str, Any],
                            expected_intent: ExpectedIntent) -> "OperationAttempt":
        expected_intent.validate(envelope)
        # Freeze nested payloads as bytes before network I/O. This is not a
        # substitute for the caller's durable INTENT transaction.
        frozen = canonical_bytes(envelope)
        parsed = decode_canonical_wire(frozen)
        return cls(parsed, expected_intent, frozen, parsed["operation_id"])

    def validate(self) -> None:
        if not isinstance(self.request_bytes, bytes):
            raise ProtocolError("attempt request bytes missing")
        parsed = decode_canonical_wire(self.request_bytes)
        if (parsed != self.envelope or parsed["operation_id"] != self.operation_id
                or request_envelope_hash(parsed) != self.expected_intent.request_envelope_hash):
            raise ProtocolError("operation attempt differs from durable INTENT")
        self.expected_intent.validate(parsed)


@dataclass(frozen=True, slots=True)
class VerifiedPhase:
    state: str
    message: Mapping[str, Any]
    terminal_receipt_hash: str | None = None


class AuthorityClient:
    """R1 client; never receives a PostgreSQL connection or a signer key."""

    def __init__(self, *, pin: AuthorityPin, ca_file: str,
                 credential_provider: Callable[[], str], timeout_seconds: float = 5.0):
        pin.validate()
        if pin.api_version != 1 or not ca_file or not callable(credential_provider):
            raise ProtocolError("invalid Authority client configuration")
        if (isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float))
                or not math.isfinite(timeout_seconds) or timeout_seconds <= 0):
            raise ProtocolError("invalid Authority timeout")
        context = ssl.create_default_context(cafile=ca_file)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["http/1.1"])
        self._pin = pin
        self._credential_provider = credential_provider
        self._context = context
        origin = urlsplit(pin.https_origin)
        self._host = origin.hostname
        self._port = origin.port
        self._timeout = timeout_seconds
        self._closed = False

    def close(self) -> None:
        self._closed = True

    def __enter__(self) -> "AuthorityClient":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def _headers(self) -> dict[str, str]:
        try:
            token = self._credential_provider()
        except Exception:
            raise AuthorityUnavailable("Authority credential unavailable") from None
        if (not isinstance(token, str) or not token
                or any(ord(ch) < 33 or ord(ch) > 126 for ch in token)):
            raise AuthorityUnavailable("Authority credential invalid")
        return {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                "Accept": "application/json", "Connection": "close"}

    def _request(self, method: str, path: str, *, body: bytes | None = None) -> Mapping[str, Any]:
        if self._closed:
            raise AuthorityUnavailable("Authority client is closed")
        # A fresh, directly connected socket for each request: no environment
        # proxies, redirect following, pooling, or unverified keep-alive reuse.
        connection = _PinnedHTTPSConnection(
            self._host, self._port, context=self._context, timeout=self._timeout,
            fingerprint=self._pin.server_spki_sha256,
        )
        try:
            connection.connect()
            headers = self._headers()  # Credentials are acquired only after pinning.
            connection.request(method, path, body=body, headers=headers)
            with connection.getresponse() as response:
                if response.status != 200:
                    raise AuthorityUnavailable("Authority returned no verified operation state")
                media_type = response.getheader("Content-Type", "").split(";", 1)[0].lower()
                if media_type != "application/json":
                    raise ProtocolError("invalid Authority response media type")
                content = response.read(1_000_001)
                if len(content) <= 1_000_000 and response.length not in (None, 0):
                    # read(amt) can return early EOF without IncompleteRead for
                    # Content-Length framing. Never accept a truncated response.
                    raise AuthorityTransportUncertain("Authority request outcome uncertain")
        except (OSError, http.client.HTTPException):
            raise AuthorityTransportUncertain("Authority request outcome uncertain") from None
        finally:
            connection.close()
        if len(content) > 1_000_000:
            raise ProtocolError("Authority response exceeds protocol limit")
        value = decode_canonical_wire(content)
        if not isinstance(value, Mapping):
            raise ProtocolError("invalid Authority response object")
        return value

    def _verify_phase(self, value: Mapping[str, Any], attempt: OperationAttempt,
                      cursor: ChainCursor) -> VerifiedPhase:
        if value.get("state") == "PREPARED":
            verify_prepare_ack(value, attempt.envelope, self._pin, attempt.expected_intent)
            return VerifiedPhase("PREPARED", value)
        if value.get("result_state") in ("COMMITTED", "ABORTED"):
            digest = verify_terminal_receipt(
                value, attempt.envelope, self._pin, attempt.expected_intent,
                expected_sequence=cursor.next_sequence,
                expected_previous_hash=cursor.previous_receipt_hash,
            )
            return VerifiedPhase(value["result_state"], value, digest)
        raise ProtocolError("unknown Authority operation phase")

    def query(self, attempt: OperationAttempt, *, cursor: ChainCursor) -> VerifiedPhase:
        attempt.validate()
        # The operation ID was validated as a canonical UUID by the envelope
        # validator, so it is safe as one encoded URL path segment.
        value = self._request("GET", f"/v1/operations/{attempt.operation_id}")
        return self._verify_phase(value, attempt, cursor)

    def prepare(self, attempt: OperationAttempt, *, cursor: ChainCursor) -> VerifiedPhase:
        """On any unverified POST result, query same ID or require reconciliation."""
        attempt.validate()
        try:
            value = self._request("POST", "/v1/operations", body=attempt.request_bytes)
            return self._verify_phase(value, attempt, cursor)
        except (AuthorityUnavailable, ProtocolError):
            # A non-200 response, malformed body, failed peer check, or socket
            # error can all occur *after* the Authority committed. None proves
            # ABORTED or authorizes a new operation ID.
            try:
                return self.query(attempt, cursor=cursor)
            except (AuthorityUnavailable, ProtocolError):
                raise ReconciliationRequired("Authority outcome uncertain; query same operation ID") from None

    def _decide(self, attempt: OperationAttempt, authorization, *, cursor: ChainCursor) -> VerifiedPhase:
        from .r1_commands import AbortAuthorization, CommitAuthorization, MutationIntent
        attempt.validate()
        if not isinstance(authorization, (CommitAuthorization, AbortAuthorization)):
            raise ProtocolError("explicit versioned operation authorization required")
        authorization.validate_for(MutationIntent.from_wire(attempt.request_bytes))
        path = f"/v1/operations/{attempt.operation_id}/{authorization.decision.lower()}"
        try:
            return self._verify_phase(self._request("POST", path, body=authorization.wire), attempt, cursor)
        except (AuthorityUnavailable, ProtocolError):
            try:
                return self.query(attempt, cursor=cursor)
            except (AuthorityUnavailable, ProtocolError):
                raise ReconciliationRequired("Authority outcome uncertain; query same operation ID") from None

    def commit(self, attempt: OperationAttempt, authorization, *, cursor: ChainCursor) -> VerifiedPhase:
        from .r1_commands import CommitAuthorization
        if not isinstance(authorization, CommitAuthorization):
            raise ProtocolError("commit authorization required")
        return self._decide(attempt, authorization, cursor=cursor)

    def abort(self, attempt: OperationAttempt, authorization, *, cursor: ChainCursor) -> VerifiedPhase:
        from .r1_commands import AbortAuthorization
        if not isinstance(authorization, AbortAuthorization):
            raise ProtocolError("abort authorization required")
        return self._decide(attempt, authorization, cursor=cursor)
