"""Real loopback TLS tests; all certificates/credentials are ephemeral test data."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import socket
import ssl
from threading import Event, Thread
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
import pytest

from app.control_plane.r1_client import (
    AuthorityClient, AuthorityTransportUncertain, AuthorityUnavailable,
)
from app.control_plane.r1_protocol import AuthorityPin, ProtocolError, key_id


TEST_TOKEN = "r1-isolated-tls-test-token"
TEST_BODY = b'{"test":"r1-isolated-body-marker"}'


def _certificate_material(directory, *, valid_hostname=True, issuer=None):
    """Use a fresh local test CA, unrelated to R1 provisioning trust material."""
    now = datetime.now(timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Ephemeral TLS Test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5))
          .not_valid_after(now + timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .sign(ca_key, hashes.SHA256()))
    if issuer is not None:
        ca, ca_key = issuer
        ca_name = ca.subject
    server_key = ec.generate_private_key(ec.SECP256R1())
    identity = (x509.IPAddress(ipaddress.ip_address("127.0.0.1")) if valid_hostname
                else x509.DNSName("wrong-host.invalid"))
    certificate = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                                                              "Ephemeral TLS Test Server")]))
                   .issuer_name(ca_name).public_key(server_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(now - timedelta(minutes=5))
                   .not_valid_after(now + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                   .add_extension(x509.SubjectAlternativeName([identity]), False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                       ca_key.public_key()), False)
                   .sign(ca_key, hashes.SHA256()))
    directory.mkdir()
    ca_file, cert_file, key_file = (directory / name for name in ("ca.pem", "server.pem", "server.key"))
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_file.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(server_key.private_bytes(serialization.Encoding.PEM,
                                                serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    spki = server_key.public_key().public_bytes(serialization.Encoding.DER,
                                              serialization.PublicFormat.SubjectPublicKeyInfo)
    return str(ca_file), str(cert_file), str(key_file), hashlib.sha256(spki).hexdigest(), ca, ca_key


@contextmanager
def _tls_server(material, *, response=None, maximum_version=None, next_material=None,
                hold_response_open=False):
    """Capture decrypted HTTP bytes at the server, including rejected connections."""
    _, cert_file, key_file, *_ = material
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if maximum_version is not None:
        context.minimum_version = maximum_version
        context.maximum_version = maximum_version
    context.load_cert_chain(cert_file, key_file)
    contexts = [context]
    if next_material is not None:
        next_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        next_context.minimum_version = ssl.TLSVersion.TLSv1_3
        next_context.load_cert_chain(next_material[1], next_material[2])
        contexts.append(next_context)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(2)
    listener.settimeout(3)
    port = listener.getsockname()[1]
    done = Event()
    observed = {"http": b"", "tls_version": None, "error": None, "connections": [],
                "handshake_captured": [Event() for _ in contexts]}
    if response is None:
        response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    b"Content-Length: 2\r\nConnection: keep-alive\r\n\r\n{}")

    def serve():
        try:
            for connection_index, current_context in enumerate(contexts):
                capture = {"http": b"", "tls_version": None}
                observed["connections"].append(capture)
                with listener.accept()[0] as raw:
                    raw.settimeout(3)
                    with current_context.wrap_socket(raw, server_side=True) as peer:
                        observed["tls_version"] = capture["tls_version"] = peer.version()
                        observed["handshake_captured"][connection_index].set()
                        while True:
                            block = peer.recv(65536)
                            if not block:
                                break
                            observed["http"] += block
                            capture["http"] += block
                            headers, separator, body = capture["http"].partition(b"\r\n\r\n")
                            if separator:
                                lengths = [line.partition(b":")[2].strip()
                                           for line in headers.split(b"\r\n")
                                           if line.lower().startswith(b"content-length:")]
                                expected = int(lengths[0]) if lengths else 0
                                if len(body) >= expected:
                                    peer.sendall(response)
                                    if hold_response_open:
                                        # Withhold the rest of the advertised response
                                        # until the client enforces its read cap and closes.
                                        assert peer.recv(1) == b""
                                    break
        except (OSError, ssl.SSLError) as error:
            observed["error"] = type(error).__name__
        finally:
            observed["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
            done.set()

    thread = Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield port, observed, done
    finally:
        listener.close()
        thread.join(timeout=4)
        assert not thread.is_alive(), "isolated TLS server did not finish"


def _pin(port, fingerprint):
    signing_key = Ed25519PrivateKey.generate().public_key()
    return AuthorityPin(str(UUID(int=1)), str(UUID(int=2)), 1, signing_key,
                        key_id(signing_key), 1, f"https://127.0.0.1:{port}",
                        fingerprint, "a" * 64)


def _await_server_handshake_capture(client, observed, monkeypatch):
    """Test-only scheduling seam, after the real validated TLS handshake.

    A rejecting client can close before the server's wrap_socket returns. Tests
    requiring an observed TLS version therefore wait for that exact server
    capture before returning the real socket to the unchanged pin/credential
    rejection path. Each reconnect has its own event; no synthetic TLS result,
    pin bypass, HTTP send, or credential access occurs in this wrapper.
    """
    wrap_socket = client._context.wrap_socket
    captures = iter(observed["handshake_captured"])

    def wrap_and_observe(*args, **kwargs):
        peer = wrap_socket(*args, **kwargs)
        try:
            captured = next(captures)
            assert captured.wait(2), "real server TLS handshake was not captured"
            return peer
        except BaseException:
            peer.close()
            raise

    monkeypatch.setattr(client._context, "wrap_socket", wrap_and_observe)


@pytest.mark.parametrize("case", ["correct_pin", "wrong_pin", "invalid_ca", "wrong_hostname"])
def test_real_tls_identity_gate_before_http(tmp_path, case):
    material = _certificate_material(tmp_path / "server", valid_hostname=case != "wrong_hostname")
    ca_file = material[0]
    if case == "invalid_ca":
        ca_file = _certificate_material(tmp_path / "unrelated-ca")[0]
    provider_calls = []

    def credentials():
        provider_calls.append("called")
        return TEST_TOKEN

    with _tls_server(material) as (port, observed, done):
        pin = _pin(port, material[3])
        if case == "wrong_pin":
            pin = replace(pin, server_spki_sha256="0" * 64)
        with AuthorityClient(pin=pin, ca_file=ca_file, credential_provider=credentials,
                             timeout_seconds=2) as client:
            if case == "correct_pin":
                assert client._request("POST", "/v1/operations", body=TEST_BODY) == {}
            else:
                with pytest.raises(AuthorityUnavailable):
                    client._request("POST", "/v1/operations", body=TEST_BODY)
        assert done.wait(3)
        # Printed only with pytest -s: exclusively synthetic test markers.
        print({"case": case, "observed_at_utc": observed["finished_at_utc"],
               "http_bytes": len(observed["http"]), "tls_version": observed["tls_version"],
               "test_token_received": TEST_TOKEN.encode() in observed["http"],
               "test_body_received": TEST_BODY in observed["http"],
               "credential_provider_calls": len(provider_calls)})
        if case == "correct_pin":
            assert observed["tls_version"] == "TLSv1.3"
            assert b"Authorization: Bearer " + TEST_TOKEN.encode() in observed["http"]
            assert observed["http"].endswith(TEST_BODY)
            assert provider_calls == ["called"]
        else:
            assert observed["http"] == b""
            assert provider_calls == []


def test_reconnect_rechecks_changed_peer_before_fetching_credentials(tmp_path, monkeypatch):
    first = _certificate_material(tmp_path / "first")
    second = _certificate_material(tmp_path / "second", issuer=first[4:])
    calls = []
    with _tls_server(first, next_material=second) as (port, observed, done):
        with AuthorityClient(pin=_pin(port, first[3]), ca_file=first[0],
                             credential_provider=lambda: calls.append(1) or TEST_TOKEN,
                             timeout_seconds=2) as client:
            _await_server_handshake_capture(client, observed, monkeypatch)
            assert client._request("POST", "/v1/operations", body=TEST_BODY) == {}
            with pytest.raises(AuthorityUnavailable, match="pin mismatch"):
                client._request("POST", "/v1/operations", body=TEST_BODY)
        assert done.wait(3)
    assert len(observed["connections"]) == 2
    assert observed["connections"][0]["http"].endswith(TEST_BODY)
    assert observed["connections"][1]["tls_version"] == "TLSv1.3"
    assert observed["connections"][1]["http"] == b""
    assert calls == [1]


def test_tls_12_is_rejected_before_http_or_credentials(tmp_path):
    material = _certificate_material(tmp_path / "server")
    calls = []
    with _tls_server(material, maximum_version=ssl.TLSVersion.TLSv1_2) as (port, observed, done):
        with AuthorityClient(pin=_pin(port, material[3]), ca_file=material[0],
                             credential_provider=lambda: calls.append(1) or TEST_TOKEN,
                             timeout_seconds=2) as client:
            with pytest.raises(AuthorityUnavailable):
                client._request("POST", "/v1/operations", body=TEST_BODY)
        assert done.wait(3)
    assert observed["http"] == b""
    assert calls == []


@pytest.mark.parametrize("credential", ["provider_exception", "invalid_control", "non_ascii"])
def test_credential_errors_are_sanitized_and_send_nothing(tmp_path, credential, monkeypatch):
    material = _certificate_material(tmp_path / "server")

    def provider():
        if credential == "provider_exception":
            raise RuntimeError(TEST_TOKEN)
        return TEST_TOKEN + ("\x00" if credential == "invalid_control" else "\u0100")

    with _tls_server(material) as (port, observed, done):
        with AuthorityClient(pin=_pin(port, material[3]), ca_file=material[0],
                             credential_provider=provider, timeout_seconds=2) as client:
            _await_server_handshake_capture(client, observed, monkeypatch)
            with pytest.raises(AuthorityUnavailable) as error:
                client._request("POST", "/v1/operations", body=TEST_BODY)
        assert done.wait(3)
    assert TEST_TOKEN not in str(error.value)
    assert observed["tls_version"] == "TLSv1.3"
    assert observed["http"] == b""


def test_environment_proxy_and_redirect_cannot_forward_credentials(tmp_path, monkeypatch):
    material = _certificate_material(tmp_path / "server")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as trap:
        trap.bind(("127.0.0.1", 0))
        trap.listen(2)
        trap.setblocking(False)
        trap_origin = f"http://127.0.0.1:{trap.getsockname()[1]}"
        for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                         "http_proxy", "https_proxy", "all_proxy"):
            monkeypatch.setenv(variable, trap_origin)
        monkeypatch.setenv("NO_PROXY", "")
        monkeypatch.setenv("no_proxy", "")
        monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "nonexistent-ca"))
        response = (f"HTTP/1.1 307 Temporary Redirect\r\nLocation: {trap_origin}/capture\r\n"
                    "Content-Length: 0\r\nConnection: close\r\n\r\n").encode("ascii")
        with _tls_server(material, response=response) as (port, observed, done):
            with AuthorityClient(pin=_pin(port, material[3]), ca_file=material[0],
                                 credential_provider=lambda: TEST_TOKEN, timeout_seconds=2) as client:
                with pytest.raises(AuthorityUnavailable):
                    client._request("POST", "/v1/operations", body=TEST_BODY)
            assert done.wait(3)
        assert observed["http"].endswith(TEST_BODY)
        with pytest.raises(BlockingIOError):
            trap.accept()


@pytest.mark.parametrize("framing", ["content_length", "chunked", "eof"])
def test_response_limit_is_bounded_during_read(tmp_path, framing):
    material = _certificate_material(tmp_path / "server")
    content = b"x" * 1_000_001
    header = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
    if framing == "content_length":
        response = header + b"Content-Length: 1000002\r\n\r\n" + content
    elif framing == "chunked":
        response = (header + b"Transfer-Encoding: chunked\r\n\r\n"
                    + format(len(content) + 1, "x").encode("ascii") + b"\r\n" + content)
    else:
        response = header + b"\r\n" + content
    with _tls_server(material, response=response, hold_response_open=True) as (port, _, done):
        with AuthorityClient(pin=_pin(port, material[3]), ca_file=material[0],
                             credential_provider=lambda: TEST_TOKEN, timeout_seconds=2) as client:
            with pytest.raises(ProtocolError, match="exceeds protocol limit"):
                client._request("POST", "/v1/operations", body=TEST_BODY)
        assert done.wait(3)


def test_truncated_content_length_is_uncertain(tmp_path):
    material = _certificate_material(tmp_path / "server")
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                b"Content-Length: 20\r\nConnection: close\r\n\r\n{}")
    with _tls_server(material, response=response) as (port, _, done):
        with AuthorityClient(pin=_pin(port, material[3]), ca_file=material[0],
                             credential_provider=lambda: TEST_TOKEN, timeout_seconds=2) as client:
            with pytest.raises(AuthorityTransportUncertain):
                client._request("POST", "/v1/operations", body=TEST_BODY)
        assert done.wait(3)
