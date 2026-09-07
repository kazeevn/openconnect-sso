import base64
import datetime
import hashlib
import socket
import ssl
import threading

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from openconnect_sso import certificate
from openconnect_sso.certificate import CertificateError, ServerCertificate


def make_certificate(common_name="vpn.example.com", key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    return key, cert


@pytest.fixture
def self_signed_server(tmp_path):
    """A TLS server with a certificate no CA vouches for, as a gateway would be."""
    key, cert = make_certificate("localhost")
    cert_file = tmp_path / "cert.pem"
    cert_file.write_bytes(
        cert.public_bytes(serialization.Encoding.PEM)
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file)

    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    port = listener.getsockname()[1]

    def serve():
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            try:
                with context.wrap_socket(client, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield f"https://localhost:{port}/group", cert
    listener.close()


def test_untrusted_certificate_is_still_fetched_but_flagged(self_signed_server):
    url, cert = self_signed_server
    fetched = certificate.fetch(url, timeout=10)

    assert fetched.ca_trusted is False
    assert (
        fetched.fingerprint
        == hashlib.sha1(cert.public_bytes(serialization.Encoding.DER))
        .hexdigest()
        .upper()
    )
    expected_pin = base64.b64encode(
        hashlib.sha256(
            cert.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).digest()
    ).decode()
    assert fetched.pin == f"pin-sha256:{expected_pin}"


def certificate_for(pin, ca_trusted=True, fingerprint="AA"):
    return ServerCertificate(
        pin=pin,
        fingerprint=fingerprint,
        subject="CN=vpn.example.com",
        issuer="CN=Example CA",
        ca_trusted=ca_trusted,
    )


def test_ca_signed_certificate_is_remembered_without_asking():
    known = {}
    pin = certificate.trust(certificate_for("pin-sha256:aaa"), known, "vpn")
    assert pin == "pin-sha256:aaa"
    assert known == {"vpn": "pin-sha256:aaa"}


def test_remembered_certificate_is_accepted_again():
    known = {"vpn": "pin-sha256:aaa"}
    assert certificate.trust(certificate_for("pin-sha256:aaa"), known, "vpn")
    assert known == {"vpn": "pin-sha256:aaa"}


def test_untrusted_certificate_needs_an_explicit_first_use_decision():
    known = {}
    untrusted = certificate_for("pin-sha256:aaa", ca_trusted=False)
    with pytest.raises(CertificateError, match="No CA vouches"):
        certificate.trust(untrusted, known, "vpn")
    assert known == {}

    assert certificate.trust(untrusted, known, "vpn", accept_new=True)
    assert known == {"vpn": "pin-sha256:aaa"}


def test_changed_certificate_is_refused_even_when_ca_signed():
    # A valid chain is exactly what an interceptor with a trusted CA presents,
    # so a changed key must not be waved through just because it validates.
    known = {"vpn": "pin-sha256:aaa"}
    with pytest.raises(CertificateError, match="changed since it was last trusted"):
        certificate.trust(certificate_for("pin-sha256:bbb"), known, "vpn")
    assert known == {"vpn": "pin-sha256:aaa"}


def test_changed_certificate_is_accepted_when_asked_for():
    known = {"vpn": "pin-sha256:aaa"}
    certificate.trust(certificate_for("pin-sha256:bbb"), known, "vpn", accept_new=True)
    assert known == {"vpn": "pin-sha256:bbb"}


def test_gateway_claiming_a_certificate_it_does_not_serve_is_reported(monkeypatch):
    warnings = []
    monkeypatch.setattr(
        certificate.logger, "warn", lambda msg, **kw: warnings.append(msg)
    )
    served = certificate_for("pin-sha256:aaa", fingerprint="A1B2C3D4")

    certificate.check_reported_hash(served, "a1b2c3d4")
    assert warnings == []

    # Diagnostic only: the reported hash is not what gets pinned any more.
    certificate.check_reported_hash(served, "DEADBEEF")
    assert "other than the one it served us" in warnings[0]


def test_no_reported_hash_is_not_a_mismatch():
    certificate.check_reported_hash(certificate_for("pin-sha256:aaa"), "")


def test_unreachable_gateway_reports_a_certificate_error():
    with pytest.raises(CertificateError, match="Could not retrieve certificate"):
        certificate.fetch("https://127.0.0.1:1/group", timeout=5)
