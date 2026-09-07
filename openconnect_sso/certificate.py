"""Validate the VPN gateway's certificate and remember it on first use.

`openconnect --servercert` implies `--no-system-trust`: the fingerprint it is
given *replaces* CA validation rather than adding to it. Passing through the
fingerprint that the gateway reports about itself therefore leaves the tunnel
trusting whatever the far end claims, with nothing checking that the claim is
about a certificate any CA ever signed.

So the certificate is fetched over a validating handshake of our own and its
public key is remembered the first time it is seen; that pin, rather than the
gateway's claim, is what `openconnect` is told to accept. A gateway whose
certificate no CA vouches for can still be used -- that is the point of trust
on first use -- but only once the user has said so explicitly, and a later
change is then refused rather than silently accepted.
"""

import base64
import hashlib
import socket
import ssl
from urllib.parse import urlparse

import attr
import structlog
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

logger = structlog.get_logger()

HTTPS_PORT = 443


class CertificateError(Exception):
    pass


@attr.s
class ServerCertificate:
    # RFC 7469 pin over the public key, in openconnect's `pin-sha256:` form.
    # Pinning the key rather than the certificate means a renewal that keeps
    # the same key does not look like an impersonation attempt.
    pin = attr.ib()
    # SHA-1 over the whole DER certificate: the "server-cert-hash" a Cisco
    # gateway reports about itself, and openconnect's legacy bare-hex form.
    fingerprint = attr.ib()
    subject = attr.ib()
    issuer = attr.ib()
    ca_trusted = attr.ib()


def _handshake(host, port, timeout, verify):
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True)


def fetch(vpn_url, timeout=30):
    """Return the certificate `vpn_url` serves, and whether a CA vouches for it."""
    parts = urlparse(vpn_url if "//" in vpn_url else f"https://{vpn_url}")
    host, port = parts.hostname, parts.port or HTTPS_PORT
    if not host:
        raise CertificateError(f"Cannot determine the host of {vpn_url!r}")

    ca_trusted = True
    try:
        der = _handshake(host, port, timeout, verify=True)
    except ssl.SSLCertVerificationError as exc:
        logger.warn(
            "VPN gateway certificate is not signed by a trusted CA",
            host=host,
            reason=exc.verify_message or str(exc),
        )
        ca_trusted = False
        try:
            der = _handshake(host, port, timeout, verify=False)
        except (OSError, ssl.SSLError) as exc:
            raise CertificateError(f"Could not retrieve certificate of {host}: {exc}")
    except (OSError, ssl.SSLError) as exc:
        raise CertificateError(f"Could not retrieve certificate of {host}: {exc}")

    cert = x509.load_der_x509_certificate(der)
    public_key = cert.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return ServerCertificate(
        pin="pin-sha256:"
        + base64.b64encode(hashlib.sha256(public_key).digest()).decode("ascii"),
        fingerprint=hashlib.sha1(der).hexdigest().upper(),
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        ca_trusted=ca_trusted,
    )


def check_reported_hash(certificate, reported_hash):
    """Compare the gateway's claim about itself with what it actually serves.

    Only diagnostic: the reported hash is no longer what gets pinned, so a
    mismatch is not by itself dangerous. It usually means a load balancer sent
    the two connections to nodes with different certificates -- which is worth
    saying out loud, because that also makes the remembered pin change from one
    connection to the next.
    """
    if not reported_hash:
        return
    if reported_hash.strip().upper() != certificate.fingerprint:
        logger.warn(
            "VPN gateway reports a certificate other than the one it served us",
            reported=reported_hash.strip().upper(),
            served=certificate.fingerprint,
        )


def trust(certificate, known, key, accept_new=False):
    """Apply trust on first use, returning the pin to hand to openconnect.

    `known` maps a gateway to the pin remembered for it and is updated in
    place, so that the caller decides when it is persisted.
    """
    remembered = known.get(key)
    if remembered == certificate.pin:
        logger.debug("VPN gateway certificate matches the remembered one", key=key)
        return certificate.pin

    if remembered is None:
        if certificate.ca_trusted:
            logger.info(
                "Remembering VPN gateway certificate",
                subject=certificate.subject,
                issuer=certificate.issuer,
                pin=certificate.pin,
            )
        elif accept_new:
            logger.warn(
                "Trusting a VPN gateway certificate that no CA vouches for",
                subject=certificate.subject,
                pin=certificate.pin,
            )
        else:
            raise CertificateError(
                f"No CA vouches for the certificate of {key} and it has not been "
                f"trusted before (subject {certificate.subject}, "
                f"fingerprint {certificate.fingerprint}). Verify it out of band, "
                "then re-run with --trust-new-cert to accept it"
            )
    elif not accept_new:
        raise CertificateError(
            f"The certificate of {key} changed since it was last trusted "
            f"(remembered {remembered}, now {certificate.pin}, subject "
            f"{certificate.subject}, issuer {certificate.issuer}). This is "
            "expected after a certificate renewal that also rolled the key; "
            "verify it out of band, then re-run with --trust-new-cert to accept it"
        )
    else:
        logger.warn(
            "Accepting a changed VPN gateway certificate",
            remembered=remembered,
            now=certificate.pin,
            subject=certificate.subject,
        )

    known[key] = certificate.pin
    return certificate.pin
