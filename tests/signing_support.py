"""Test helpers that mint throwaway signing material and produce signed SAML Responses.

No key material is committed; everything is generated per call. Requires the xmlsec1 binary.
"""

from __future__ import annotations

import datetime as _dt
import tempfile
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from saml2.sigver import (
    CryptoBackendXmlSec1,
    SecurityContext,
    get_xmlsec_binary,
    pre_signature_part,
)

_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
_ASSERTION_NODE = "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"

# (signature-method, digest-method) URIs by short name. pre_signature_part defaults to SHA-1, so the
# algorithm is always set explicitly here — the "sha1" pair exists only to exercise rejection.
_ALGORITHMS = {
    "sha256": (
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2001/04/xmlenc#sha256",
    ),
    "sha1": (
        "http://www.w3.org/2000/09/xmldsig#rsa-sha1",
        "http://www.w3.org/2000/09/xmldsig#sha1",
    ),
}


@dataclass(frozen=True)
class SignedResponse:
    """A signed Response plus the certificate that verifies it and the signed assertion's ID."""

    response_xml: str
    cert_pem: str
    assertion_id: str


def self_signed_cert() -> tuple[str, str]:
    """Return a fresh (private-key PEM, self-signed certificate PEM) pair."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-idp")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_dt.datetime(2020, 1, 1, tzinfo=_dt.UTC))
        .not_valid_after(_dt.datetime(2100, 1, 1, tzinfo=_dt.UTC))
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return key_pem, cert_pem


def sign_assertion_response(
    *,
    assertion_id: str = "_a1",
    issuer: str = "https://idp.example.com/entity",
    key_pem: str | None = None,
    cert_pem: str | None = None,
    algorithm: str = "sha256",
) -> SignedResponse:
    """Return a Response whose assertion is enveloped-signed with a throwaway (or supplied) key."""
    if key_pem is None or cert_pem is None:
        key_pem, cert_pem = self_signed_cert()
    sign_alg, digest_alg = _ALGORITHMS[algorithm]
    template = pre_signature_part(assertion_id, sign_alg=sign_alg, digest_alg=digest_alg).to_string()
    if isinstance(template, bytes):
        template = template.decode()
    escaped_issuer = escape(issuer)
    unsigned = (
        f'<samlp:Response xmlns:samlp="{_SAMLP}" xmlns:saml="{_SAML}" ID="_r1" Version="2.0">'
        f"<saml:Issuer>{escaped_issuer}</saml:Issuer>"
        f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f'<saml:Assertion ID="{assertion_id}" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">'
        f"<saml:Issuer>{escaped_issuer}</saml:Issuer>{template}"
        f"<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>"
        f"</saml:Assertion></samlp:Response>"
    )
    context = SecurityContext(CryptoBackendXmlSec1(get_xmlsec_binary()))
    with tempfile.TemporaryDirectory() as tmp:
        key_path = Path(tmp) / "key.pem"
        key_path.write_text(key_pem)
        signed = context.sign_statement(
            unsigned,
            node_name=_ASSERTION_NODE,
            key_file=str(key_path),
            node_id=assertion_id,
        )
    if isinstance(signed, bytes):
        signed = signed.decode()
    return SignedResponse(response_xml=signed, cert_pem=cert_pem, assertion_id=assertion_id)
