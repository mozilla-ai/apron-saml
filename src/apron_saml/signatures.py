"""Cryptographic verification of a SAML assertion's signature against the configured IdP (internal)."""

from __future__ import annotations

import tempfile
from pathlib import Path
from xml.etree.ElementTree import Element

from saml2.sigver import CryptoBackendXmlSec1, SecurityContext, XmlsecError, get_xmlsec_binary
from saml2.sigver import SignatureError as _BackendSignatureError

from apron_saml.errors import SignatureError
from apron_saml.models import IdPDescriptor
from apron_saml.response import ParsedResponse

_DS_NS = "http://www.w3.org/2000/09/xmldsig#"

# Signature and digest algorithm URIs strong enough to trust: RSA/ECDSA with SHA-256 or better.
# SHA-1 (and weaker) is excluded — it is collision-broken and must never verify an assertion.
_ALLOWED_SIGNATURE_ALGORITHMS = frozenset(
    {
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
        "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
    }
)
_ALLOWED_DIGEST_ALGORITHMS = frozenset(
    {
        "http://www.w3.org/2001/04/xmlenc#sha256",
        "http://www.w3.org/2001/04/xmldsig-more#sha384",
        "http://www.w3.org/2001/04/xmlenc#sha512",
    }
)


def _require_strong_algorithms(signature: Element) -> None:
    """Reject a signature whose SignatureMethod or any DigestMethod is not on the strong allowlist."""
    method = signature.find(f"{{{_DS_NS}}}SignedInfo/{{{_DS_NS}}}SignatureMethod")
    if method is None or method.get("Algorithm") not in _ALLOWED_SIGNATURE_ALGORITHMS:
        raise SignatureError("assertion signature uses a disallowed or missing signature algorithm")
    for digest in signature.iterfind(f"{{{_DS_NS}}}SignedInfo/{{{_DS_NS}}}Reference/{{{_DS_NS}}}DigestMethod"):
        if digest.get("Algorithm") not in _ALLOWED_DIGEST_ALGORITHMS:
            raise SignatureError("assertion signature uses a disallowed or missing digest algorithm")


def _locate_assertion_signature(parsed: ParsedResponse) -> tuple[Element, str]:
    """Return the assertion's single enveloped signature and the assertion ID it must cover.

    The signature must be a direct child of the consumed assertion, and its Reference must target the
    assertion's own ID — the structural half of binding the element verified to the element consumed.
    """
    assertion_id = (parsed.assertion.get("ID") or "").strip()
    if not assertion_id:
        raise SignatureError("assertion has no ID for its signature to cover")
    signatures = parsed.assertion.findall(f"{{{_DS_NS}}}Signature")
    if len(signatures) != 1:
        raise SignatureError("assertion does not carry exactly one signature")
    signature = signatures[0]
    references = [ref.get("URI") for ref in signature.iterfind(f"{{{_DS_NS}}}SignedInfo/{{{_DS_NS}}}Reference")]
    if references != [f"#{assertion_id}"]:
        raise SignatureError("assertion signature does not cover the assertion element")
    return signature, assertion_id


_ASSERTION_NODE_NAME = "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"


def _pem(cert_body: str) -> str:
    """Wrap a whitespace-free base64 DER certificate body as a PEM certificate."""
    lines = "\n".join(cert_body[i : i + 64] for i in range(0, len(cert_body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def verify_assertion_signature(parsed: ParsedResponse, idp: IdPDescriptor) -> None:
    """Verify the consumed assertion's enveloped signature against a configured IdP certificate.

    Raises SignatureError unless the consumed assertion carries exactly one enveloped signature that
    covers it, uses a strong algorithm, and verifies against one of the IdP's configured signing
    certificates. In-message KeyInfo is ignored: trust is pinned to the configured certificates, any
    of which may verify the signature (supporting key rollover).

    Args:
        parsed: The decoded Response and its located assertion.
        idp: The identity provider descriptor supplying the pinned signing certificates.

    Raises:
        SignatureError: If the assertion is unsigned, its signature does not cover it, uses a weak
            algorithm, or does not verify against any configured certificate.
    """
    signature, assertion_id = _locate_assertion_signature(parsed)
    _require_strong_algorithms(signature)
    if not idp.signing_certificates:
        raise SignatureError("no configured IdP certificate to verify the assertion signature")

    context = SecurityContext(CryptoBackendXmlSec1(get_xmlsec_binary()))
    for cert_body in idp.signing_certificates:
        with tempfile.TemporaryDirectory() as tmp:
            cert_file = Path(tmp) / "idp.pem"
            cert_file.write_text(_pem(cert_body))
            try:
                verified = context.verify_signature(
                    parsed.response_xml,
                    cert_file=str(cert_file),
                    cert_type="pem",
                    node_name=_ASSERTION_NODE_NAME,
                    node_id=assertion_id,
                )
            except (_BackendSignatureError, XmlsecError):
                # A backend rejection means this certificate did not verify the signature, not a crash.
                verified = False
        if verified:
            return
    raise SignatureError("assertion signature did not verify against the configured IdP certificate")
