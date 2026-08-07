"""Cryptographic verification of a SAML assertion's signature against the configured IdP (internal)."""

from __future__ import annotations

from xml.etree.ElementTree import Element

from apron_saml.errors import SignatureError
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
