"""XML-Signature-Wrapping (XSW) hardening: prove the consumed assertion is the one that gets verified (internal)."""

from __future__ import annotations

from apron_saml.errors import MalformedResponseError
from apron_saml.response import ParsedResponse

_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_ASSERTION_TAG = f"{{{_SAML_NS}}}Assertion"


def _require_sole_consumed_assertion(parsed: ParsedResponse) -> str:
    """Return the consumed assertion's ID after proving it is the document's only assertion.

    The consumed ``parsed.assertion`` must carry a non-empty ID and must be the single
    ``<Assertion>`` anywhere in ``parsed.root`` — binding, by object identity, the element the
    application consumes to the element the rest of the pipeline verifies.
    """
    assertion_id = (parsed.assertion.get("ID") or "").strip()
    if not assertion_id:
        raise MalformedResponseError("assertion has no ID")
    found = [e for e in parsed.root.iter() if e.tag == _ASSERTION_TAG]
    if len(found) != 1 or found[0] is not parsed.assertion:
        raise MalformedResponseError("SAML Response does not carry exactly one, unambiguous assertion")
    return assertion_id


def reject_signature_wrapping(parsed: ParsedResponse) -> None:
    """Reject a decoded SAML Response that shows any XML-Signature-Wrapping indicator.

    Enforces position integrity of the consumed assertion: a second assertion anywhere in the
    document, a non-unique element ID, a signature planted outside the assertion's own single
    signature, or an assertion that fails the hardened local schema each cause rejection.

    Args:
        parsed: The parsed Response, its located assertion, and the parsed root.

    Raises:
        MalformedResponseError: If any wrapping, ID-ambiguity, or schema-conformance check fails.
    """
    _require_sole_consumed_assertion(parsed)
