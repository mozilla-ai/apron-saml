"""XML-Signature-Wrapping (XSW) hardening: prove the consumed assertion is the one that gets verified (internal)."""

from __future__ import annotations

from xml.etree.ElementTree import Element

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


_XML_ID = "{http://www.w3.org/XML/1998/namespace}id"
# Attribute local names an XML/xmlsec ID resolver may treat as ID-typed. Bare lowercase ``id`` is
# excluded (not ID-typed without a DTD/schema; legitimate inside XHTML AttributeValue content) — the
# decisive value rule below still catches an ``id`` that reuses the consumed assertion's ID value.
_ID_ATTRS = ("ID", "Id", _XML_ID)


def _reject_ambiguous_ids(parsed: ParsedResponse, assertion_id: str) -> None:
    """Reject the document if the assertion ID is reusable or any ID-typed value is shared.

    Decisive rule: the consumed assertion's ID value must not appear as any attribute value on any
    other element, so the backend cannot resolve that ID to a different element. Defense-in-depth:
    no ID-typed attribute value (``ID``/``Id``/``xml:id``) may appear on more than one element.
    """
    typed_id_values: dict[str, Element] = {}
    for element in parsed.root.iter():
        if element is not parsed.assertion:
            for value in element.attrib.values():
                if value == assertion_id:
                    raise MalformedResponseError("assertion ID is not unique in the SAML Response")
        for name in _ID_ATTRS:
            value = element.get(name)
            if value is None:
                continue
            if value in typed_id_values and typed_id_values[value] is not element:
                raise MalformedResponseError("SAML Response reuses an element ID")
            typed_id_values[value] = element


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
    assertion_id = _require_sole_consumed_assertion(parsed)
    _reject_ambiguous_ids(parsed, assertion_id)
