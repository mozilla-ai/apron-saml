"""XML-Signature-Wrapping (XSW) hardening: prove the consumed assertion is the one that gets verified (internal)."""

from __future__ import annotations

import functools
import io
from importlib.resources import as_file, files
from xml.etree.ElementTree import Element

import xmlschema
from defusedxml.ElementTree import iterparse

from apron_saml.errors import MalformedResponseError
from apron_saml.response import ParsedResponse

_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_ASSERTION_TAG = f"{{{_SAML_NS}}}Assertion"
# Prefix for the anchored XPath selection only; xsi:type resolves from the document's own bindings.
_SCHEMA_NS = {"saml": _SAML_NS}


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


def _normalize_id(value: str) -> str:
    """Collapse XML whitespace in an ID value (matches xml:id/xs:ID normalization)."""
    return " ".join(value.split())


def _reject_ambiguous_ids(parsed: ParsedResponse, assertion_id: str) -> None:
    """Reject the document if the assertion ID is reusable or any ID-typed value is shared.

    Decisive rule: the consumed assertion's ID value must not appear as any attribute value on any
    other element, so the backend cannot resolve that ID to a different element. Defense-in-depth:
    no ID-typed attribute value (``ID``/``Id``/``xml:id``) may appear on more than one element. Both
    rules compare under XML whitespace normalization (``xml:id``/``xs:ID`` collapse whitespace), so a
    padded value cannot evade a comparison the XML-security backend would still resolve as equal.
    """
    normalized_assertion_id = _normalize_id(assertion_id)
    typed_id_values: dict[str, Element] = {}
    for element in parsed.root.iter():
        if element is not parsed.assertion:
            for value in element.attrib.values():
                if _normalize_id(value) == normalized_assertion_id:
                    raise MalformedResponseError("assertion ID is not unique in the SAML Response")
        for name in _ID_ATTRS:
            value = element.get(name)
            if value is None:
                continue
            normalized_value = _normalize_id(value)
            if normalized_value in typed_id_values and typed_id_values[normalized_value] is not element:
                raise MalformedResponseError("SAML Response reuses an element ID")
            typed_id_values[normalized_value] = element


_SIGNATURE_TAG = f"{{{_DS_NS}}}Signature"


def _require_sole_assertion_signature(parsed: ParsedResponse) -> None:
    """Reject the assertion unless it carries exactly one signature anywhere in its subtree.

    Both zero signatures (unsigned) and more than one are rejected. With the sole-assertion check,
    exactly one ``<ds:Signature>`` in the assertion subtree proves the single signature is the
    direct-child enveloped one, and closes a signature planted in an open-content slot
    (``SubjectConfirmationData``/``AttributeValue``/``Advice``).
    """
    signatures = [e for e in parsed.assertion.iter() if e.tag == _SIGNATURE_TAG]
    if len(signatures) != 1:
        raise MalformedResponseError("assertion does not carry exactly one signature in its subtree")


class SchemaBundleError(Exception):
    """The vendored SAML schema bundle could not be loaded — a packaging/deployment fault.

    This is not a SAML-message failure and is deliberately not a ``SamlError``: it signals a broken
    installation (missing or corrupt bundled XSDs), so a packaging fault is never mistaken for a
    malformed message.
    """


@functools.cache
def _assertion_schema() -> xmlschema.XMLSchema:
    """Build (once) the offline SAML assertion schema from the vendored bundle."""
    try:
        with as_file(files("apron_saml") / "schemas") as schema_dir:
            return xmlschema.XMLSchema(
                str(schema_dir / "saml-schema-assertion-2.0.xsd"),
                base_url=str(schema_dir),
                allow="sandbox",
            )
    except Exception as e:  # noqa: BLE001 — any build failure is a broken bundle, re-raised as our own.
        raise SchemaBundleError("the bundled SAML assertion schema failed to load") from e


def _document_namespaces(response_xml: str) -> dict[str, str]:
    """Return the prefix-to-URI namespace declarations found anywhere in the decoded Response.

    ElementTree discards ``xmlns`` declarations, so an ``xsi:type`` QName declared below the
    assertion element cannot otherwise resolve during schema validation; ``start-ns`` events
    recover every declaration (the first binding of each prefix wins, so an inner rebinding of a
    prefix does not shadow the outer one). The Response has already passed the DTD/entity screening
    in ``parse_response``, so this reparse expands nothing.
    """
    namespaces: dict[str, str] = {}
    for _event, (prefix, uri) in iterparse(io.StringIO(response_xml), events=("start-ns",), forbid_dtd=True):
        namespaces.setdefault(prefix, uri)
    return namespaces


def _reject_schema_invalid_assertion(parsed: ParsedResponse) -> None:
    """Reject the consumed assertion if it does not conform to the hardened local assertion schema.

    Validates from the response string so ``xmlschema`` resolves ``xsi:type`` QNames from the
    document's own namespace declarations, recovered via ``start-ns`` so a legitimately-typed
    ``AttributeValue`` validates regardless of where its prefix is declared; ``schema_path`` binds
    the anchored selection to the ``Assertion`` global declaration so the content model is enforced.
    """
    try:
        namespaces = {**_document_namespaces(parsed.response_xml), **_SCHEMA_NS}
        valid = _assertion_schema().is_valid(
            parsed.response_xml,
            path="saml:Assertion",
            schema_path="saml:Assertion",
            namespaces=namespaces,
            allow_empty=False,
        )
    except SchemaBundleError:
        raise
    except Exception as e:  # noqa: BLE001 — any validator error over attacker input is a rejection.
        raise MalformedResponseError("assertion does not conform to the SAML assertion schema") from e
    if not valid:
        raise MalformedResponseError("assertion does not conform to the SAML assertion schema")


def reject_signature_wrapping(parsed: ParsedResponse) -> None:
    """Reject a decoded SAML Response that shows any XML-Signature-Wrapping indicator.

    Enforces position integrity of the consumed assertion: a second assertion anywhere in the
    document, a non-unique element ID, a signature planted outside the assertion's own single
    signature, or an assertion that fails the hardened local schema each cause rejection.

    Args:
        parsed: The parsed Response, its located assertion, and the parsed root.

    Raises:
        MalformedResponseError: If any wrapping, ID-ambiguity, or schema-conformance check fails.
        SchemaBundleError: If the bundled schema could not be loaded — a packaging/deployment fault.
    """
    assertion_id = _require_sole_consumed_assertion(parsed)
    _reject_ambiguous_ids(parsed, assertion_id)
    _require_sole_assertion_signature(parsed)
    _reject_schema_invalid_assertion(parsed)
