import functools

import pytest
from defusedxml.ElementTree import fromstring
from signing_support import sign_assertion_response

from apron_saml.errors import MalformedResponseError
from apron_saml.response import ParsedResponse
from apron_saml.wrapping import reject_signature_wrapping

_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
_DS = "http://www.w3.org/2000/09/xmldsig#"
# Tail marker inside the valid base, between the Subject close and the Assertion close — every
# in-assertion mutation is inserted here so it lands inside the assertion subtree.
_A_TAIL = "</saml:Subject></saml:Assertion>"


@functools.lru_cache(maxsize=1)
def _valid_response_xml() -> str:
    """A fully valid, signed, schema-conformant Response (cached; signing is slow)."""
    return sign_assertion_response().response_xml


def _wrap(response_xml: str) -> ParsedResponse:
    root = fromstring(response_xml)
    assertion = root.find(f"{{{_SAML}}}Assertion")
    return ParsedResponse(response_xml=response_xml, assertion=assertion, root=root)


def _mutate(*, in_assertion: str = "", sibling: str = "") -> str:
    """Return the valid base with content inserted inside the assertion and/or as a Response sibling."""
    xml = _valid_response_xml()
    if in_assertion:
        xml = xml.replace(_A_TAIL, f"</saml:Subject>{in_assertion}</saml:Assertion>", 1)
    if sibling:
        xml = xml.replace("</samlp:Response>", f"{sibling}</samlp:Response>", 1)
    return xml


def test_single_clean_assertion_passes() -> None:
    reject_signature_wrapping(_wrap(_valid_response_xml()))  # no raise.


def test_missing_assertion_id_rejected() -> None:
    xml = _valid_response_xml().replace('ID="_a1"', "", 1)  # drop the assertion ID.
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(xml))


def test_second_assertion_in_advice_rejected() -> None:
    xml = _mutate(in_assertion='<saml:Advice><saml:Assertion ID="_a2"/></saml:Advice>')
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(xml))


def test_second_assertion_as_sibling_rejected() -> None:
    xml = _mutate(sibling='<saml:Assertion ID="_a3"/>')
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(xml))


def test_consumed_assertion_not_the_tree_assertion_rejected() -> None:
    # parsed.assertion is a detached element that is NOT the one inside root.
    base = _valid_response_xml()
    root = fromstring(base)
    other = fromstring(f'<saml:Assertion xmlns:saml="{_SAML}" ID="_a1"/>')
    parsed = ParsedResponse(response_xml=base, assertion=other, root=root)
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(parsed)
