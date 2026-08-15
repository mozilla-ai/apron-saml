import functools

import pytest
from defusedxml.ElementTree import fromstring
from signing_support import sign_assertion_response

from apron_saml import wrapping
from apron_saml.errors import MalformedResponseError, SamlError
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


def test_duplicate_id_value_across_elements_rejected() -> None:
    # A NON-ID attribute reusing the assertion's ID value must still be caught (decisive value rule).
    xml = _mutate(sibling='<samlp:Extra foo="_a1"/>')
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(xml))


def test_duplicate_typed_id_rejected() -> None:
    # Isolate the typed-ID branch (Id name, xmldsig spelling) with a value distinct from the
    # assertion's own ID, so the decisive-value rule does not mask it.
    xml = _mutate(sibling='<samlp:A Id="dup2"/><samlp:B Id="dup2"/>')
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(xml))


def test_duplicate_xml_id_rejected() -> None:
    xml = _mutate(sibling='<samlp:A xml:id="dup"/><samlp:B xml:id="dup"/>')
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(xml))


def test_unique_ids_pass() -> None:
    xml = _mutate(sibling='<samlp:Extra ID="_other"/>')
    reject_signature_wrapping(_wrap(xml))  # no raise.


def test_whitespace_padded_id_colliding_after_normalization_rejected() -> None:
    # xml:id/xs:ID use XML whitespace normalization, so a padded value that collapses to the
    # assertion's own ID must still trip the decisive-value rule (an XML-security backend resolves
    # it to the same element the raw-value comparison would miss).
    xml = _mutate(sibling='<samlp:Extra xml:id=" _a1 "/>')
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(xml))


def test_duplicate_typed_id_after_whitespace_normalization_rejected() -> None:
    # Two typed-ID values differing only in surrounding whitespace collapse to the same ID under
    # XML whitespace normalization.
    xml = _mutate(sibling='<samlp:A Id="dup2"/><samlp:B Id=" dup2 "/>')
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(xml))


_EXTRA_SIG = f'<ds:Signature xmlns:ds="{_DS}"><ds:SignedInfo/></ds:Signature>'


def test_second_signature_in_assertion_subtree_rejected() -> None:
    # A second <ds:Signature> anywhere inside the assertion (2 total in the subtree) is rejected.
    xml = _mutate(in_assertion=_EXTRA_SIG)
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(xml))


def test_response_level_signature_not_rejected() -> None:
    # A signature OUTSIDE the assertion subtree (a Response sibling) is legitimate — check 3 ignores it.
    xml = _mutate(sibling=_EXTRA_SIG)
    reject_signature_wrapping(_wrap(xml))  # no raise (assertion subtree still has exactly one signature).


def test_zero_signatures_rejected() -> None:
    # A hand-built, otherwise-valid single assertion carrying NO signature must reach check 3 (having
    # cleared checks 1 and 2 — one unambiguous assertion, no ID collisions) and be rejected there: the
    # `!= 1` predicate in _require_sole_assertion_signature rejects zero signatures, not just >1.
    xml = (
        f'<samlp:Response xmlns:samlp="{_SAMLP}" xmlns:saml="{_SAML}" ID="_r1" Version="2.0">'
        f"<saml:Issuer>https://idp.example.com/entity</saml:Issuer>"
        f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f'<saml:Assertion ID="_a1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z">'
        f"<saml:Issuer>https://idp.example.com/entity</saml:Issuer>"
        f"<saml:Subject><saml:NameID>user@example.com</saml:NameID></saml:Subject>"
        f"</saml:Assertion></samlp:Response>"
    )
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(xml))


_XS = "http://www.w3.org/2001/XMLSchema"
_XSI = "http://www.w3.org/2001/XMLSchema-instance"
# A valid AttributeStatement whose AttributeValue uses a NON-STANDARD prefix (zz) bound to the XSD
# namespace for xsi:type — must resolve from the document's own bindings.
_ATTR_STMT_XSI = (
    '<saml:AttributeStatement><saml:Attribute Name="x">'
    f'<saml:AttributeValue xmlns:xsi="{_XSI}" xmlns:zz="{_XS}" xsi:type="zz:string">v</saml:AttributeValue>'
    "</saml:Attribute></saml:AttributeStatement>"
)
# Same shape, but xsi:type names a type in a namespace not in the bundle — xmlschema cannot resolve it.
_ATTR_STMT_CUSTOM = (
    '<saml:AttributeStatement><saml:Attribute Name="x">'
    f'<saml:AttributeValue xmlns:xsi="{_XSI}" xmlns:c="urn:custom" xsi:type="c:Missing">v</saml:AttributeValue>'
    "</saml:Attribute></saml:AttributeStatement>"
)


def test_real_signed_assertion_passes_schema() -> None:
    reject_signature_wrapping(_wrap(_valid_response_xml()))  # no raise.


def test_assertion_with_disallowed_child_rejected() -> None:
    xml = _mutate(in_assertion="<saml:Bogus/>")  # not in AssertionType's content model.
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(xml))


def test_attribute_statement_with_xsi_type_passes() -> None:
    reject_signature_wrapping(_wrap(_mutate(in_assertion=_ATTR_STMT_XSI)))  # no raise.


def test_unresolvable_custom_xsi_type_is_domain_error() -> None:
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(_mutate(in_assertion=_ATTR_STMT_CUSTOM)))


def test_schema_build_is_offline_and_ignores_hostile_schemalocation() -> None:
    hostile = _valid_response_xml().replace(
        "<saml:Assertion ",
        '<saml:Assertion xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
        'xsi:schemaLocation="urn:oasis:names:tc:SAML:2.0:assertion http://127.0.0.1:9/evil.xsd" ',
        1,
    )
    reject_signature_wrapping(_wrap(hostile))  # no network, still validates.


def test_disallowed_child_is_the_version_canary() -> None:
    # If a future xmlschema makes this pass, the schema check is toothless — treat as a hard failure.
    with pytest.raises(MalformedResponseError):
        reject_signature_wrapping(_wrap(_mutate(in_assertion="<saml:Bogus/>")))


def test_schema_is_valid_is_reentrant_under_threads() -> None:
    import concurrent.futures

    ok = _valid_response_xml()
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(lambda _: reject_signature_wrapping(_wrap(ok)), range(32)))  # no raise.


def test_broken_bundle_raises_schema_bundle_error(monkeypatch, tmp_path) -> None:
    # Point the bundle lookup at an empty directory so the XSD build fails, and confirm the
    # translated exception is NOT a SamlError (it signals a packaging fault, not a bad message).
    wrapping._assertion_schema.cache_clear()
    monkeypatch.setattr(wrapping, "files", lambda _pkg: tmp_path)
    try:
        with pytest.raises(wrapping.SchemaBundleError):
            wrapping._assertion_schema()
        assert not issubclass(wrapping.SchemaBundleError, SamlError)
    finally:
        wrapping._assertion_schema.cache_clear()  # restore so later tests rebuild the real schema.
