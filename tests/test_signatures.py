import pytest
from defusedxml.ElementTree import fromstring
from signing_support import self_signed_cert, sign_assertion_response

from apron_saml import IdPDescriptor, SignatureError
from apron_saml.response import ParsedResponse, parse_response
from apron_saml.signatures import (
    _locate_assertion_signature,
    _require_strong_algorithms,
    verify_assertion_signature,
)

_DS = "http://www.w3.org/2000/09/xmldsig#"
_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"

_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"


def _sig(sig_alg: str, digest_alg: str):
    xml = (
        f'<ds:Signature xmlns:ds="{_DS}"><ds:SignedInfo>'
        f'<ds:SignatureMethod Algorithm="{sig_alg}"/>'
        f'<ds:Reference URI="#_a1"><ds:DigestMethod Algorithm="{digest_alg}"/></ds:Reference>'
        f"</ds:SignedInfo></ds:Signature>"
    )
    return fromstring(xml)


def test_accepts_sha256() -> None:
    _require_strong_algorithms(_sig(_RSA_SHA256, _SHA256))  # no raise


def test_rejects_sha1_signature() -> None:
    with pytest.raises(SignatureError):
        _require_strong_algorithms(_sig(_RSA_SHA1, _SHA256))


def test_rejects_sha1_digest() -> None:
    with pytest.raises(SignatureError):
        _require_strong_algorithms(_sig(_RSA_SHA256, _SHA1))


def _sig_xml(uri: str = "#_a1") -> str:
    return (
        f"<ds:Signature><ds:SignedInfo>"
        f'<ds:SignatureMethod Algorithm="{_RSA_SHA256}"/>'
        f'<ds:Reference URI="{uri}"><ds:DigestMethod Algorithm="{_SHA256}"/></ds:Reference>'
        f"</ds:SignedInfo></ds:Signature>"
    )


def _assertion_with(sig_children: str, assertion_id: str = "_a1") -> ParsedResponse:
    xml = f'<saml:Assertion xmlns:saml="{_SAML}" xmlns:ds="{_DS}" ID="{assertion_id}">{sig_children}</saml:Assertion>'
    return ParsedResponse(response_xml="<unused/>", assertion=fromstring(xml))


def test_locates_single_child_signature() -> None:
    sig, aid = _locate_assertion_signature(_assertion_with(_sig_xml()))
    assert aid == "_a1"
    assert sig.tag == f"{{{_DS}}}Signature"


def test_rejects_missing_signature() -> None:
    with pytest.raises(SignatureError):
        _locate_assertion_signature(_assertion_with(""))


def test_rejects_reference_not_covering_assertion() -> None:
    with pytest.raises(SignatureError):
        _locate_assertion_signature(_assertion_with(_sig_xml(uri="#_other")))


def test_rejects_missing_assertion_id() -> None:
    xml = f'<saml:Assertion xmlns:saml="{_SAML}" xmlns:ds="{_DS}">{_sig_xml()}</saml:Assertion>'
    with pytest.raises(SignatureError):
        _locate_assertion_signature(ParsedResponse(response_xml="<u/>", assertion=fromstring(xml)))


def test_rejects_multiple_signatures() -> None:
    with pytest.raises(SignatureError):
        _locate_assertion_signature(_assertion_with(_sig_xml() + _sig_xml()))


def _idp(*cert_pems: str) -> IdPDescriptor:
    bodies = tuple(
        "".join(c.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").split())
        for c in cert_pems
    )
    return IdPDescriptor(
        entity_id="https://idp.example.com/entity",
        sso_url="https://idp.example.com/sso",
        signing_certificates=bodies,
    )


def test_valid_signature_passes() -> None:
    signed = sign_assertion_response()
    verify_assertion_signature(parse_response(signed.response_xml), _idp(signed.cert_pem))


def test_tampered_assertion_fails() -> None:
    signed = sign_assertion_response()
    tampered = signed.response_xml.replace("user@example.com", "attacker@evil.example")
    with pytest.raises(SignatureError):
        verify_assertion_signature(parse_response(tampered), _idp(signed.cert_pem))


def test_wrong_cert_fails() -> None:
    signed = sign_assertion_response()
    _, other_cert = self_signed_cert()
    with pytest.raises(SignatureError):
        verify_assertion_signature(parse_response(signed.response_xml), _idp(other_cert))


def test_valid_under_one_of_several_certs_rollover() -> None:
    signed = sign_assertion_response()
    _, other_cert = self_signed_cert()
    verify_assertion_signature(parse_response(signed.response_xml), _idp(other_cert, signed.cert_pem))


def test_no_configured_certs_fails() -> None:
    signed = sign_assertion_response()
    with pytest.raises(SignatureError):
        verify_assertion_signature(parse_response(signed.response_xml), _idp())


def test_sha1_signature_rejected_end_to_end() -> None:
    signed = sign_assertion_response(algorithm="sha1")
    with pytest.raises(SignatureError):
        verify_assertion_signature(parse_response(signed.response_xml), _idp(signed.cert_pem))
