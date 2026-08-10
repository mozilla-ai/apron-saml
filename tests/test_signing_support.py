from pathlib import Path

from saml2.sigver import CryptoBackendXmlSec1, SecurityContext, get_xmlsec_binary
from signing_support import sign_assertion_response

_NODE = "urn:oasis:names:tc:SAML:2.0:assertion:Assertion"


def _sec() -> SecurityContext:
    return SecurityContext(CryptoBackendXmlSec1(get_xmlsec_binary()))


def test_signed_response_has_signature_value() -> None:
    assert "SignatureValue" in sign_assertion_response().response_xml


def test_signs_response_with_special_chars_in_issuer() -> None:
    # An issuer containing '&' must be escaped, or the fixture builds malformed XML that fails signing.
    signed = sign_assertion_response(issuer="https://idp.example.com/e?a=1&b=2")
    assert "SignatureValue" in signed.response_xml


def test_signed_response_verifies_with_its_cert(tmp_path: Path) -> None:
    signed = sign_assertion_response()
    pem = tmp_path / "c.pem"
    pem.write_text(signed.cert_pem)
    assert (
        _sec().verify_signature(
            signed.response_xml,
            cert_file=str(pem),
            cert_type="pem",
            node_name=_NODE,
            node_id=signed.assertion_id,
        )
        is True
    )
