import base64

import pytest
from signing_support import sign_assertion_response

from apron_saml import MalformedResponseError, MetadataError, SamlConfig, ServiceProvider, SignatureError

_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

# A non-empty certificate body is enough for construction/warning tests, which never verify a
# signature; tests that actually verify pass a real signing certificate via _cert_body().
_PLACEHOLDER_CERT = "MIIBplaceholdercertbodyForConstructionTestsOnlyAAAAAAAA"


def _cert_body(cert_pem: str) -> str:
    return "".join(cert_pem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").split())


def _idp_metadata(cert_body: str | None = _PLACEHOLDER_CERT) -> str:
    key_descriptor = ""
    if cert_body is not None:
        key_descriptor = (
            f'<KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>'
            f"<ds:X509Certificate>{cert_body}</ds:X509Certificate>"
            f"</ds:X509Data></ds:KeyInfo></KeyDescriptor>"
        )
    return (
        f'<EntityDescriptor xmlns="{_MD}" xmlns:ds="{_DS}" entityID="https://idp.example.com/entity">'
        f'<IDPSSODescriptor protocolSupportEnumeration="{_PROTOCOL}">'
        f"{key_descriptor}"
        f'<SingleSignOnService Binding="{_REDIRECT}" Location="https://idp.example.com/sso"/>'
        f"</IDPSSODescriptor></EntityDescriptor>"
    )


def _sp(idp_metadata: str, *, want_assertions_signed: bool = True) -> ServiceProvider:
    return ServiceProvider(
        SamlConfig(
            entity_id="https://sp.example.com/metadata",
            acs_url="https://sp.example.com/acs",
            idp_metadata=idp_metadata,
            want_assertions_signed=want_assertions_signed,
        )
    )


def _b64(xml: str) -> str:
    return base64.b64encode(xml.encode("utf-8")).decode("ascii")


def test_want_assertions_signed_false_rejected() -> None:
    # Fail closed at construction: response-level signature acceptance is not implemented yet (#52).
    with pytest.raises(ValueError, match="want_assertions_signed"):
        _sp(_idp_metadata(), want_assertions_signed=False)


def test_construction_fails_fast_on_bad_metadata() -> None:
    with pytest.raises(MetadataError):
        _sp("<not-entity-descriptor/>")


def test_construction_fails_fast_without_signing_certificate() -> None:
    with pytest.raises(MetadataError):
        _sp(_idp_metadata(cert_body=None))


def test_process_response_rejects_tampered_signature() -> None:
    signed = sign_assertion_response()
    sp = _sp(_idp_metadata(_cert_body(signed.cert_pem)))
    tampered = signed.response_xml.replace("user@example.com", "attacker@evil.example")
    with pytest.raises(SignatureError):
        sp.process_response(_b64(tampered))


def test_process_response_runs_conditions_after_signature() -> None:
    # A validly-signed assertion with no <Conditions> is rejected, so the public entry point reaches
    # the Conditions check. Pipeline ordering itself is proven in tests/test_validation.py.
    signed = sign_assertion_response()
    sp = _sp(_idp_metadata(_cert_body(signed.cert_pem)))
    with pytest.raises(MalformedResponseError):
        sp.process_response(_b64(signed.response_xml))


def test_process_response_accepts_valid_conditions() -> None:
    # The one positive path through the public entry point: decode, wrapping, signature, and
    # Conditions all clear, stopping only at the not-yet-implemented remainder. The window is left
    # open-ended so this runs against the default system clock, which nothing else exercises.
    conditions = (
        '<saml:Conditions NotOnOrAfter="2099-01-01T00:00:00Z">'
        "<saml:AudienceRestriction><saml:Audience>https://sp.example.com/metadata</saml:Audience>"
        "</saml:AudienceRestriction></saml:Conditions>"
    )
    signed = sign_assertion_response(conditions=conditions)
    sp = _sp(_idp_metadata(_cert_body(signed.cert_pem)))
    with pytest.raises(NotImplementedError):
        sp.process_response(_b64(signed.response_xml))
