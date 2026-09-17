import base64
from datetime import UTC, datetime

import pytest
from signing_support import sign_assertion_response

from apron_saml import (
    InResponseToError,
    MalformedResponseError,
    MetadataError,
    SamlConfig,
    ServiceProvider,
    SignatureError,
)
from apron_saml.protocols import Clock

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


_NOW = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)


class _FixedClock:
    def now(self) -> datetime:
        return _NOW


# The default for these tests. Passing clock=None instead selects the facade's own system clock.
_FIXED_CLOCK = _FixedClock()


def _sp(
    idp_metadata: str, *, want_assertions_signed: bool = True, clock: Clock | None = _FIXED_CLOCK
) -> ServiceProvider:
    return ServiceProvider(
        SamlConfig(
            entity_id="https://sp.example.com/metadata",
            acs_url="https://sp.example.com/acs",
            idp_metadata=idp_metadata,
            want_assertions_signed=want_assertions_signed,
        ),
        clock=clock,
    )


# A window around the fixed clock. The facade's default system clock is exercised separately.
_CONDITIONS = (
    '<saml:Conditions NotOnOrAfter="2024-01-01T13:00:00Z">'
    "<saml:AudienceRestriction><saml:Audience>https://sp.example.com/metadata</saml:Audience>"
    "</saml:AudienceRestriction></saml:Conditions>"
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
        sp.process_response(_b64(tampered), expected_in_response_to="_req1")


def test_process_response_runs_conditions_after_signature() -> None:
    # A validly-signed assertion with no <Conditions> is rejected, so the public entry point reaches
    # the Conditions check. Pipeline ordering itself is proven in tests/test_validation.py.
    signed = sign_assertion_response()
    sp = _sp(_idp_metadata(_cert_body(signed.cert_pem)))
    with pytest.raises(MalformedResponseError):
        sp.process_response(_b64(signed.response_xml), expected_in_response_to="_req1")


def test_process_response_accepts_a_fully_valid_response() -> None:
    # The one positive path through the public entry point: decode, wrapping, signature, Conditions,
    # and SubjectConfirmation all clear, stopping only at the not-yet-implemented remainder.
    subject_confirmation = (
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        '<saml:SubjectConfirmationData Recipient="https://sp.example.com/acs" '
        'NotOnOrAfter="2024-01-01T12:05:00Z" InResponseTo="_req1"/></saml:SubjectConfirmation>'
    )
    signed = sign_assertion_response(
        conditions=_CONDITIONS,
        subject_confirmation=subject_confirmation,
        response_attributes='Destination="https://sp.example.com/acs" InResponseTo="_req1"',
    )
    sp = _sp(_idp_metadata(_cert_body(signed.cert_pem)))
    with pytest.raises(NotImplementedError):
        sp.process_response(_b64(signed.response_xml), expected_in_response_to="_req1")


def test_process_response_rejects_unsolicited_response_by_default() -> None:
    # Passing None declares the response unsolicited, which the secure default configuration refuses.
    signed = sign_assertion_response(conditions=_CONDITIONS)
    sp = _sp(_idp_metadata(_cert_body(signed.cert_pem)))
    with pytest.raises(InResponseToError):
        sp.process_response(_b64(signed.response_xml), expected_in_response_to=None)


def test_process_response_requires_an_explicit_request_id() -> None:
    # None is the positive declaration that a response is unsolicited, so it must be chosen rather
    # than fallen into by omitting the argument.
    signed = sign_assertion_response(conditions=_CONDITIONS)
    sp = _sp(_idp_metadata(_cert_body(signed.cert_pem)))
    with pytest.raises(TypeError):
        sp.process_response(_b64(signed.response_xml))  # ty: ignore[missing-argument]


def test_process_response_uses_the_system_clock_by_default() -> None:
    # The only test that exercises the facade's default clock. Its windows are open-ended so it cannot
    # age out; every other facade test injects a fixed clock instead.
    conditions = (
        '<saml:Conditions NotOnOrAfter="2099-01-01T00:00:00Z">'
        "<saml:AudienceRestriction><saml:Audience>https://sp.example.com/metadata</saml:Audience>"
        "</saml:AudienceRestriction></saml:Conditions>"
    )
    subject_confirmation = (
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        '<saml:SubjectConfirmationData Recipient="https://sp.example.com/acs" '
        'NotOnOrAfter="2099-01-01T00:00:00Z" InResponseTo="_req1"/></saml:SubjectConfirmation>'
    )
    signed = sign_assertion_response(
        conditions=conditions,
        subject_confirmation=subject_confirmation,
        response_attributes='Destination="https://sp.example.com/acs" InResponseTo="_req1"',
    )
    sp = _sp(_idp_metadata(_cert_body(signed.cert_pem)), clock=None)
    with pytest.raises(NotImplementedError):
        sp.process_response(_b64(signed.response_xml), expected_in_response_to="_req1")
