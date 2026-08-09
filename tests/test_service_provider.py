import base64
import warnings

import pytest
from signing_support import sign_assertion_response

from apron_saml import MetadataError, SamlConfig, ServiceProvider, SignatureError

_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"


def _idp_metadata(cert_pem: str | None = None) -> str:
    key_descriptor = ""
    if cert_pem is not None:
        body = "".join(
            cert_pem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").split()
        )
        key_descriptor = (
            f'<KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data>'
            f"<ds:X509Certificate>{body}</ds:X509Certificate>"
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


def test_warns_when_assertion_signing_relaxed() -> None:
    with pytest.warns(UserWarning, match="want_assertions_signed"):
        _sp(_idp_metadata(), want_assertions_signed=False)


def test_silent_when_assertion_signing_required() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        _sp(_idp_metadata())  # default True -> no warning


def test_construction_fails_fast_on_bad_metadata() -> None:
    with pytest.raises(MetadataError):
        _sp("<not-entity-descriptor/>")


def test_process_response_rejects_tampered_signature() -> None:
    signed = sign_assertion_response()
    sp = _sp(_idp_metadata(signed.cert_pem))
    tampered = signed.response_xml.replace("user@example.com", "attacker@evil.example")
    with pytest.raises(SignatureError):
        sp.process_response(_b64(tampered))


def test_process_response_valid_signature_reaches_unimplemented_steps() -> None:
    signed = sign_assertion_response()
    sp = _sp(_idp_metadata(signed.cert_pem))
    with pytest.raises(NotImplementedError):
        sp.process_response(_b64(signed.response_xml))
