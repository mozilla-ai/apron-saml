from unittest.mock import patch

import pytest
from signing_support import sign_assertion_response

from apron_saml import IdPDescriptor
from apron_saml.errors import MalformedResponseError
from apron_saml.validation import validate_and_extract


def _idp(cert_pem: str) -> IdPDescriptor:
    body = "".join(cert_pem.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").split())
    return IdPDescriptor(
        entity_id="https://idp.example.com/entity", sso_url="https://idp.example.com/sso", signing_certificates=(body,)
    )


def test_wrapping_runs_before_signature_verification() -> None:
    # Nest a second assertion in Advice: parse_response still sees exactly one DIRECT-CHILD assertion
    # (so it passes), and wrapping's document-wide check is what rejects — proving order.
    signed = sign_assertion_response()
    wrapped = signed.response_xml.replace(
        "</saml:Subject></saml:Assertion>",
        '</saml:Subject><saml:Advice><saml:Assertion ID="_a2"/></saml:Advice></saml:Assertion>',
    )
    with patch("apron_saml.validation.verify_assertion_signature") as verify, pytest.raises(MalformedResponseError):
        validate_and_extract(
            wrapped,
            config=None,
            idp=_idp(signed.cert_pem),
            clock=None,
            assertion_store=None,
            expected_in_response_to=None,
        )
    verify.assert_not_called()
