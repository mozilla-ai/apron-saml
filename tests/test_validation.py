from datetime import UTC, datetime
from unittest.mock import patch

import pytest
from signing_support import sign_assertion_response

from apron_saml import IdPDescriptor, SamlConfig
from apron_saml.errors import MalformedResponseError
from apron_saml.validation import validate_and_extract


class _FixedClock:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


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


def test_conditions_run_after_signature_verification() -> None:
    # A validly-signed assertion with no <Conditions> passes verification, then the Conditions check
    # rejects it — proving Conditions runs after verification in the pipeline.
    signed = sign_assertion_response()
    config = SamlConfig(
        entity_id="https://sp.example.com/metadata",
        acs_url="https://sp.example.com/acs",
        idp_metadata="<EntityDescriptor/>",
    )
    with pytest.raises(MalformedResponseError):
        validate_and_extract(
            signed.response_xml,
            config=config,
            idp=_idp(signed.cert_pem),
            clock=_FixedClock(datetime(2024, 1, 1, 12, 0, tzinfo=UTC)),
            assertion_store=None,
            expected_in_response_to=None,
        )
