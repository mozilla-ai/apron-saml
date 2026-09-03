from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from signing_support import sign_assertion_response

from apron_saml import IdPDescriptor, SamlConfig
from apron_saml.errors import MalformedResponseError, SignatureError
from apron_saml.validation import validate_and_extract

_NOW = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
_SP = "https://sp.example.com/metadata"
_SKEW = timedelta(minutes=7)


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


def _validate(response_xml: str, cert_pem: str) -> None:
    validate_and_extract(
        response_xml,
        SamlConfig(
            entity_id=_SP,
            acs_url="https://sp.example.com/acs",
            idp_metadata="<EntityDescriptor/>",
            clock_skew=_SKEW,
        ),
        _idp(cert_pem),
        clock=_FixedClock(_NOW),
        assertion_store=None,
        expected_in_response_to=None,
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
        _validate(wrapped, signed.cert_pem)
    verify.assert_not_called()


def test_conditions_do_not_run_when_signature_verification_fails() -> None:
    # Tampering breaks the signature, so the Conditions check must never be reached.
    signed = sign_assertion_response()
    tampered = signed.response_xml.replace("user@example.com", "attacker@evil.example")
    with patch("apron_saml.validation.validate_conditions") as conditions, pytest.raises(SignatureError):
        _validate(tampered, signed.cert_pem)
    conditions.assert_not_called()


def test_conditions_run_once_the_signature_verifies() -> None:
    # The same pipeline reaches the Conditions check when the signature is intact, and it is handed
    # the configured audience, the configured skew, and the injected clock's instant.
    signed = sign_assertion_response()
    with patch("apron_saml.validation.validate_conditions") as conditions, pytest.raises(NotImplementedError):
        _validate(signed.response_xml, signed.cert_pem)
    conditions.assert_called_once()
    assert conditions.call_args.kwargs == {"audience": _SP, "now": _NOW, "clock_skew": _SKEW}


def test_conditions_failure_surfaces_from_the_pipeline() -> None:
    # Unpatched, the signed fixture carries no <Conditions>, so the real check rejects it.
    signed = sign_assertion_response()
    with pytest.raises(MalformedResponseError):
        _validate(signed.response_xml, signed.cert_pem)
