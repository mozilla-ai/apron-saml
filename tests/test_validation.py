from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from signing_support import sign_assertion_response

from apron_saml import IdPDescriptor, SamlConfig
from apron_saml.errors import (
    AssertionExpiredError,
    AudienceMismatchError,
    InResponseToError,
    MalformedResponseError,
    RecipientMismatchError,
    SignatureError,
)
from apron_saml.validation import validate_and_extract

_NOW = datetime(2024, 1, 1, 12, 0, tzinfo=UTC)
_SP = "https://sp.example.com/metadata"
_SKEW = timedelta(minutes=7)
_ACS = "https://sp.example.com/acs"
_REQUEST_ID = "_req1"


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


def _config() -> SamlConfig:
    return SamlConfig(entity_id=_SP, acs_url=_ACS, idp_metadata="<EntityDescriptor/>", clock_skew=_SKEW)


def _validate(response_xml: str, cert_pem: str, *, expected_in_response_to: str | None = _REQUEST_ID) -> None:
    validate_and_extract(
        response_xml,
        _config(),
        _idp(cert_pem),
        clock=_FixedClock(_NOW),
        assertion_store=None,
        expected_in_response_to=expected_in_response_to,
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
    with (
        patch("apron_saml.validation.validate_conditions") as conditions,
        patch("apron_saml.validation.validate_subject_confirmation"),
        pytest.raises(NotImplementedError),
    ):
        _validate(signed.response_xml, signed.cert_pem)
    conditions.assert_called_once()
    assert conditions.call_args.kwargs == {"audience": _SP, "now": _NOW, "clock_skew": _SKEW}


def test_conditions_failure_surfaces_from_the_pipeline() -> None:
    # Unpatched, the signed fixture carries no <Conditions>, so the real check rejects it.
    signed = sign_assertion_response()
    with pytest.raises(MalformedResponseError):
        _validate(signed.response_xml, signed.cert_pem)


def _conditions(*, audience: str = _SP, window: str = 'NotOnOrAfter="2024-01-01T13:00:00Z"') -> str:
    return (
        f"<saml:Conditions {window}>"
        f"<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>"
        f"</saml:Conditions>"
    )


def _subject_confirmation(*, recipient: str = _ACS, in_response_to: str | None = _REQUEST_ID) -> str:
    in_response_to_attr = f' InResponseTo="{in_response_to}"' if in_response_to is not None else ""
    return (
        '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData Recipient="{recipient}" NotOnOrAfter="2024-01-01T12:05:00Z"'
        f"{in_response_to_attr}/></saml:SubjectConfirmation>"
    )


_SOLICITED = f'Destination="{_ACS}" InResponseTo="{_REQUEST_ID}"'


def _signed_valid(
    *,
    conditions: str | None = None,
    subject_confirmation: str | None = None,
    response_attributes: str = _SOLICITED,
) -> tuple[str, str]:
    signed = sign_assertion_response(
        conditions=_conditions() if conditions is None else conditions,
        subject_confirmation=_subject_confirmation() if subject_confirmation is None else subject_confirmation,
        response_attributes=response_attributes,
    )
    return signed.response_xml, signed.cert_pem


def test_valid_conditions_pass_the_whole_pipeline() -> None:
    # A signed assertion carrying a schema-valid <Conditions> clears wrapping, signature verification,
    # and the Conditions check; the fixture carries no SubjectConfirmation, so that check is what
    # rejects, proving the pipeline continued past Conditions.
    signed = sign_assertion_response(conditions=_conditions(), response_attributes=_SOLICITED)
    with pytest.raises(MalformedResponseError):
        _validate(signed.response_xml, signed.cert_pem)


def test_subject_confirmation_does_not_run_when_conditions_fail() -> None:
    signed = sign_assertion_response(conditions=_conditions(audience="https://other.example/sp"))
    with (
        patch("apron_saml.validation.validate_subject_confirmation") as confirmation,
        pytest.raises(AudienceMismatchError),
    ):
        _validate(signed.response_xml, signed.cert_pem)
    confirmation.assert_not_called()


def test_subject_confirmation_runs_after_conditions_with_the_same_instant() -> None:
    # Both time-based checks must compare against one clock reading, and the check receives the
    # configuration and the caller's outstanding request ID.
    signed = sign_assertion_response(conditions=_conditions())
    with (
        patch("apron_saml.validation.validate_subject_confirmation") as confirmation,
        pytest.raises(NotImplementedError),
    ):
        _validate(signed.response_xml, signed.cert_pem)
    confirmation.assert_called_once()
    assert confirmation.call_args.args[1] == _config()
    assert confirmation.call_args.kwargs == {"expected_in_response_to": _REQUEST_ID, "now": _NOW}


def test_fully_valid_response_passes_the_whole_pipeline() -> None:
    # The one positive path: wrapping, signature, Conditions, and SubjectConfirmation all clear,
    # stopping only at the not-yet-implemented remainder.
    response_xml, cert_pem = _signed_valid()
    with pytest.raises(NotImplementedError):
        _validate(response_xml, cert_pem)


def test_foreign_recipient_rejected_by_the_whole_pipeline() -> None:
    response_xml, cert_pem = _signed_valid(
        subject_confirmation=_subject_confirmation(recipient="https://other.example/acs")
    )
    with pytest.raises(RecipientMismatchError):
        _validate(response_xml, cert_pem)


def test_wrong_request_id_rejected_by_the_whole_pipeline() -> None:
    response_xml, cert_pem = _signed_valid()
    with pytest.raises(InResponseToError):
        _validate(response_xml, cert_pem, expected_in_response_to="_other")


def test_unsolicited_response_rejected_by_the_whole_pipeline_by_default() -> None:
    response_xml, cert_pem = _signed_valid(
        subject_confirmation=_subject_confirmation(in_response_to=None), response_attributes=f'Destination="{_ACS}"'
    )
    with pytest.raises(InResponseToError):
        _validate(response_xml, cert_pem, expected_in_response_to=None)


def test_expired_conditions_rejected_by_the_whole_pipeline() -> None:
    signed = sign_assertion_response(conditions=_conditions(window='NotOnOrAfter="2024-01-01T11:00:00Z"'))
    with pytest.raises(AssertionExpiredError):
        _validate(signed.response_xml, signed.cert_pem)


def test_foreign_audience_rejected_by_the_whole_pipeline() -> None:
    signed = sign_assertion_response(conditions=_conditions(audience="https://other.example/sp"))
    with pytest.raises(AudienceMismatchError):
        _validate(signed.response_xml, signed.cert_pem)
