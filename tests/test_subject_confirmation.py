from datetime import UTC, datetime, timedelta

import pytest

from apron_saml import SamlConfig
from apron_saml.errors import (
    AssertionExpiredError,
    InResponseToError,
    MalformedResponseError,
    RecipientMismatchError,
    SamlError,
)
from apron_saml.response import ParsedResponse, parse_response
from apron_saml.subject_confirmation import validate_subject_confirmation

_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
_HOLDER_OF_KEY = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
_NOW = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
_SKEW = timedelta(minutes=3)
_ACS = "https://sp.example.com/acs"
_REQUEST_ID = "_req1"
_EXPIRY = "2024-01-01T13:00:00Z"


def _config(*, allow_idp_initiated: bool = False, skew: timedelta = _SKEW) -> SamlConfig:
    return SamlConfig(
        entity_id="https://sp.example.com/metadata",
        acs_url=_ACS,
        idp_metadata="<EntityDescriptor/>",
        clock_skew=skew,
        allow_idp_initiated=allow_idp_initiated,
    )


def _data(
    *,
    recipient: str | None = _ACS,
    not_on_or_after: str | None = _EXPIRY,
    in_response_to: str | None = _REQUEST_ID,
    not_before: str | None = None,
) -> str:
    attrs = [
        f'Recipient="{recipient}"' if recipient is not None else "",
        f'NotOnOrAfter="{not_on_or_after}"' if not_on_or_after is not None else "",
        f'InResponseTo="{in_response_to}"' if in_response_to is not None else "",
        f'NotBefore="{not_before}"' if not_before is not None else "",
    ]
    return f"<saml:SubjectConfirmationData {' '.join(a for a in attrs if a)}/>"


def _confirmation(data: str = _data(), *, method: str = _BEARER) -> str:
    return f'<saml:SubjectConfirmation Method="{method}">{data}</saml:SubjectConfirmation>'


def _parsed(
    confirmations: str = _confirmation(), *, response_attributes: str = "", subject: bool = True, subjects: int = 1
) -> ParsedResponse:
    one = f"<saml:Subject><saml:NameID>user@example.com</saml:NameID>{confirmations}</saml:Subject>"
    subject_xml = one * subjects
    xml = (
        f'<samlp:Response xmlns:samlp="{_SAMLP}" xmlns:saml="{_SAML}" ID="_r1" Version="2.0" {response_attributes}>'
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f'<saml:Assertion ID="_a1">{subject_xml if subject else ""}</saml:Assertion></samlp:Response>'
    )
    return parse_response(xml)


_SOLICITED = f'Destination="{_ACS}" InResponseTo="{_REQUEST_ID}"'


def _check(
    parsed: ParsedResponse,
    *,
    config: SamlConfig | None = None,
    expected: str | None = _REQUEST_ID,
    now: datetime = _NOW,
) -> None:
    validate_subject_confirmation(parsed, config or _config(), expected_in_response_to=expected, now=now)


# --- happy paths -----------------------------------------------------------------------------------


def test_solicited_bearer_confirmation_passes() -> None:
    _check(_parsed(response_attributes=_SOLICITED))  # no raise.


def test_response_destination_is_optional() -> None:
    _check(_parsed(response_attributes=f'InResponseTo="{_REQUEST_ID}"'))  # no raise.


def test_unsolicited_passes_when_idp_initiated_is_allowed() -> None:
    parsed = _parsed(_confirmation(_data(in_response_to=None)))
    _check(parsed, config=_config(allow_idp_initiated=True), expected=None)  # no raise.


def test_within_skew_after_expiry_passes() -> None:
    # NotOnOrAfter is 11:58; +3min skew = 12:01 (exclusive), and now is 12:00 -> still valid.
    parsed = _parsed(_confirmation(_data(not_on_or_after="2024-01-01T11:58:00Z")), response_attributes=_SOLICITED)
    _check(parsed)  # no raise.


def test_non_bearer_confirmations_are_ignored_when_a_bearer_one_passes() -> None:
    holder_of_key = _confirmation(_data(recipient="https://other.example/acs"), method=_HOLDER_OF_KEY)
    _check(_parsed(holder_of_key + _confirmation(), response_attributes=_SOLICITED))  # no raise.


def test_any_one_satisfied_bearer_confirmation_suffices() -> None:
    # Profiles §4.1.4.3: at least one bearer SubjectConfirmation must be satisfied; others are ignored.
    stale = _confirmation(_data(not_on_or_after="2024-01-01T11:00:00Z"))
    _check(_parsed(stale + _confirmation(), response_attributes=_SOLICITED))  # no raise.


# --- structural rejections -------------------------------------------------------------------------


def test_missing_subject_rejected() -> None:
    with pytest.raises(MalformedResponseError):
        _check(_parsed(subject=False, response_attributes=_SOLICITED))


def test_no_subject_confirmation_rejected() -> None:
    with pytest.raises(MalformedResponseError):
        _check(_parsed("", response_attributes=_SOLICITED))


def test_only_non_bearer_confirmation_rejected() -> None:
    holder_of_key = _confirmation(method=_HOLDER_OF_KEY)
    with pytest.raises(MalformedResponseError):
        _check(_parsed(holder_of_key, response_attributes=_SOLICITED))


def test_missing_subject_confirmation_data_rejected() -> None:
    with pytest.raises(MalformedResponseError):
        _check(_parsed(_confirmation(""), response_attributes=_SOLICITED))


def test_multiple_subject_confirmation_data_rejected() -> None:
    with pytest.raises(MalformedResponseError):
        _check(_parsed(_confirmation(_data() + _data()), response_attributes=_SOLICITED))


def test_missing_not_on_or_after_rejected() -> None:
    with pytest.raises(MalformedResponseError):
        _check(_parsed(_confirmation(_data(not_on_or_after=None)), response_attributes=_SOLICITED))


def test_unparseable_not_on_or_after_rejected() -> None:
    with pytest.raises(MalformedResponseError):
        _check(_parsed(_confirmation(_data(not_on_or_after="soon")), response_attributes=_SOLICITED))


def test_naive_not_on_or_after_rejected() -> None:
    with pytest.raises(MalformedResponseError):
        _check(_parsed(_confirmation(_data(not_on_or_after="2024-01-01T13:00:00")), response_attributes=_SOLICITED))


def test_all_bearer_confirmations_failing_reports_the_first_failure() -> None:
    stale = _confirmation(_data(not_on_or_after="2024-01-01T11:00:00Z"))
    misdirected = _confirmation(_data(recipient="https://other.example/acs"))
    with pytest.raises(AssertionExpiredError):
        _check(_parsed(stale + misdirected, response_attributes=_SOLICITED))


def test_not_before_on_bearer_confirmation_data_rejected() -> None:
    # Profiles 4.1.4.2: bearer SubjectConfirmationData MUST NOT carry NotBefore. Its presence marks a
    # nonconforming assertion whose intended semantics this SP cannot settle, so it is refused rather
    # than enforced as a lower bound.
    parsed = _parsed(_confirmation(_data(not_before="2024-01-01T11:00:00Z")), response_attributes=_SOLICITED)
    with pytest.raises(MalformedResponseError):
        _check(parsed)


def test_already_elapsed_not_before_is_still_rejected() -> None:
    # The value is never evaluated, so a NotBefore that would have passed as a lower bound is refused
    # on the same grounds as a future one.
    parsed = _parsed(_confirmation(_data(not_before="2020-01-01T00:00:00Z")), response_attributes=_SOLICITED)
    with pytest.raises(MalformedResponseError):
        _check(parsed)


def test_duplicate_subject_rejected() -> None:
    # Core 2.3.3 permits at most one Subject. Rejecting duplicates keeps this check self-contained
    # rather than relying on the upstream schema step, matching how Conditions is handled.
    with pytest.raises(MalformedResponseError):
        _check(_parsed(response_attributes=_SOLICITED, subjects=2))


def test_confirmation_without_method_is_not_bearer() -> None:
    # A Method-less SubjectConfirmation falls out of the bearer filter, leaving none to satisfy.
    no_method = f"<saml:SubjectConfirmation>{_data()}</saml:SubjectConfirmation>"
    with pytest.raises(MalformedResponseError):
        _check(_parsed(no_method, response_attributes=_SOLICITED))


def test_nested_subject_confirmation_data_is_not_found() -> None:
    # Only a direct child counts, so data buried under a wrapper leaves the confirmation without any.
    nested = (
        f'<saml:SubjectConfirmation Method="{_BEARER}"><saml:Advice>{_data()}</saml:Advice></saml:SubjectConfirmation>'
    )
    with pytest.raises(MalformedResponseError):
        _check(_parsed(nested, response_attributes=_SOLICITED))


# --- recipient and destination rejections ----------------------------------------------------------


def test_recipient_mismatch_rejected() -> None:
    parsed = _parsed(_confirmation(_data(recipient="https://other.example/acs")), response_attributes=_SOLICITED)
    with pytest.raises(RecipientMismatchError):
        _check(parsed)


def test_missing_recipient_rejected() -> None:
    with pytest.raises(RecipientMismatchError):
        _check(_parsed(_confirmation(_data(recipient=None)), response_attributes=_SOLICITED))


@pytest.mark.parametrize("recipient", [_ACS.upper(), _ACS + "/", _ACS + " ", "https://sp.example.com/acs?x=1"])
def test_recipient_comparison_is_exact(recipient: str) -> None:
    parsed = _parsed(_confirmation(_data(recipient=recipient)), response_attributes=_SOLICITED)
    with pytest.raises(RecipientMismatchError):
        _check(parsed)


def test_response_destination_mismatch_rejected() -> None:
    attrs = f'Destination="https://other.example/acs" InResponseTo="{_REQUEST_ID}"'
    with pytest.raises(RecipientMismatchError):
        _check(_parsed(response_attributes=attrs))


# --- expiry rejections -----------------------------------------------------------------------------


def test_expired_rejected() -> None:
    parsed = _parsed(_confirmation(_data(not_on_or_after="2024-01-01T11:00:00Z")), response_attributes=_SOLICITED)
    with pytest.raises(AssertionExpiredError):
        _check(parsed)


def test_not_on_or_after_is_exclusive_at_zero_skew() -> None:
    parsed = _parsed(_confirmation(_data(not_on_or_after="2024-01-01T12:00:00Z")), response_attributes=_SOLICITED)
    with pytest.raises(AssertionExpiredError):
        _check(parsed, config=_config(skew=timedelta(0)))


def test_exact_upper_skew_boundary_rejected() -> None:
    # now == NotOnOrAfter + skew must reject (11:57 + 3min == 12:00 == now).
    parsed = _parsed(_confirmation(_data(not_on_or_after="2024-01-01T11:57:00Z")), response_attributes=_SOLICITED)
    with pytest.raises(AssertionExpiredError):
        _check(parsed)


def test_one_microsecond_inside_upper_skew_boundary_passes() -> None:
    parsed = _parsed(
        _confirmation(_data(not_on_or_after="2024-01-01T11:57:00.000001Z")), response_attributes=_SOLICITED
    )
    _check(parsed)  # no raise.


def test_far_future_expiry_does_not_overflow() -> None:
    parsed = _parsed(_confirmation(_data(not_on_or_after="9999-12-31T23:59:59Z")), response_attributes=_SOLICITED)
    _check(parsed)  # no raise.


# --- InResponseTo rejections -----------------------------------------------------------------------


def test_in_response_to_mismatch_rejected() -> None:
    parsed = _parsed(_confirmation(_data(in_response_to="_other")), response_attributes=_SOLICITED)
    with pytest.raises(InResponseToError):
        _check(parsed)


def test_solicited_response_without_in_response_to_rejected() -> None:
    parsed = _parsed(_confirmation(_data(in_response_to=None)), response_attributes=_SOLICITED)
    with pytest.raises(InResponseToError):
        _check(parsed)


def test_in_response_to_comparison_is_exact() -> None:
    parsed = _parsed(_confirmation(_data(in_response_to=_REQUEST_ID.upper())), response_attributes=_SOLICITED)
    with pytest.raises(InResponseToError):
        _check(parsed)


def test_response_in_response_to_mismatch_rejected() -> None:
    attrs = f'Destination="{_ACS}" InResponseTo="_other"'
    with pytest.raises(InResponseToError):
        _check(_parsed(response_attributes=attrs))


def test_solicited_response_missing_response_in_response_to_rejected() -> None:
    # Profiles §4.1.4.2: a Response answering a request MUST carry the request's ID.
    with pytest.raises(InResponseToError):
        _check(_parsed(response_attributes=f'Destination="{_ACS}"'))


def test_unsolicited_rejected_by_default() -> None:
    parsed = _parsed(_confirmation(_data(in_response_to=None)))
    with pytest.raises(InResponseToError):
        _check(parsed, expected=None)


def test_unsolicited_with_in_response_to_rejected() -> None:
    # An unsolicited response must not claim to answer a request this SP never issued.
    with pytest.raises(InResponseToError):
        _check(_parsed(), config=_config(allow_idp_initiated=True), expected=None)


def test_unsolicited_with_response_in_response_to_rejected() -> None:
    parsed = _parsed(_confirmation(_data(in_response_to=None)), response_attributes=f'InResponseTo="{_REQUEST_ID}"')
    with pytest.raises(InResponseToError):
        _check(parsed, config=_config(allow_idp_initiated=True), expected=None)


def test_solicited_response_ignores_allow_idp_initiated() -> None:
    # Allowing unsolicited responses never relaxes matching when a request ID is expected.
    parsed = _parsed(_confirmation(_data(in_response_to=None)), response_attributes=_SOLICITED)
    with pytest.raises(InResponseToError):
        _check(parsed, config=_config(allow_idp_initiated=True))


# --- caller contract -------------------------------------------------------------------------------


def test_naive_now_is_a_time_source_contract_error() -> None:
    with pytest.raises(ValueError) as exc:
        _check(_parsed(response_attributes=_SOLICITED), now=datetime(2024, 1, 1, 12, 0, 0))
    assert not isinstance(exc.value, SamlError)


def test_blank_expected_in_response_to_is_a_contract_error() -> None:
    with pytest.raises(ValueError) as exc:
        _check(_parsed(response_attributes=_SOLICITED), expected="  ")
    assert not isinstance(exc.value, SamlError)
