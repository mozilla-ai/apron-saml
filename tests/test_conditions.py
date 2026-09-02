from datetime import UTC, datetime, timedelta
from xml.etree.ElementTree import Element

import pytest
from defusedxml.ElementTree import fromstring

from apron_saml.conditions import validate_conditions
from apron_saml.errors import AssertionExpiredError, AudienceMismatchError, MalformedResponseError

_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
_NOW = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
_SKEW = timedelta(minutes=3)
_SP = "https://sp.example.com/metadata"

# A validity window comfortably around _NOW and an AudienceRestriction naming _SP.
_WINDOW = 'NotBefore="2024-01-01T11:00:00Z" NotOnOrAfter="2024-01-01T13:00:00Z"'
_AUDIENCE = f"<saml:AudienceRestriction><saml:Audience>{_SP}</saml:Audience></saml:AudienceRestriction>"


def _assertion(conditions: str) -> Element:
    return fromstring(f'<saml:Assertion xmlns:saml="{_SAML}" ID="_a1">{conditions}</saml:Assertion>')


def _check(conditions: str, *, audience: str = _SP, now: datetime = _NOW, skew: timedelta = _SKEW) -> None:
    validate_conditions(_assertion(conditions), audience=audience, now=now, clock_skew=skew)


def _conditions(inner: str = _AUDIENCE, *, window: str = _WINDOW) -> str:
    return f"<saml:Conditions {window}>{inner}</saml:Conditions>"


# --- happy paths -----------------------------------------------------------------------------------


def test_valid_window_and_audience_passes() -> None:
    _check(_conditions())  # no raise.


def test_not_before_is_optional() -> None:
    _check(_conditions(window='NotOnOrAfter="2024-01-01T13:00:00Z"'))  # no raise.


def test_within_skew_after_expiry_passes() -> None:
    # NotOnOrAfter is 11:58; +3min skew = 12:01 (exclusive), and now is 12:00 -> still valid.
    _check(_conditions(window='NotOnOrAfter="2024-01-01T11:58:00Z"'))  # no raise.


def test_within_skew_before_not_before_passes() -> None:
    # NotBefore is 12:02; -3min skew = 11:59, and now is 12:00 -> already valid.
    _check(_conditions(window='NotBefore="2024-01-01T12:02:00Z" NotOnOrAfter="2024-01-01T13:00:00Z"'))


def test_proxy_restriction_is_accepted() -> None:
    inner = _AUDIENCE + '<saml:ProxyRestriction Count="0"/>'
    _check(_conditions(inner))  # no raise: a terminal SP never re-asserts.


def test_multiple_audiences_within_one_restriction_passes() -> None:
    inner = (
        "<saml:AudienceRestriction>"
        "<saml:Audience>https://other.example/sp</saml:Audience>"
        f"<saml:Audience>{_SP}</saml:Audience>"
        "</saml:AudienceRestriction>"
    )
    _check(_conditions(inner))  # no raise.


def test_multiple_restrictions_all_naming_sp_passes() -> None:
    inner = _AUDIENCE + _AUDIENCE
    _check(_conditions(inner))  # no raise.


# --- validity window rejections --------------------------------------------------------------------


def test_expired_rejected() -> None:
    with pytest.raises(AssertionExpiredError):
        _check(_conditions(window='NotOnOrAfter="2024-01-01T11:00:00Z"'))


def test_not_yet_valid_rejected() -> None:
    with pytest.raises(AssertionExpiredError):
        _check(_conditions(window='NotBefore="2024-01-01T13:00:00Z" NotOnOrAfter="2024-01-01T14:00:00Z"'))


def test_missing_conditions_rejected() -> None:
    with pytest.raises(MalformedResponseError):
        _check("")


def test_missing_not_on_or_after_rejected() -> None:
    with pytest.raises(MalformedResponseError):
        _check(_conditions(window='NotBefore="2024-01-01T11:00:00Z"'))


def test_inverted_window_rejected() -> None:
    with pytest.raises(MalformedResponseError):
        _check(_conditions(window='NotBefore="2024-01-01T13:00:00Z" NotOnOrAfter="2024-01-01T11:00:00Z"'))


def test_naive_timestamp_rejected() -> None:
    with pytest.raises(MalformedResponseError):
        _check(_conditions(window='NotOnOrAfter="2024-01-01T13:00:00"'))


def test_unparseable_timestamp_rejected() -> None:
    with pytest.raises(MalformedResponseError):
        _check(_conditions(window='NotOnOrAfter="not-a-timestamp"'))


# --- audience rejections ---------------------------------------------------------------------------


def test_audience_mismatch_rejected() -> None:
    inner = (
        "<saml:AudienceRestriction><saml:Audience>https://other.example/sp</saml:Audience></saml:AudienceRestriction>"
    )
    with pytest.raises(AudienceMismatchError):
        _check(_conditions(inner))


def test_no_audience_restriction_rejected() -> None:
    with pytest.raises(AudienceMismatchError):
        _check(_conditions(""))


def test_sp_missing_from_one_of_several_restrictions_rejected() -> None:
    other = (
        "<saml:AudienceRestriction><saml:Audience>https://other.example/sp</saml:Audience></saml:AudienceRestriction>"
    )
    with pytest.raises(AudienceMismatchError):
        _check(_conditions(_AUDIENCE + other))


# --- unevaluable-condition rejections --------------------------------------------------------------


def test_one_time_use_rejected() -> None:
    # OneTimeUse demands single-use enforcement, which needs the replay store (#24); reject until then.
    with pytest.raises(MalformedResponseError):
        _check(_conditions(_AUDIENCE + "<saml:OneTimeUse/>"))


def test_unknown_condition_rejected() -> None:
    inner = _AUDIENCE + '<saml:Condition xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="x:Custom"/>'
    with pytest.raises(MalformedResponseError):
        _check(_conditions(inner))
