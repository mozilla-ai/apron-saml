from datetime import UTC, datetime, timedelta, timezone

import pytest

from apron_saml.errors import MalformedResponseError
from apron_saml.timestamps import has_expired, is_not_yet_valid, parse_instant, require_aware

_NOW = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
_SKEW = timedelta(minutes=3)
_ZERO = timedelta(0)
_MICROSECOND = timedelta(microseconds=1)


# --- parse_instant -----------------------------------------------------------------------------


def test_parses_utc_designator() -> None:
    assert parse_instant("2024-01-01T13:00:00Z", field="x") == datetime(2024, 1, 1, 13, tzinfo=UTC)


def test_rejects_naive_value_with_field_in_message() -> None:
    with pytest.raises(MalformedResponseError, match="assertion Conditions NotBefore"):
        parse_instant("2024-01-01T13:00:00", field="assertion Conditions NotBefore")


def test_rejects_unparseable_value() -> None:
    with pytest.raises(MalformedResponseError):
        parse_instant("soon", field="x")


# --- require_aware -----------------------------------------------------------------------------


def test_require_aware_rejects_naive_now() -> None:
    with pytest.raises(ValueError):
        require_aware(datetime(2024, 1, 1))


def test_require_aware_accepts_aware_now() -> None:
    require_aware(datetime(2024, 1, 1, tzinfo=UTC))  # no raise.


def test_require_aware_accepts_a_non_utc_offset() -> None:
    # The contract is timezone-awareness, not UTC specifically; an offset instant compares correctly.
    require_aware(datetime(2024, 1, 1, tzinfo=timezone(timedelta(hours=2))))  # no raise.


# --- has_expired (NotOnOrAfter: exclusive bound, exclusive skew edge) ----------------------------


def test_not_expired_well_inside_the_window() -> None:
    assert not has_expired(_NOW, _NOW + timedelta(hours=1), _ZERO)


def test_expired_at_the_bound_with_zero_skew() -> None:
    # The bound is exclusive, so now == expiry is already outside.
    assert has_expired(_NOW, _NOW, _ZERO)


def test_not_expired_one_microsecond_before_the_bound() -> None:
    assert not has_expired(_NOW, _NOW + _MICROSECOND, _ZERO)


def test_expired_exactly_at_the_far_skew_edge() -> None:
    assert has_expired(_NOW, _NOW - _SKEW, _SKEW)


def test_not_expired_one_microsecond_inside_the_skew_edge() -> None:
    assert not has_expired(_NOW, _NOW - _SKEW + _MICROSECOND, _SKEW)


def test_far_future_expiry_does_not_overflow() -> None:
    # A "never expires" bound near the representable limit must not raise.
    assert not has_expired(_NOW, datetime(9999, 12, 31, 23, 59, 59, tzinfo=UTC), _SKEW)


# --- is_not_yet_valid (NotBefore: inclusive bound, inclusive skew edge) --------------------------


def test_valid_well_after_not_before() -> None:
    assert not is_not_yet_valid(_NOW, _NOW - timedelta(hours=1), _ZERO)


def test_valid_exactly_at_the_bound_with_zero_skew() -> None:
    # The bound is inclusive, so now == not_before is inside.
    assert not is_not_yet_valid(_NOW, _NOW, _ZERO)


def test_not_yet_valid_one_microsecond_before_the_bound() -> None:
    assert is_not_yet_valid(_NOW, _NOW + _MICROSECOND, _ZERO)


def test_valid_exactly_at_the_far_skew_edge() -> None:
    # The skew edge is inclusive here, mirroring the exclusive edge on has_expired.
    assert not is_not_yet_valid(_NOW, _NOW + _SKEW, _SKEW)


def test_not_yet_valid_one_microsecond_outside_the_skew_edge() -> None:
    assert is_not_yet_valid(_NOW, _NOW + _SKEW + _MICROSECOND, _SKEW)


def test_distant_past_not_before_does_not_overflow() -> None:
    assert not is_not_yet_valid(_NOW, datetime(1, 1, 1, tzinfo=UTC), _SKEW)
