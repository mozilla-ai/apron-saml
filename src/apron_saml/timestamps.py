"""Parsing and comparison of the timestamps SAML validation depends on (internal).

Holds the timestamp handling shared by the assertion's ``<Conditions>`` and its
``<SubjectConfirmationData>``. Both carry independent validity windows with the same lexical syntax
and the same boundary semantics, so the parsing and the window predicates live here once rather than
being restated by each caller.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from apron_saml.errors import MalformedResponseError


def parse_instant(value: str, *, field: str) -> datetime:
    """Parse a SAML timestamp attribute into a timezone-aware datetime.

    The accepted syntax overlaps ``xs:dateTime`` rather than containing it.
    Every shape mainstream identity providers emit is admitted — trailing ``Z``, numeric offsets, and
    fractional seconds — while a few schema-valid forms are refused, notably end-of-day ``24:00:00``,
    whose acceptance additionally varies across interpreter versions.
    A refused value fails closed as malformed rather than being reinterpreted.
    A timezone-unqualified value is rejected, because SAML requires an explicit UTC designator or offset
    and comparing a naive instant would be ambiguous.
    Fractional seconds finer than a microsecond are truncated, since that is the resolution ``datetime``
    can represent; the effect is bounded below one microsecond.

    Args:
        value: The raw attribute value.
        field: Domain name of the attribute for the error message, such as ``assertion Conditions NotBefore``.

    Returns:
        The parsed instant, timezone-aware.

    Raises:
        MalformedResponseError: If the value cannot be parsed, is out of the representable range, or
            carries no timezone.
    """
    try:
        parsed = datetime.fromisoformat(value.strip())
    except (ValueError, OverflowError) as e:
        raise MalformedResponseError(f"{field} is not a valid timestamp") from e
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MalformedResponseError(f"{field} is not timezone-qualified")
    return parsed


def require_aware(now: datetime) -> None:
    """Reject a timezone-naive current time, which breaks the time-source contract.

    Any timezone-aware instant is accepted. A non-UTC offset compares correctly against the parsed
    bounds, so requiring UTC specifically would reject a usable clock for no benefit.

    Args:
        now: The current time as reported by the configured time source.

    Raises:
        ValueError: If ``now`` carries no timezone.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("the time source returned a naive datetime; it must return a timezone-aware datetime")


def has_expired(now: datetime, expiry: datetime, clock_skew: timedelta) -> bool:
    """Report whether ``now`` has reached an exclusive ``NotOnOrAfter`` bound, allowing for skew.

    The bound is exclusive, so an instant exactly at ``expiry`` is already outside the window and is
    admitted only by the skew allowance. The allowance is itself exclusive at its far edge: ``now``
    exactly at ``expiry`` plus ``clock_skew`` has expired.

    The comparison is expressed as a difference against ``now`` rather than by shifting ``expiry`` by
    ``clock_skew``. Shifting a bound near the representable limits of ``datetime`` raises
    ``OverflowError``, and a "never expires" bound in the year 9999 is a shape identity providers
    really emit, so the arithmetic is arranged to make that unreachable.

    Args:
        now: The current time, timezone-aware.
        expiry: The parsed ``NotOnOrAfter`` bound.
        clock_skew: Non-negative allowance for clock drift.

    Returns:
        True if the window has closed.
    """
    return now >= expiry and now - expiry >= clock_skew


def is_not_yet_valid(now: datetime, not_before: datetime, clock_skew: timedelta) -> bool:
    """Report whether ``now`` precedes an inclusive ``NotBefore`` bound, allowing for skew.

    The bound is inclusive, so an instant exactly at ``not_before`` is inside the window. The skew
    allowance is inclusive at its far edge too: ``now`` exactly at ``not_before`` minus ``clock_skew``
    is admitted. This is deliberately the mirror of ``has_expired``, whose bound is exclusive at both
    edges, and the asymmetry is the one SAML defines rather than an oversight.

    The difference is taken against ``now`` for the same overflow reason given on ``has_expired``.

    Args:
        now: The current time, timezone-aware.
        not_before: The parsed ``NotBefore`` bound.
        clock_skew: Non-negative allowance for clock drift.

    Returns:
        True if the window has not opened yet.
    """
    return now < not_before and not_before - now > clock_skew
