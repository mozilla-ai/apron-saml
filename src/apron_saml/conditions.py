"""Enforcement of a SAML assertion's ``<Conditions>`` — validity window and audience (internal).

Applies the SP-side processing rules of SAML 2.0 Core §2.5.1: the assertion's validity window
(``NotBefore``/``NotOnOrAfter`` with a bounded clock skew) and its audience restriction. The policy
is fail-closed: a ``<Conditions>`` whose outcome is Invalid or Indeterminate is rejected, so an
assertion without a bounded expiry, without an audience restriction naming this SP, or carrying a
condition this SP cannot evaluate (``OneTimeUse``, a custom ``<Condition>``) is not trusted.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from xml.etree.ElementTree import Element

from apron_saml.errors import AssertionExpiredError, AudienceMismatchError, MalformedResponseError

_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_CONDITIONS = f"{{{_SAML_NS}}}Conditions"
_AUDIENCE_RESTRICTION = f"{{{_SAML_NS}}}AudienceRestriction"
_AUDIENCE = f"{{{_SAML_NS}}}Audience"
_PROXY_RESTRICTION = f"{{{_SAML_NS}}}ProxyRestriction"
# Condition child elements this SP can affirmatively evaluate as Valid. ``ProxyRestriction`` only
# limits issuing further assertions from this one, which a terminal SP never does, so it is trivially
# satisfied. Any other child (``OneTimeUse``, a custom ``<Condition xsi:type=...>``) is Indeterminate
# and rejected fail-closed; single-use enforcement of ``OneTimeUse`` needs the replay store (#24).
_EVALUABLE_CONDITIONS = frozenset({_AUDIENCE_RESTRICTION, _PROXY_RESTRICTION})


def _parse_instant(value: str, attribute: str) -> datetime:
    """Parse a SAML ``xs:dateTime`` attribute into a timezone-aware datetime.

    Raises:
        MalformedResponseError: If the value is not a valid, timezone-qualified ``xs:dateTime``.
    """
    try:
        parsed = datetime.fromisoformat(value.strip())
    except ValueError as e:
        raise MalformedResponseError(f"assertion Conditions {attribute} is not a valid timestamp") from e
    if parsed.tzinfo is None:
        raise MalformedResponseError(f"assertion Conditions {attribute} is not timezone-qualified")
    return parsed


def validate_conditions(assertion: Element, *, audience: str, now: datetime, clock_skew: timedelta) -> None:
    """Enforce the consumed assertion's ``<Conditions>`` against this SP and the current time.

    Args:
        assertion: The consumed ``<Assertion>`` element.
        audience: This service provider's entity ID, which an audience restriction must name.
        now: The current time as a timezone-aware datetime.
        clock_skew: Non-negative allowance applied to both ends of the validity window.

    Raises:
        AssertionExpiredError: If ``now`` is outside the ``NotBefore``/``NotOnOrAfter`` window.
        AudienceMismatchError: If no audience restriction names this service provider.
        MalformedResponseError: If ``<Conditions>`` is absent, lacks ``NotOnOrAfter``, carries an
            inverted or unparseable window, or carries a condition this SP cannot evaluate.
    """
    conditions = assertion.find(_CONDITIONS)
    if conditions is None:
        raise MalformedResponseError("assertion has no Conditions")
    _reject_outside_validity_window(conditions, now=now, clock_skew=clock_skew)
    _require_audience(conditions, audience)
    _reject_unevaluable_conditions(conditions)


def _reject_outside_validity_window(conditions: Element, *, now: datetime, clock_skew: timedelta) -> None:
    """Reject the assertion unless ``now`` falls within its (skew-widened) validity window.

    ``NotOnOrAfter`` is required and exclusive; ``NotBefore`` is optional and inclusive.

    Raises:
        AssertionExpiredError: If ``now`` is before ``NotBefore`` or at/after ``NotOnOrAfter`` (skew applied).
        MalformedResponseError: If ``NotOnOrAfter`` is missing, a bound is unparseable, or the window is inverted.
    """
    not_on_or_after = conditions.get("NotOnOrAfter")
    if not_on_or_after is None:
        raise MalformedResponseError("assertion Conditions has no NotOnOrAfter, so its validity is unbounded")
    expiry = _parse_instant(not_on_or_after, "NotOnOrAfter")
    not_before_raw = conditions.get("NotBefore")
    not_before = _parse_instant(not_before_raw, "NotBefore") if not_before_raw is not None else None
    if not_before is not None and not_before >= expiry:
        raise MalformedResponseError("assertion Conditions NotBefore is not before NotOnOrAfter")
    if not_before is not None and now < not_before - clock_skew:
        raise AssertionExpiredError("assertion is not yet valid")
    if now >= expiry + clock_skew:
        raise AssertionExpiredError("assertion has expired")


def _require_audience(conditions: Element, audience: str) -> None:
    """Reject the assertion unless every audience restriction names this service provider.

    Each ``<AudienceRestriction>`` is ANDed; within one, the SP need match any ``<Audience>``.

    Raises:
        AudienceMismatchError: If there is no audience restriction, or one does not name this SP.
    """
    restrictions = conditions.findall(_AUDIENCE_RESTRICTION)
    if not restrictions:
        raise AudienceMismatchError("assertion carries no audience restriction naming this service provider")
    for restriction in restrictions:
        values = {(a.text or "").strip() for a in restriction.findall(_AUDIENCE)}
        if audience not in values:
            raise AudienceMismatchError("assertion audience restriction does not name this service provider")


def _reject_unevaluable_conditions(conditions: Element) -> None:
    """Reject the assertion if ``<Conditions>`` carries a condition this SP cannot evaluate (Indeterminate).

    Raises:
        MalformedResponseError: If any child is not one of the evaluable condition types.
    """
    for child in conditions:
        if child.tag not in _EVALUABLE_CONDITIONS:
            raise MalformedResponseError(
                "assertion Conditions carries a condition this service provider cannot evaluate"
            )
