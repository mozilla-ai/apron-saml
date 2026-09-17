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
from apron_saml.timestamps import has_expired, is_not_yet_valid, parse_instant, require_aware

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


def _local_name(tag: str) -> str:
    """Return the local part of a namespace-qualified element tag."""
    return tag.rpartition("}")[2] or tag


def validate_conditions(assertion: Element, *, audience: str, now: datetime, clock_skew: timedelta) -> None:
    """Enforce the consumed assertion's ``<Conditions>`` against this SP and the current time.

    Every check must pass, so their order changes only which error a multiply-invalid ``<Conditions>``
    reports, never which assertions are accepted.
    The audience is checked ahead of evaluability deliberately: an assertion addressed to a different
    service provider is the more actionable signal — it is what a relayed assertion looks like — so it
    is reported even when the element also carries a condition this service provider cannot evaluate.

    Args:
        assertion: The consumed ``<Assertion>`` element.
        audience: This service provider's entity ID, which an audience restriction must name.
        now: The current time as a timezone-aware datetime.
        clock_skew: Non-negative allowance applied to both ends of the validity window.

    Raises:
        AssertionExpiredError: If ``now`` is outside the ``NotBefore``/``NotOnOrAfter`` window.
        AudienceMismatchError: If no audience restriction names this service provider.
        MalformedResponseError: If the assertion does not carry exactly one ``<Conditions>``, it lacks
            ``NotOnOrAfter``, its window is inverted or unparseable, or it carries a condition this
            service provider cannot evaluate.
        ValueError: If ``now`` is timezone-naive, which breaks the time-source contract.
    """
    require_aware(now)
    # SAML 2.0 Core §2.5.1 permits at most one <Conditions>; more than one is unevaluable. The bundled
    # assertion schema already rejects duplicates upstream, so this keeps the check self-contained
    # rather than depending on that earlier step.
    all_conditions = assertion.findall(_CONDITIONS)
    if not all_conditions:
        raise MalformedResponseError("assertion has no Conditions")
    if len(all_conditions) > 1:
        raise MalformedResponseError("assertion carries more than one Conditions")
    conditions = all_conditions[0]
    _enforce_validity_window(conditions, now=now, clock_skew=clock_skew)
    _require_audience(conditions, audience)
    _reject_unevaluable_conditions(conditions)


def _enforce_validity_window(conditions: Element, *, now: datetime, clock_skew: timedelta) -> None:
    """Require a bounded validity window and reject unless ``now`` falls inside it (skew applied).

    ``NotOnOrAfter`` is required and exclusive; ``NotBefore`` is optional and inclusive.

    Raises:
        AssertionExpiredError: If ``now`` precedes ``NotBefore`` or reaches ``NotOnOrAfter`` (skew applied).
        MalformedResponseError: If ``NotOnOrAfter`` is missing, a bound is unparseable, or the window
            is inverted.
    """
    not_on_or_after = conditions.get("NotOnOrAfter")
    if not_on_or_after is None:
        raise MalformedResponseError("assertion Conditions has no NotOnOrAfter, so its validity is unbounded")
    expiry = parse_instant(not_on_or_after, field="assertion Conditions NotOnOrAfter")
    not_before_raw = conditions.get("NotBefore")
    not_before = (
        parse_instant(not_before_raw, field="assertion Conditions NotBefore") if not_before_raw is not None else None
    )
    if not_before is not None and not_before >= expiry:
        raise MalformedResponseError("assertion Conditions NotBefore is not before NotOnOrAfter")
    if not_before is not None and is_not_yet_valid(now, not_before, clock_skew):
        raise AssertionExpiredError("assertion is not yet valid")
    if has_expired(now, expiry, clock_skew):
        raise AssertionExpiredError("assertion has expired")


def _require_audience(conditions: Element, audience: str) -> None:
    """Reject the assertion unless every audience restriction names this service provider.

    Each ``<AudienceRestriction>`` is ANDed; within one, the SP need match any ``<Audience>``. An
    audience's text is gathered across its whole subtree so a split text node cannot truncate the
    compared value, and blank audiences are discarded so they can never match.

    Raises:
        AudienceMismatchError: If there is no audience restriction, or one does not name this SP.
    """
    restrictions = conditions.findall(_AUDIENCE_RESTRICTION)
    if not restrictions:
        raise AudienceMismatchError("assertion carries no audience restriction naming this service provider")
    for restriction in restrictions:
        values = {text for a in restriction.findall(_AUDIENCE) if (text := "".join(a.itertext()).strip())}
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
                f"assertion Conditions carries a condition this service provider cannot evaluate: "
                f"{_local_name(child.tag)}"
            )
