"""Enforcement of bearer ``<SubjectConfirmation>`` and the Response's addressing (internal).

Applies the SP-side processing rules of SAML 2.0 Core §2.4.1.1–§2.4.1.2 as profiled for Web Browser SSO
(Profiles §4.1.4.2–§4.1.4.3): a bearer confirmation must name this SP's assertion consumer URL as
``Recipient``, must carry a bounded ``NotOnOrAfter``, must not carry ``NotBefore``, and must answer the
outstanding authentication request via ``InResponseTo`` — or carry none when the response is
unsolicited. The ``<Response>`` element's own ``Destination`` and ``InResponseTo`` are held to the same
values.

Those four attributes are the evaluated surface, and a bearer confirmation that fails any of them is
unsatisfied. ``Address`` is deliberately not enforced: the profile makes it optional, it names the
address the subject was expected to present from, and an SP behind a proxy or a mobile network sees a
different one often enough that enforcing it rejects legitimate logins. Other attributes and child
content are likewise not evaluated, because ``SubjectConfirmationDataType`` admits arbitrary attributes
and children by design, so refusing what this SP does not recognize would reject conformant identity
providers that the earlier schema check legitimately admits. This is the one place the module departs
from the fail-closed posture that governs ``<Conditions>``, where an unrecognized condition can carry a
restriction and is therefore rejected.

Only the assertion is signed, so the ``<Response>`` attributes guard against a misdirected or stale
legitimate response rather than against a forging attacker, and ``Destination`` is checked only when
present, as Core §3.2.2 directs. The signed ``SubjectConfirmationData`` is what binds the assertion to
this endpoint and this request.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from xml.etree.ElementTree import Element

from apron_saml.errors import (
    AssertionExpiredError,
    InResponseToError,
    MalformedResponseError,
    RecipientMismatchError,
    SamlError,
)
from apron_saml.models import SamlConfig
from apron_saml.response import ParsedResponse
from apron_saml.timestamps import has_expired, parse_instant, require_aware

_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
_SUBJECT = f"{{{_SAML_NS}}}Subject"
_SUBJECT_CONFIRMATION = f"{{{_SAML_NS}}}SubjectConfirmation"
_SUBJECT_CONFIRMATION_DATA = f"{{{_SAML_NS}}}SubjectConfirmationData"
_METHOD_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"


def validate_subject_confirmation(
    parsed: ParsedResponse,
    config: SamlConfig,
    *,
    expected_in_response_to: str | None,
    now: datetime,
) -> None:
    """Require a satisfied bearer subject confirmation and consistent Response addressing.

    The assertion must carry at least one bearer ``<SubjectConfirmation>``, and at least one of them
    must be satisfied; others are ignored, as the profile directs. When every bearer confirmation
    fails, the first one's failure is reported. The Response-level checks run first because they are
    cheaper and their failure is the more actionable signal for a misrouted response.

    NOTE: the value of this check rests on a caller obligation the code cannot verify.
    ``expected_in_response_to`` must be the ID of a request this service provider issued for this same
    user agent, held in state the user agent cannot read or influence, and it must be discarded once a
    response consumes it. An ID taken from the response itself, shared across sessions, or accepted
    more than once reduces the check to a formality. Single-use invalidation is not enforced here and
    arrives with replay prevention (#24).

    Args:
        parsed: The parsed Response and its consumed assertion.
        config: SP configuration supplying the assertion consumer URL, clock skew, and whether
            unsolicited (IdP-initiated) responses are allowed.
        expected_in_response_to: The outstanding request ID this response must answer, or ``None``
            for an unsolicited response.
        now: The current time as a timezone-aware datetime.

    Raises:
        InResponseToError: If the response is unsolicited but IdP-initiated SSO is not allowed, or an
            ``InResponseTo`` on the Response or confirmation data is absent, present, or valued
            contrary to ``expected_in_response_to``.
        RecipientMismatchError: If the Response ``Destination`` (when present) or the confirmation
            ``Recipient`` is not exactly the configured assertion consumer URL.
        AssertionExpiredError: If ``now`` has reached the confirmation's ``NotOnOrAfter`` (skew applied).
        MalformedResponseError: If the assertion does not carry exactly one ``<Subject>``, carries no
            bearer confirmation, or a bearer confirmation lacks exactly one ``<SubjectConfirmationData>``
            with a parseable ``NotOnOrAfter`` and no ``NotBefore``.
        ValueError: If ``now`` is timezone-naive or ``expected_in_response_to`` is blank, which break
            the caller contract.
    """
    require_aware(now)
    if expected_in_response_to is not None and not expected_in_response_to.strip():
        raise ValueError("expected_in_response_to must be a non-blank request ID, or None for an unsolicited response")
    if expected_in_response_to is None and not config.allow_idp_initiated:
        raise InResponseToError(
            "response answers no outstanding authentication request and IdP-initiated SSO is not allowed"
        )
    _check_response_addressing(parsed.root, acs_url=config.acs_url, expected_in_response_to=expected_in_response_to)
    failures: list[SamlError] = []
    for confirmation in _bearer_confirmations(parsed.assertion):
        try:
            _confirm_bearer(
                confirmation,
                acs_url=config.acs_url,
                expected_in_response_to=expected_in_response_to,
                now=now,
                clock_skew=config.clock_skew,
            )
        except SamlError as e:
            failures.append(e)
        else:
            return
    raise failures[0]


def _bearer_confirmations(assertion: Element) -> list[Element]:
    """Return the assertion's bearer ``<SubjectConfirmation>`` elements, requiring at least one.

    SAML 2.0 Core §2.3.3 permits at most one ``<Subject>``, and duplicates are rejected rather than
    resolved by taking the first. The bundled assertion schema already rejects them upstream, so this
    keeps the check self-contained rather than depending on that earlier step, matching how
    ``<Conditions>`` is handled.

    Raises:
        MalformedResponseError: If the assertion does not carry exactly one ``<Subject>``, or that
            subject carries no bearer confirmation.
    """
    subjects = assertion.findall(_SUBJECT)
    if not subjects:
        raise MalformedResponseError("assertion has no Subject")
    if len(subjects) > 1:
        raise MalformedResponseError("assertion carries more than one Subject")
    bearer = [c for c in subjects[0].findall(_SUBJECT_CONFIRMATION) if c.get("Method") == _METHOD_BEARER]
    if not bearer:
        raise MalformedResponseError("assertion Subject has no bearer SubjectConfirmation")
    return bearer


def _check_response_addressing(response: Element, *, acs_url: str, expected_in_response_to: str | None) -> None:
    """Hold the Response's ``Destination`` and ``InResponseTo`` to this SP's endpoint and request.

    ``Destination`` is optional on an unsigned Response, so it is checked only when present.
    ``InResponseTo`` must be present and match for a solicited response, and absent for an unsolicited one.

    Raises:
        RecipientMismatchError: If ``Destination`` is present and is not exactly ``acs_url``.
        InResponseToError: If ``InResponseTo`` disagrees with ``expected_in_response_to``.
    """
    destination = response.get("Destination")
    if destination is not None and destination != acs_url:
        raise RecipientMismatchError("SAML Response Destination is not this service provider's assertion consumer URL")
    _check_in_response_to(response.get("InResponseTo"), expected_in_response_to, element="SAML Response")


def _confirm_bearer(
    confirmation: Element,
    *,
    acs_url: str,
    expected_in_response_to: str | None,
    now: datetime,
    clock_skew: timedelta,
) -> None:
    """Evaluate one bearer ``<SubjectConfirmation>`` against this SP, the current time, and the request.

    Exactly one ``<SubjectConfirmationData>`` is required, and it must carry ``Recipient`` and
    ``NotOnOrAfter``. A ``NotBefore`` is rejected rather than enforced: the profile states bearer
    confirmation data must not carry one, so its presence marks a nonconforming assertion whose
    intended semantics this SP cannot settle.

    Raises:
        RecipientMismatchError: If ``Recipient`` is missing or is not exactly ``acs_url``.
        AssertionExpiredError: If ``now`` has reached ``NotOnOrAfter`` (skew applied).
        InResponseToError: If ``InResponseTo`` disagrees with ``expected_in_response_to``.
        MalformedResponseError: If the confirmation data is missing, duplicated, carries ``NotBefore``,
            or has no parseable ``NotOnOrAfter``.
    """
    all_data = confirmation.findall(_SUBJECT_CONFIRMATION_DATA)
    if len(all_data) != 1:
        raise MalformedResponseError("bearer SubjectConfirmation does not carry exactly one SubjectConfirmationData")
    data = all_data[0]
    if data.get("NotBefore") is not None:
        raise MalformedResponseError("bearer SubjectConfirmationData must not carry NotBefore")
    recipient = data.get("Recipient")
    if recipient is None:
        raise RecipientMismatchError("bearer SubjectConfirmationData has no Recipient")
    if recipient != acs_url:
        raise RecipientMismatchError(
            "bearer SubjectConfirmationData Recipient is not this service provider's assertion consumer URL"
        )
    not_on_or_after = data.get("NotOnOrAfter")
    if not_on_or_after is None:
        raise MalformedResponseError("bearer SubjectConfirmationData has no NotOnOrAfter, so its validity is unbounded")
    expiry = parse_instant(not_on_or_after, field="bearer SubjectConfirmationData NotOnOrAfter")
    if has_expired(now, expiry, clock_skew):
        raise AssertionExpiredError("bearer subject confirmation has expired")
    _check_in_response_to(data.get("InResponseTo"), expected_in_response_to, element="bearer SubjectConfirmationData")


def _check_in_response_to(actual: str | None, expected: str | None, *, element: str) -> None:
    """Require ``actual`` to equal the expected request ID exactly, or to be absent when unsolicited.

    Raises:
        InResponseToError: If ``actual`` is present for an unsolicited response, absent for a solicited
            one, or differs from ``expected``.
    """
    if expected is None:
        if actual is not None:
            raise InResponseToError(f"{element} carries InResponseTo but the response is unsolicited")
        return
    if actual is None:
        raise InResponseToError(f"{element} has no InResponseTo but the response must answer an outstanding request")
    if actual != expected:
        raise InResponseToError(f"{element} InResponseTo does not match the outstanding authentication request")
