"""Security-critical validation of SAML assertions (internal).

Wraps the vetted XML-security backend and enforces the SP-side checks: signature verification,
XML-Signature-Wrapping hardening, ``Conditions``, ``SubjectConfirmation``, and replay prevention.
"""

from __future__ import annotations

from apron_saml.conditions import validate_conditions
from apron_saml.models import IdPDescriptor, SamlConfig, SamlIdentity
from apron_saml.protocols import AssertionStore, Clock
from apron_saml.response import parse_response
from apron_saml.signatures import verify_assertion_signature
from apron_saml.wrapping import reject_signature_wrapping


def validate_and_extract(
    response_xml: str,
    config: SamlConfig,
    idp: IdPDescriptor,
    *,
    clock: Clock,
    assertion_store: AssertionStore | None,
    expected_in_response_to: str | None,
) -> SamlIdentity:
    """Validate a decoded SAML Response end to end and return the extracted identity.

    Runs the SP-side security checks in trust order, returning a SamlIdentity only once every check
    has passed and raising a SamlError subclass on the first failure. XSW hardening runs first so a
    wrapped assertion is rejected before any signature is trusted, then signature verification, then
    the assertion's Conditions (validity window and audience); the remaining SubjectConfirmation,
    replay, and assembly steps are not yet implemented and raise NotImplementedError until they land.

    Args:
        response_xml: The decoded SAML Response XML, as produced by decode_response.
        config: SP configuration supplying the audience and assertion consumer URL for later checks.
        idp: Descriptor supplying the pinned signing certificates the assertion must verify against.
        clock: Time source for the validity-window checks.
        assertion_store: Replay store used to reject a previously consumed assertion, if provided.
        expected_in_response_to: The outstanding request ID the response must answer, if solicited.

    Returns:
        The validated identity extracted from the assertion.

    Raises:
        SamlError: On the first failed security check (for example a signature that does not verify).
    """
    parsed = parse_response(response_xml)
    reject_signature_wrapping(parsed)
    verify_assertion_signature(parsed, idp)
    validate_conditions(parsed.assertion, audience=config.entity_id, now=clock.now(), clock_skew=config.clock_skew)
    raise NotImplementedError  # SubjectConfirmation, replay, and assembly land in #23-#26.
