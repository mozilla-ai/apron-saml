"""Security-critical validation of SAML assertions (internal).

Wraps the vetted XML-security backend and enforces the SP-side checks: signature verification,
XML-Signature-Wrapping hardening, ``Conditions``, ``SubjectConfirmation``, and replay prevention.
"""

from __future__ import annotations

from apron_saml.models import IdPDescriptor, SamlConfig, SamlIdentity
from apron_saml.protocols import AssertionStore, Clock
from apron_saml.response import parse_response
from apron_saml.signatures import verify_assertion_signature


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
    has passed and raising a SamlError subclass on the first failure. Signature verification is
    enforced today; the remaining Conditions, SubjectConfirmation, replay, and assembly steps are not
    yet implemented and raise NotImplementedError until they land.

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
    verify_assertion_signature(parsed, idp)
    raise NotImplementedError  # Conditions, SubjectConfirmation, replay, and assembly land in #22-#26.
