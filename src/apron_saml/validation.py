"""Security-critical validation of SAML assertions (internal).

Wraps the vetted XML-security backend and enforces the SP-side checks: signature verification,
XML-Signature-Wrapping hardening, ``Conditions``, ``SubjectConfirmation``, and replay prevention.
"""

from __future__ import annotations

from apron_saml.models import SamlConfig, SamlIdentity
from apron_saml.protocols import AssertionStore, Clock


def validate_and_extract(
    response_xml: str,
    config: SamlConfig,
    *,
    clock: Clock,
    assertion_store: AssertionStore | None,
    expected_in_response_to: str | None,
) -> SamlIdentity:
    """Validate a decoded SAML Response end to end and return the extracted identity.

    Raises a SamlError subclass on the first failed check; returns a SamlIdentity only once every
    security check has passed.
    """
    raise NotImplementedError
