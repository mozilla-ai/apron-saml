"""Exception hierarchy for SP-side SAML processing failures."""

from __future__ import annotations


class SamlError(Exception):
    """Base class for all apron-saml failures.

    Every rejection path in the library raises a subclass of this type, so callers can catch
    SamlError to treat any SAML processing failure uniformly.
    """


class MalformedResponseError(SamlError):
    """The SAML Response could not be decoded or parsed into the expected structure."""


class StatusError(SamlError):
    """The SAML Response carried a non-success top-level status."""


class SignatureError(SamlError):
    """A required signature was missing, malformed, or did not verify against the configured key."""


class AssertionExpiredError(SamlError):
    """The assertion is outside its validity window (Conditions or SubjectConfirmationData)."""


class AudienceMismatchError(SamlError):
    """The assertion's audience restriction did not name this service provider."""


class RecipientMismatchError(SamlError):
    """The subject confirmation recipient did not match the configured assertion consumer URL."""


class InResponseToError(SamlError):
    """The InResponseTo value did not match an outstanding, SP-issued authentication request."""


class ReplayError(SamlError):
    """The assertion has already been consumed."""
