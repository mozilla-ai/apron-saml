"""The ServiceProvider facade — the primary entry point for SP-side SAML."""

from __future__ import annotations

from datetime import UTC, datetime

from apron_saml.models import AuthnRequest, SamlConfig, SamlIdentity
from apron_saml.protocols import AssertionStore, Clock


class _SystemClock:
    """Default Clock backed by the system UTC time."""

    def now(self) -> datetime:
        """Return the current time as a timezone-aware UTC datetime."""
        return datetime.now(UTC)


class ServiceProvider:
    """Entry point for SP-side SAML: build requests, emit metadata, and process responses.

    Constructed from an immutable SamlConfig plus optional caller-provided replay storage and a
    clock. Every method is synchronous and performs no network I/O.
    """

    def __init__(
        self,
        config: SamlConfig,
        *,
        assertion_store: AssertionStore | None = None,
        clock: Clock | None = None,
    ) -> None:
        """Bind a service provider to ``config`` and its optional replay store and clock."""
        self._config = config
        self._assertion_store = assertion_store
        self._clock: Clock = clock or _SystemClock()

    def build_authn_request(self, *, relay_state: str | None = None) -> AuthnRequest:
        """Build a SAML authentication request for an SP-initiated login."""
        raise NotImplementedError

    def generate_metadata(self) -> str:
        """Return this service provider's SAML metadata document as an XML string."""
        raise NotImplementedError

    def process_response(
        self,
        saml_response_b64: str,
        *,
        expected_in_response_to: str | None = None,
    ) -> SamlIdentity:
        """Decode, fully validate, and extract the identity from a SAML Response.

        Raises a SamlError subclass on any validation failure; returns a SamlIdentity only once
        every security check has passed.
        """
        raise NotImplementedError
