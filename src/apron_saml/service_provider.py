"""The ServiceProvider facade — the primary entry point for SP-side SAML."""

from __future__ import annotations

import warnings
from datetime import UTC, datetime

from apron_saml.metadata import parse_idp_metadata
from apron_saml.models import AuthnRequest, SamlConfig, SamlIdentity
from apron_saml.protocols import AssertionStore, Clock
from apron_saml.response import decode_response
from apron_saml.validation import validate_and_extract


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
        """Bind a service provider to ``config`` and its optional replay store and clock.

        Parses the IdP metadata once here so an unusable configuration fails fast at construction.
        """
        self._config = config
        self._assertion_store = assertion_store
        self._clock: Clock = clock or _SystemClock()
        self._idp = parse_idp_metadata(config.idp_metadata)
        if not config.want_assertions_signed:
            warnings.warn(
                "want_assertions_signed=False is not yet honored: response-level signature "
                "acceptance is not implemented, so assertion signatures are still required.",
                UserWarning,
                stacklevel=2,
            )

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
        response_xml = decode_response(saml_response_b64)
        return validate_and_extract(
            response_xml,
            self._config,
            self._idp,
            clock=self._clock,
            assertion_store=self._assertion_store,
            expected_in_response_to=expected_in_response_to,
        )
