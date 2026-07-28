"""Building SAML authentication requests for SP-initiated login."""

from __future__ import annotations

from apron_saml.models import AuthnRequest, IdPDescriptor, SamlConfig


def build_authn_request(
    config: SamlConfig,
    idp: IdPDescriptor,
    *,
    relay_state: str | None = None,
) -> AuthnRequest:
    """Build a SAML authentication request for an SP-initiated login against ``idp``."""
    raise NotImplementedError
