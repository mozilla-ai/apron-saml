"""Building SAML authentication requests for SP-initiated login."""

from __future__ import annotations

from datetime import UTC, datetime

from saml2 import BINDING_HTTP_POST, s_utils, saml, samlp, time_util

from apron_saml.models import AuthnRequest, IdPDescriptor, SamlConfig
from apron_saml.protocols import Clock


def build_authn_request(
    config: SamlConfig,
    idp: IdPDescriptor,
    *,
    relay_state: str | None = None,
    clock: Clock | None = None,
) -> AuthnRequest:
    """Build an unsigned SAML AuthnRequest for an SP-initiated login against ``idp``.

    Emits a SAML 2.0 ``<AuthnRequest>`` that names this service provider (SP) as issuer, targets the
    identity provider's single sign-on endpoint, and asks for the response at ``config.acs_url`` over
    the HTTP-POST binding. The request is unsigned: SP request signing needs key material the
    configuration does not carry, and an unsigned AuthnRequest is valid under both web bindings.

    Args:
        config: SP configuration supplying the issuer entityID and assertion consumer URL.
        idp: Descriptor supplying the destination single sign-on URL.
        relay_state: Opaque value to be returned unchanged on the result for the caller to encode.
        clock: Time source for the ``IssueInstant``; defaults to the system UTC clock.

    Returns:
        An AuthnRequest bundling the request ID to persist, the request XML, the destination, and the
        relay state, with the HTTP-Redirect and HTTP-POST encodings available on it.
    """
    now = clock.now() if clock is not None else datetime.now(UTC)
    request_id = s_utils.sid()
    request = samlp.AuthnRequest(
        id=request_id,
        version="2.0",
        issue_instant=time_util.instant(time_stamp=now.timestamp()),
        destination=idp.sso_url,
        protocol_binding=BINDING_HTTP_POST,
        assertion_consumer_service_url=config.acs_url,
        issuer=saml.Issuer(text=config.entity_id),
    )
    return AuthnRequest(
        request_id=request_id,
        xml=request.to_string().decode("utf-8"),
        destination=idp.sso_url,
        relay_state=relay_state,
    )
