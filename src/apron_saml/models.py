"""Configuration, result, and descriptor types for SP-side SAML."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta


@dataclass(frozen=True)
class SamlConfig:
    """Immutable configuration for a single SAML service provider (SP).

    Holds the SP's own identifiers plus the trust material for one identity provider (IdP).
    apron-saml performs no network I/O: the caller fetches ``idp_metadata`` and passes the XML in.
    """

    entity_id: str
    acs_url: str
    idp_metadata: str
    want_assertions_signed: bool = True
    clock_skew: timedelta = timedelta(minutes=3)
    allow_idp_initiated: bool = False
    decrypt_key: str | None = None

    def __post_init__(self) -> None:
        """Reject configuration missing an identifier the protocol cannot proceed without."""
        if not self.entity_id:
            raise ValueError("entity_id must not be empty")
        if not self.acs_url:
            raise ValueError("acs_url must not be empty")
        if not self.idp_metadata:
            raise ValueError("idp_metadata must not be empty")


@dataclass(frozen=True)
class IdPDescriptor:
    """The subset of identity-provider metadata a service provider needs.

    Produced by parsing IdP metadata XML; used to locate the SSO endpoint and to select the key
    that must have signed an assertion.
    """

    entity_id: str
    sso_url: str
    signing_certificates: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthnRequest:
    """A built authentication request ready to send to the identity provider.

    Carries the request ID the caller must persist to later match an inbound response, and exposes
    the two web-binding encodings.
    """

    request_id: str
    xml: str
    destination: str
    relay_state: str | None = None

    def redirect_url(self) -> str:
        """Return the destination URL with the request encoded for the HTTP-Redirect binding."""
        raise NotImplementedError

    def post_form(self) -> str:
        """Return a self-submitting HTML form encoding the request for the HTTP-POST binding."""
        raise NotImplementedError


@dataclass(frozen=True)
class SamlIdentity:
    """The validated identity extracted from a SAML assertion.

    A service-provider-shaped result; the consuming application maps it onto its own canonical
    user model.
    """

    name_id: str
    issuer: str
    name_id_format: str | None = None
    email: str | None = None
    attributes: dict[str, list[str]] = field(default_factory=dict)
    session_index: str | None = None
