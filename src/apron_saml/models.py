"""Configuration, result, and descriptor types for SP-side SAML."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import urlparse


@dataclass(frozen=True)
class SamlConfig:
    """Immutable configuration for a single SAML service provider (SP).

    Holds the SP's own identifiers plus the trust material for one identity provider (IdP).
    apron-saml performs no network I/O: the caller fetches ``idp_metadata`` and passes the XML in.
    ``acs_url`` may use http for local development, but production deployments should use https,
    since the assertion consumer endpoint receives bearer assertions.
    """

    entity_id: str
    acs_url: str
    idp_metadata: str
    want_assertions_signed: bool = True
    clock_skew: timedelta = timedelta(minutes=3)
    allow_idp_initiated: bool = False
    decrypt_key: str | None = None

    def __post_init__(self) -> None:
        """Validate the configuration at construction, rejecting values the protocol cannot use.

        Full validation of ``decrypt_key`` as a usable key is deferred to the decryption path;
        here it is only required to be non-blank when supplied.

        Raises:
            ValueError: If ``entity_id``, ``acs_url``, or ``idp_metadata`` is blank; if ``acs_url``
                is not an absolute http or https URL or carries userinfo; if ``idp_metadata`` does
                not appear to contain XML; if ``clock_skew`` is negative; or if ``decrypt_key`` is
                blank when supplied.
        """
        if not self.entity_id.strip():
            raise ValueError("entity_id must not be blank")
        if not self.acs_url.strip():
            raise ValueError("acs_url must not be blank")
        parsed = urlparse(self.acs_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("acs_url must be an absolute http or https URL")
        if "@" in parsed.netloc:
            raise ValueError("acs_url must not contain userinfo (credentials)")
        if not self.idp_metadata.strip():
            raise ValueError("idp_metadata must not be blank")
        # Cheap fail-fast for the common misuse (a URL or file path in place of XML); authoritative
        # well-formedness and parsing are the metadata layer's job via the vetted backend, not here.
        if "<" not in self.idp_metadata:
            raise ValueError("idp_metadata must contain SAML metadata XML, not a URL or file path")
        if self.clock_skew < timedelta(0):
            raise ValueError("clock_skew must not be negative")
        if self.decrypt_key is not None and not self.decrypt_key.strip():
            raise ValueError("decrypt_key must not be blank when provided")


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
