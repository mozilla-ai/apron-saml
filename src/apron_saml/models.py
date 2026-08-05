"""Configuration, result, and descriptor types for SP-side SAML."""

from __future__ import annotations

import base64
import html
import zlib
from dataclasses import dataclass, field
from datetime import timedelta
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit


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

    def __post_init__(self) -> None:
        """Validate that ``sso_url`` is an absolute http or https URL, without userinfo.

        Rejecting other schemes (for example ``javascript:`` or ``data:``) at construction keeps the
        descriptor from carrying a single sign-on location that is unsafe to use as a request
        destination.

        Raises:
            ValueError: If ``sso_url`` is not an absolute http or https URL, or carries userinfo.
        """
        parsed = urlparse(self.sso_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("sso_url must be an absolute http or https URL")
        if "@" in parsed.netloc:
            raise ValueError("sso_url must not contain userinfo (credentials)")


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
        """Return the destination URL with the request encoded for the HTTP-Redirect binding.

        The request XML is DEFLATE-compressed, base64-encoded, and carried in the ``SAMLRequest``
        query parameter, with ``relay_state`` alongside it as ``RelayState`` when present.
        """
        compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        deflated = compressor.compress(self.xml.encode("utf-8")) + compressor.flush()
        params = {"SAMLRequest": base64.b64encode(deflated).decode("ascii")}
        if self.relay_state is not None:
            params["RelayState"] = self.relay_state
        parts = urlsplit(self.destination)
        query = urlencode([*parse_qsl(parts.query), *params.items()])
        return urlunsplit(parts._replace(query=query))

    def post_form(self) -> str:
        """Return a self-submitting HTML form encoding the request for the HTTP-POST binding.

        The request XML is base64-encoded into a ``SAMLRequest`` hidden field, with ``relay_state``
        as a ``RelayState`` field when present, in a form that posts to the destination on load.
        Interpolated values are HTML-escaped, so a hostile destination or relay state cannot break
        out of the markup. A visible submit button lets the user continue if the auto-submit script
        does not run (for example under a Content-Security-Policy that blocks inline scripts).
        """
        payload = base64.b64encode(self.xml.encode("utf-8")).decode("ascii")
        fields = [f'<input type="hidden" name="SAMLRequest" value="{html.escape(payload)}"/>']
        if self.relay_state is not None:
            fields.append(f'<input type="hidden" name="RelayState" value="{html.escape(self.relay_state)}"/>')
        action = html.escape(self.destination)
        return (
            f'<form id="saml-post-form" method="post" action="{action}">'
            f"{''.join(fields)}"
            '<input type="submit" value="Continue"/>'
            "</form>"
            "<script>document.getElementById('saml-post-form').submit();</script>"
        )


@dataclass(frozen=True)
class SamlIdentity:
    """The validated identity extracted from a SAML assertion.

    A service-provider-shaped result the consuming application maps onto its own user model.
    ``name_id`` (the subject) and ``issuer`` (the asserting IdP's ``<Issuer>`` entityID, usable as a
    tenant discriminator) are always present; the remaining fields are best-effort enrichments.
    """

    name_id: str
    issuer: str
    name_id_format: str | None = None
    email: str | None = None
    attributes: dict[str, list[str]] = field(default_factory=dict)
    session_index: str | None = None
