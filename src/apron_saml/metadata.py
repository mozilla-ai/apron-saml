"""Parsing identity-provider metadata and generating service-provider metadata."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import urlparse
from xml.etree.ElementTree import ParseError

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from saml2.md import IDPSSODescriptor, entity_descriptor_from_string

from apron_saml.errors import MetadataError
from apron_saml.models import IdPDescriptor, SamlConfig

# SingleSignOnService bindings an SP can dispatch a browser AuthnRequest over, in preference order.
# HTTP-Redirect is the canonical binding for sending requests; other bindings (e.g. SOAP for ECP)
# are back-channel and not usable here.
_SSO_BINDING_PREFERENCE = (BINDING_HTTP_REDIRECT, BINDING_HTTP_POST)

# KeyDescriptor ``use`` values whose key may verify an assertion signature: "signing", or unset
# (a dual-use key). Any other value — "encryption", or an unrecognized use — is excluded.
_SIGNING_USES = frozenset({None, "", "signing"})


def parse_idp_metadata(xml: str) -> IdPDescriptor:
    """Parse IdP metadata XML into the entity ID, SSO URL, and signing certificates an SP needs.

    Reads a single ``<EntityDescriptor>`` describing an identity provider (IdP) and extracts the
    trust material a service provider requires: the IdP's entityID, the single sign-on endpoint to
    target, and the certificates that may have signed an assertion. The SSO endpoint is chosen from
    the advertised web bindings, preferring HTTP-Redirect over HTTP-POST. Signing certificates are
    those from KeyDescriptors usable for signing (``use="signing"`` or no ``use``); encryption-only
    keys are excluded. Certificate text is normalized to whitespace-free base64.

    Args:
        xml: A SAML 2.0 metadata document whose root is an ``<EntityDescriptor>`` for one IdP.

    Returns:
        An IdPDescriptor holding the entity ID, selected SSO URL, and signing certificates.

    Raises:
        MetadataError: If the input is not well-formed XML, carries a disallowed DTD or entity
            declaration, is not rooted at an EntityDescriptor, names no entityID, describes no
            identity provider, or advertises no HTTP-Redirect or HTTP-POST single sign-on endpoint.
    """
    try:
        entity = entity_descriptor_from_string(xml)
    except ParseError as e:
        raise MetadataError("IdP metadata is not well-formed XML") from e
    except ValueError as e:
        # The XML-security backend rejects a DTD or entity definition (an XXE/expansion vector) by
        # raising a ValueError subclass; translate it into a domain error rather than leaking it.
        raise MetadataError("IdP metadata contains a disallowed DTD or entity declaration") from e
    if entity is None:
        raise MetadataError("IdP metadata root element is not an EntityDescriptor")

    entity_id = (entity.entity_id or "").strip()
    if not entity_id:
        raise MetadataError("IdP metadata EntityDescriptor has no entityID")

    idp_roles = entity.idpsso_descriptor
    if not idp_roles:
        raise MetadataError("IdP metadata describes no identity provider")

    return IdPDescriptor(
        entity_id=entity_id,
        sso_url=_select_sso_url(idp_roles),
        signing_certificates=_collect_signing_certificates(idp_roles),
    )


def _select_sso_url(idp_roles: Iterable[IDPSSODescriptor]) -> str:
    """Return the preferred single sign-on URL across the IdP roles' usable web-binding endpoints.

    An endpoint is usable when it advertises a supported web binding and its location is an absolute
    http or https URL, preferring HTTP-Redirect over HTTP-POST. The http(s) requirement keeps a
    hostile ``javascript:`` or ``data:`` location out of the URL a caller later dispatches the
    request to.

    Raises:
        MetadataError: If no usable HTTP-Redirect or HTTP-POST endpoint is advertised.
    """
    locations: dict[str, str] = {}
    for role in idp_roles:
        for service in role.single_sign_on_service:
            location = (service.location or "").strip()
            if service.binding and service.binding not in locations and _is_http_url(location):
                locations[service.binding] = location
    for binding in _SSO_BINDING_PREFERENCE:
        if binding in locations:
            return locations[binding]
    raise MetadataError(
        "IdP metadata has no HTTP-Redirect or HTTP-POST single sign-on endpoint with an absolute http or https location"
    )


def _is_http_url(value: str) -> bool:
    """Return whether ``value`` is an absolute http or https URL."""
    parsed = urlparse(value)
    return parsed.scheme in ("http", "https") and bool(parsed.hostname)


def _collect_signing_certificates(idp_roles: Iterable[IDPSSODescriptor]) -> tuple[str, ...]:
    """Return the distinct signing certificates across the IdP roles, in document order.

    Includes only keys usable for signing — those with ``use="signing"`` or no ``use`` — and
    excludes all others, including encryption-only keys and any unrecognized ``use``. Certificate
    text is normalized to whitespace-free base64.
    """
    certificates: list[str] = []
    seen: set[str] = set()
    for role in idp_roles:
        for key_descriptor in role.key_descriptor:
            if key_descriptor.use not in _SIGNING_USES or key_descriptor.key_info is None:
                continue
            for x509_data in key_descriptor.key_info.x509_data:
                certificate = x509_data.x509_certificate
                if certificate is None or not certificate.text:
                    continue
                normalized = "".join(certificate.text.split())
                if normalized and normalized not in seen:
                    seen.add(normalized)
                    certificates.append(normalized)
    return tuple(certificates)


def generate_sp_metadata(config: SamlConfig) -> str:
    """Generate this service provider's SAML metadata document as an XML string."""
    raise NotImplementedError
