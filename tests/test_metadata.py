from collections.abc import Iterable

import pytest

from apron_saml import IdPDescriptor, MetadataError, SamlError
from apron_saml.metadata import parse_idp_metadata

_ENTITY_ID = "https://idp.example.com/entity"
_REDIRECT_URL = "https://idp.example.com/sso/redirect"
_POST_URL = "https://idp.example.com/sso/post"
_SOAP_URL = "https://idp.example.com/sso/soap"

_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
_DS = "http://www.w3.org/2000/09/xmldsig#"
_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
_SOAP = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP"

# Opaque placeholder certificate bodies; parsing treats X509Certificate content as text, not keys.
_SIGNING_CERT = "signing-certificate-placeholder-one"
_SIGNING_CERT_2 = "signing-certificate-placeholder-two"
_ENCRYPTION_CERT = "encryption-certificate-placeholder"


def _sso(binding: str, location: str) -> str:
    return f'<SingleSignOnService Binding="{binding}" Location="{location}"/>'


def _key_descriptor(cert: str, *, use: str | None = "signing") -> str:
    use_attr = f' use="{use}"' if use is not None else ""
    return (
        f"<KeyDescriptor{use_attr}>"
        f"<ds:KeyInfo><ds:X509Data>"
        f"<ds:X509Certificate>{cert}</ds:X509Certificate>"
        f"</ds:X509Data></ds:KeyInfo>"
        f"</KeyDescriptor>"
    )


def _idp_metadata(
    *,
    entity_id: str | None = _ENTITY_ID,
    endpoints: Iterable[str] = (_sso(_REDIRECT, _REDIRECT_URL), _sso(_POST, _POST_URL)),
    key_descriptors: Iterable[str] = (_key_descriptor(_SIGNING_CERT),),
) -> str:
    entity_attr = f' entityID="{entity_id}"' if entity_id is not None else ""
    body = "".join((*key_descriptors, *endpoints))
    return (
        f'<EntityDescriptor xmlns="{_MD}" xmlns:ds="{_DS}"{entity_attr}>'
        f'<IDPSSODescriptor protocolSupportEnumeration="{_PROTOCOL}">'
        f"{body}"
        f"</IDPSSODescriptor>"
        f"</EntityDescriptor>"
    )


def test_returns_idp_descriptor() -> None:
    assert isinstance(parse_idp_metadata(_idp_metadata()), IdPDescriptor)


def test_extracts_entity_id() -> None:
    assert parse_idp_metadata(_idp_metadata()).entity_id == _ENTITY_ID


def test_prefers_http_redirect_for_sso_url() -> None:
    # Both web bindings advertised; HTTP-Redirect is the canonical binding for dispatching requests.
    assert parse_idp_metadata(_idp_metadata()).sso_url == _REDIRECT_URL


def test_falls_back_to_http_post_when_no_redirect() -> None:
    xml = _idp_metadata(endpoints=(_sso(_POST, _POST_URL),))
    assert parse_idp_metadata(xml).sso_url == _POST_URL


def test_ignores_non_web_binding_sso_endpoints() -> None:
    xml = _idp_metadata(endpoints=(_sso(_SOAP, _SOAP_URL), _sso(_POST, _POST_URL)))
    assert parse_idp_metadata(xml).sso_url == _POST_URL


def test_selects_valid_endpoint_when_preferred_binding_has_hostile_scheme() -> None:
    # A javascript:-scheme redirect location must not be chosen; the valid POST endpoint is used.
    xml = _idp_metadata(
        endpoints=(_sso(_REDIRECT, "javascript:alert(1)"), _sso(_POST, _POST_URL)),
    )
    assert parse_idp_metadata(xml).sso_url == _POST_URL


def test_extracts_signing_certificate() -> None:
    assert parse_idp_metadata(_idp_metadata()).signing_certificates == (_SIGNING_CERT,)


def test_normalizes_whitespace_in_certificate() -> None:
    wrapped = f"\n        {_SIGNING_CERT[:20]}\n        {_SIGNING_CERT[20:]}\n      "
    xml = _idp_metadata(key_descriptors=(_key_descriptor(wrapped),))
    assert parse_idp_metadata(xml).signing_certificates == (_SIGNING_CERT,)


def test_includes_signing_key_descriptor_without_use() -> None:
    xml = _idp_metadata(key_descriptors=(_key_descriptor(_SIGNING_CERT, use=None),))
    assert parse_idp_metadata(xml).signing_certificates == (_SIGNING_CERT,)


def test_excludes_encryption_only_certificate() -> None:
    xml = _idp_metadata(key_descriptors=(_key_descriptor(_ENCRYPTION_CERT, use="encryption"),))
    assert parse_idp_metadata(xml).signing_certificates == ()


def test_keeps_only_signing_key_when_both_present() -> None:
    xml = _idp_metadata(
        key_descriptors=(
            _key_descriptor(_SIGNING_CERT, use="signing"),
            _key_descriptor(_ENCRYPTION_CERT, use="encryption"),
        )
    )
    assert parse_idp_metadata(xml).signing_certificates == (_SIGNING_CERT,)


def test_collects_multiple_signing_certificates_in_order() -> None:
    xml = _idp_metadata(key_descriptors=(_key_descriptor(_SIGNING_CERT), _key_descriptor(_SIGNING_CERT_2)))
    assert parse_idp_metadata(xml).signing_certificates == (_SIGNING_CERT, _SIGNING_CERT_2)


def test_deduplicates_repeated_signing_certificates() -> None:
    xml = _idp_metadata(key_descriptors=(_key_descriptor(_SIGNING_CERT), _key_descriptor(_SIGNING_CERT)))
    assert parse_idp_metadata(xml).signing_certificates == (_SIGNING_CERT,)


def test_signing_certificates_empty_when_none_present() -> None:
    xml = _idp_metadata(key_descriptors=())
    assert parse_idp_metadata(xml).signing_certificates == ()


def test_rejects_blank_input() -> None:
    with pytest.raises(MetadataError):
        parse_idp_metadata("   ")


def test_rejects_malformed_xml() -> None:
    with pytest.raises(MetadataError):
        parse_idp_metadata("<EntityDescriptor><unclosed>")


def test_rejects_non_entity_descriptor_root() -> None:
    aggregate = f'<EntitiesDescriptor xmlns="{_MD}"><EntityDescriptor entityID="{_ENTITY_ID}"/></EntitiesDescriptor>'
    with pytest.raises(MetadataError):
        parse_idp_metadata(aggregate)


def test_rejects_metadata_without_idpsso_descriptor() -> None:
    sp_only = (
        f'<EntityDescriptor xmlns="{_MD}" entityID="{_ENTITY_ID}">'
        f'<SPSSODescriptor protocolSupportEnumeration="{_PROTOCOL}"/>'
        f"</EntityDescriptor>"
    )
    with pytest.raises(MetadataError):
        parse_idp_metadata(sp_only)


def test_rejects_metadata_without_entity_id() -> None:
    with pytest.raises(MetadataError):
        parse_idp_metadata(_idp_metadata(entity_id=None))


def test_rejects_metadata_without_supported_sso_binding() -> None:
    xml = _idp_metadata(endpoints=(_sso(_SOAP, _SOAP_URL),))
    with pytest.raises(MetadataError):
        parse_idp_metadata(xml)


def test_rejects_sso_endpoint_with_non_http_scheme() -> None:
    xml = _idp_metadata(endpoints=(_sso(_REDIRECT, "javascript:alert(1)"),))
    with pytest.raises(MetadataError):
        parse_idp_metadata(xml)


def test_metadata_error_is_catchable_as_saml_error() -> None:
    with pytest.raises(SamlError):
        parse_idp_metadata("not xml at all")
