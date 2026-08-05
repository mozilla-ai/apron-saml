from collections.abc import Iterable
from xml.etree.ElementTree import Element

import pytest
from defusedxml.ElementTree import fromstring

from apron_saml import IdPDescriptor, MetadataError, SamlConfig, SamlError
from apron_saml.metadata import generate_sp_metadata, parse_idp_metadata

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

# Service-provider identifiers for exercising generate_sp_metadata.
_SP_ENTITY_ID = "https://sp.example.com/metadata"
_ACS_URL = "https://sp.example.com/acs"


def _sso(binding: str, location: str) -> str:
    return f'<SingleSignOnService Binding="{binding}" Location="{location}"/>'


def _key_descriptor(*certs: str, use: str | None = "signing") -> str:
    use_attr = f' use="{use}"' if use is not None else ""
    x509 = "".join(f"<ds:X509Certificate>{cert}</ds:X509Certificate>" for cert in certs)
    return f"<KeyDescriptor{use_attr}><ds:KeyInfo><ds:X509Data>{x509}</ds:X509Data></ds:KeyInfo></KeyDescriptor>"


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


def test_excludes_key_descriptor_with_unrecognized_use() -> None:
    # An unexpected use value is not signing-eligible; only "signing"/unset keys are trusted.
    xml = _idp_metadata(key_descriptors=(_key_descriptor(_SIGNING_CERT, use="bogus"),))
    assert parse_idp_metadata(xml).signing_certificates == ()


def test_keeps_only_signing_key_when_both_present() -> None:
    xml = _idp_metadata(
        key_descriptors=(
            _key_descriptor(_SIGNING_CERT, use="signing"),
            _key_descriptor(_ENCRYPTION_CERT, use="encryption"),
        )
    )
    assert parse_idp_metadata(xml).signing_certificates == (_SIGNING_CERT,)


def test_collects_all_certificates_within_one_x509data() -> None:
    # A single X509Data may carry a certificate chain; every X509Certificate is captured, in order.
    xml = _idp_metadata(key_descriptors=(_key_descriptor(_SIGNING_CERT, _SIGNING_CERT_2),))
    assert parse_idp_metadata(xml).signing_certificates == (_SIGNING_CERT, _SIGNING_CERT_2)


def test_excludes_all_certificates_of_encryption_key_descriptor() -> None:
    xml = _idp_metadata(key_descriptors=(_key_descriptor(_ENCRYPTION_CERT, _SIGNING_CERT_2, use="encryption"),))
    assert parse_idp_metadata(xml).signing_certificates == ()


def test_ignores_key_descriptors_of_nested_idpsso_descriptor() -> None:
    # Only the entity's direct IDPSSODescriptor role contributes certs; a nested IDPSSODescriptor
    # (e.g. embedded in Extensions) must not smuggle in trust material.
    xml = (
        f'<EntityDescriptor xmlns="{_MD}" xmlns:ds="{_DS}" xmlns:x="urn:example:ext" '
        f'entityID="{_ENTITY_ID}">'
        f'<IDPSSODescriptor protocolSupportEnumeration="{_PROTOCOL}">'
        f"{_key_descriptor(_SIGNING_CERT)}{_sso(_REDIRECT, _REDIRECT_URL)}"
        f"</IDPSSODescriptor>"
        f"<Extensions><x:wrapper>"
        f'<IDPSSODescriptor protocolSupportEnumeration="{_PROTOCOL}">'
        f"{_key_descriptor(_SIGNING_CERT_2)}"
        f"</IDPSSODescriptor>"
        f"</x:wrapper></Extensions>"
        f"</EntityDescriptor>"
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


def test_rejects_metadata_with_entity_declaration() -> None:
    # A DTD with an entity definition (billion-laughs/XXE vector) must be a domain MetadataError,
    # not a leaked backend exception.
    xml = f'<!DOCTYPE EntityDescriptor [<!ENTITY x "y">]><EntityDescriptor xmlns="{_MD}" entityID="{_ENTITY_ID}"/>'
    with pytest.raises(MetadataError):
        parse_idp_metadata(xml)


def test_rejects_metadata_with_external_entity() -> None:
    xml = f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><EntityDescriptor xmlns="{_MD}" entityID="&xxe;"/>'
    with pytest.raises(MetadataError):
        parse_idp_metadata(xml)


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


def _sp_config(
    *,
    entity_id: str = _SP_ENTITY_ID,
    acs_url: str = _ACS_URL,
    want_assertions_signed: bool = True,
) -> SamlConfig:
    return SamlConfig(
        entity_id=entity_id,
        acs_url=acs_url,
        idp_metadata=_idp_metadata(),
        want_assertions_signed=want_assertions_signed,
    )


def _sp_metadata_root(config: SamlConfig) -> Element:
    # Parsing the output proves it is well-formed XML and lets tests assert its structure.
    return fromstring(generate_sp_metadata(config))


def _spsso_descriptor(config: SamlConfig) -> Element:
    return _sp_metadata_root(config).find(f"{{{_MD}}}SPSSODescriptor")


def test_generate_sp_metadata_returns_str() -> None:
    assert isinstance(generate_sp_metadata(_sp_config()), str)


def test_generated_sp_metadata_is_rooted_at_entity_descriptor() -> None:
    assert _sp_metadata_root(_sp_config()).tag == f"{{{_MD}}}EntityDescriptor"


def test_generated_sp_metadata_entity_id_matches_config() -> None:
    root = _sp_metadata_root(_sp_config(entity_id="https://sp.other.example/saml"))
    assert root.get("entityID") == "https://sp.other.example/saml"


def test_generated_sp_metadata_advertises_spsso_for_saml2_protocol() -> None:
    spsso = _spsso_descriptor(_sp_config())
    assert spsso is not None
    assert spsso.get("protocolSupportEnumeration") == _PROTOCOL


def test_generated_sp_metadata_acs_targets_config_url_over_http_post() -> None:
    acs = _spsso_descriptor(_sp_config()).find(f"{{{_MD}}}AssertionConsumerService")
    assert acs.get("Location") == _ACS_URL
    assert acs.get("Binding") == _POST
    assert acs.get("index") == "0"
    assert acs.get("isDefault") == "true"


def test_generated_sp_metadata_want_assertions_signed_true_reflects_config() -> None:
    assert _spsso_descriptor(_sp_config(want_assertions_signed=True)).get("WantAssertionsSigned") == "true"


def test_generated_sp_metadata_want_assertions_signed_false_reflects_config() -> None:
    assert _spsso_descriptor(_sp_config(want_assertions_signed=False)).get("WantAssertionsSigned") == "false"


def test_generated_sp_metadata_declares_authn_requests_unsigned() -> None:
    # The library emits unsigned AuthnRequests and holds no request-signing key.
    assert _spsso_descriptor(_sp_config()).get("AuthnRequestsSigned") == "false"


def test_generated_sp_metadata_omits_key_descriptor() -> None:
    # No SP signing or encryption certificate is configured, so none is published.
    assert _spsso_descriptor(_sp_config()).find(f"{{{_MD}}}KeyDescriptor") is None
