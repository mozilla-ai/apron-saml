from dataclasses import FrozenInstanceError

import pytest

from apron_saml import IdPDescriptor, SamlIdentity

_NAME_ID = "user@example.com"
_ISSUER = "https://idp.example.com/entity"


def test_saml_identity_exposes_required_subject_and_issuer() -> None:
    identity = SamlIdentity(name_id=_NAME_ID, issuer=_ISSUER)
    assert identity.name_id == _NAME_ID
    assert identity.issuer == _ISSUER


def test_saml_identity_optional_fields_default_to_none_and_empty() -> None:
    identity = SamlIdentity(name_id=_NAME_ID, issuer=_ISSUER)
    assert identity.name_id_format is None
    assert identity.email is None
    assert identity.attributes == {}
    assert identity.session_index is None


def test_saml_identity_accepts_all_fields() -> None:
    fmt = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
    identity = SamlIdentity(
        name_id=_NAME_ID,
        issuer=_ISSUER,
        name_id_format=fmt,
        email=_NAME_ID,
        attributes={"groups": ["admins", "users"], "department": ["eng"]},
        session_index="_session-123",
    )
    assert identity.name_id_format == fmt
    assert identity.email == _NAME_ID
    assert identity.attributes["groups"] == ["admins", "users"]
    assert identity.session_index == "_session-123"


def test_saml_identity_requires_issuer() -> None:
    with pytest.raises(TypeError):
        SamlIdentity(name_id=_NAME_ID)


def test_saml_identity_attributes_are_per_instance() -> None:
    first = SamlIdentity(name_id="a", issuer=_ISSUER)
    second = SamlIdentity(name_id="b", issuer=_ISSUER)
    assert first.attributes is not second.attributes


def test_saml_identity_is_frozen() -> None:
    identity = SamlIdentity(name_id=_NAME_ID, issuer=_ISSUER)
    attr = "name_id"
    with pytest.raises(FrozenInstanceError):
        setattr(identity, attr, "changed")


def test_idp_descriptor_exposes_entity_and_sso_url() -> None:
    idp = IdPDescriptor(entity_id=_ISSUER, sso_url="https://idp.example.com/sso")
    assert idp.entity_id == _ISSUER
    assert idp.sso_url == "https://idp.example.com/sso"


def test_idp_descriptor_signing_certificates_default_empty() -> None:
    idp = IdPDescriptor(entity_id=_ISSUER, sso_url="https://idp.example.com/sso")
    assert idp.signing_certificates == ()


def test_idp_descriptor_accepts_signing_certificates() -> None:
    idp = IdPDescriptor(
        entity_id=_ISSUER,
        sso_url="https://idp.example.com/sso",
        signing_certificates=("cert-a", "cert-b"),
    )
    assert idp.signing_certificates == ("cert-a", "cert-b")


def test_idp_descriptor_is_frozen() -> None:
    idp = IdPDescriptor(entity_id=_ISSUER, sso_url="https://idp.example.com/sso")
    attr = "entity_id"
    with pytest.raises(FrozenInstanceError):
        setattr(idp, attr, "changed")
