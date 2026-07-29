from datetime import UTC, datetime, timedelta

import pytest

import apron_saml
from apron_saml import (
    MemoryAssertionStore,
    SamlConfig,
    SamlError,
    SamlIdentity,
    ServiceProvider,
)
from apron_saml.errors import SignatureError


def _config() -> SamlConfig:
    return SamlConfig(
        entity_id="https://sp.example.com/metadata",
        acs_url="https://sp.example.com/saml/acs",
        idp_metadata="<md/>",
    )


def test_package_exposes_public_surface() -> None:
    assert apron_saml.__all__
    assert hasattr(apron_saml, "ServiceProvider")


def test_saml_config_rejects_missing_identifier() -> None:
    with pytest.raises(ValueError, match="entity_id"):
        SamlConfig(entity_id="", acs_url="https://sp.example.com/acs", idp_metadata="<md/>")


def test_saml_config_defaults_and_service_provider_wiring() -> None:
    cfg = _config()
    assert cfg.want_assertions_signed is True
    assert cfg.clock_skew == timedelta(minutes=3)
    sp = ServiceProvider(cfg, assertion_store=MemoryAssertionStore())
    assert sp is not None


def test_saml_identity_schema_and_defaults() -> None:
    identity = SamlIdentity(name_id="user@example.com", issuer="https://idp.example.com/entity")
    assert identity.name_id == "user@example.com"
    assert identity.issuer == "https://idp.example.com/entity"
    assert identity.name_id_format is None
    assert identity.email is None
    assert identity.attributes == {}
    assert identity.session_index is None


def test_saml_identity_requires_issuer() -> None:
    with pytest.raises(TypeError):
        SamlIdentity(name_id="user@example.com")


def test_errors_share_a_common_base() -> None:
    assert issubclass(SignatureError, SamlError)


def test_memory_assertion_store_roundtrip() -> None:
    store = MemoryAssertionStore()
    assert store.contains("id-1") is False
    store.add("id-1", datetime.now(UTC) + timedelta(minutes=5))
    assert store.contains("id-1") is True
