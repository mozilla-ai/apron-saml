from datetime import UTC, datetime, timedelta

import pytest

import apron_saml
from apron_saml import MemoryAssertionStore, SamlConfig, SamlError, ServiceProvider
from apron_saml.errors import SignatureError


def _config() -> SamlConfig:
    return SamlConfig(
        entity_id="https://sp.example.com/metadata",
        acs_url="https://sp.example.com/saml/acs",
        idp_metadata="<md/>",
    )


def test_package_exposes_public_surface():
    assert apron_saml.__all__
    assert hasattr(apron_saml, "ServiceProvider")


def test_saml_config_rejects_missing_identifier():
    with pytest.raises(ValueError, match="entity_id"):
        SamlConfig(entity_id="", acs_url="https://sp.example.com/acs", idp_metadata="<md/>")


def test_saml_config_defaults_and_service_provider_wiring():
    cfg = _config()
    assert cfg.want_assertions_signed is True
    assert cfg.clock_skew == timedelta(minutes=3)
    sp = ServiceProvider(cfg, assertion_store=MemoryAssertionStore())
    assert sp is not None


def test_errors_share_a_common_base():
    assert issubclass(SignatureError, SamlError)


def test_memory_assertion_store_roundtrip():
    store = MemoryAssertionStore()
    assert store.contains("id-1") is False
    store.add("id-1", datetime.now(UTC) + timedelta(minutes=5))
    assert store.contains("id-1") is True
