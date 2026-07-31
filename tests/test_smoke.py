from datetime import UTC, datetime, timedelta

import pytest

import apron_saml
from apron_saml import (
    MemoryAssertionStore,
    SamlConfig,
    ServiceProvider,
)

# The public surface ratified by ADR 0002 (§4c export list).
EXPECTED_EXPORTS = {
    "AssertionExpiredError",
    "AssertionStore",
    "AudienceMismatchError",
    "AuthnRequest",
    "Clock",
    "IdPDescriptor",
    "InResponseToError",
    "MalformedResponseError",
    "MemoryAssertionStore",
    "RecipientMismatchError",
    "ReplayError",
    "SamlConfig",
    "SamlError",
    "SamlIdentity",
    "ServiceProvider",
    "SignatureError",
    "StatusError",
    "parse_idp_metadata",
}


class _FixedClock:
    """Deterministic Clock returning a fixed moment."""

    def __init__(self, moment: datetime) -> None:
        self._moment = moment

    def now(self) -> datetime:
        return self._moment


def _config() -> SamlConfig:
    """Return a minimal valid SamlConfig for tests."""
    return SamlConfig(
        entity_id="https://sp.example.com/metadata",
        acs_url="https://sp.example.com/saml/acs",
        idp_metadata="<md/>",
    )


def test_package_exposes_public_surface() -> None:
    assert set(apron_saml.__all__) == EXPECTED_EXPORTS
    assert len(apron_saml.__all__) == len(EXPECTED_EXPORTS)
    for name in EXPECTED_EXPORTS:
        assert hasattr(apron_saml, name), name


def test_saml_config_rejects_missing_identifier() -> None:
    with pytest.raises(ValueError, match="entity_id"):
        SamlConfig(entity_id="", acs_url="https://sp.example.com/acs", idp_metadata="<md/>")


def test_saml_config_defaults_and_service_provider_wiring() -> None:
    cfg = _config()
    assert cfg.want_assertions_signed is True
    assert cfg.clock_skew == timedelta(minutes=3)
    assert cfg.allow_idp_initiated is False
    assert cfg.decrypt_key is None
    clock = _FixedClock(datetime(2026, 1, 1, tzinfo=UTC))
    sp = ServiceProvider(cfg, assertion_store=MemoryAssertionStore(), clock=clock)
    assert sp is not None


def test_memory_assertion_store_roundtrip() -> None:
    store = MemoryAssertionStore()
    assert store.contains("id-1") is False
    store.add("id-1", datetime.now(UTC) + timedelta(minutes=5))
    assert store.contains("id-1") is True
