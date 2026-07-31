from dataclasses import FrozenInstanceError
from datetime import timedelta

import pytest

from apron_saml import SamlConfig

_ENTITY_ID = "https://sp.example.com/metadata"
_ACS_URL = "https://sp.example.com/saml/acs"
_METADATA = "<EntityDescriptor/>"


def _config(
    *,
    entity_id: str = _ENTITY_ID,
    acs_url: str = _ACS_URL,
    idp_metadata: str = _METADATA,
) -> SamlConfig:
    """Build a valid SamlConfig, overriding only the given string fields."""
    return SamlConfig(entity_id=entity_id, acs_url=acs_url, idp_metadata=idp_metadata)


def test_defaults_are_secure_and_conventional() -> None:
    cfg = _config()
    assert cfg.want_assertions_signed is True
    assert cfg.clock_skew == timedelta(minutes=3)
    assert cfg.allow_idp_initiated is False
    assert cfg.decrypt_key is None


def test_all_valid_fields_accepted() -> None:
    cfg = SamlConfig(
        entity_id=_ENTITY_ID,
        acs_url="http://localhost:8000/acs",
        idp_metadata=_METADATA,
        want_assertions_signed=False,
        clock_skew=timedelta(0),
        allow_idp_initiated=True,
        decrypt_key="placeholder-decrypt-key",
    )
    assert cfg.acs_url == "http://localhost:8000/acs"
    assert cfg.want_assertions_signed is False
    assert cfg.clock_skew == timedelta(0)
    assert cfg.allow_idp_initiated is True
    assert cfg.decrypt_key is not None


def test_config_is_frozen() -> None:
    cfg = _config()
    attr = "entity_id"
    with pytest.raises(FrozenInstanceError):
        setattr(cfg, attr, "changed")


@pytest.mark.parametrize("blank", ["", "   "])
def test_rejects_blank_entity_id(blank: str) -> None:
    with pytest.raises(ValueError, match="entity_id"):
        _config(entity_id=blank)


@pytest.mark.parametrize("blank", ["", "   "])
def test_rejects_blank_acs_url(blank: str) -> None:
    with pytest.raises(ValueError, match="acs_url"):
        _config(acs_url=blank)


@pytest.mark.parametrize(
    "bad_url",
    [
        "sp.example.com/acs",
        "/saml/acs",
        "ftp://sp.example.com/acs",
        "https://",
        "https://user@/acs",
        "https://:443/acs",
    ],
)
def test_rejects_non_absolute_http_acs_url(bad_url: str) -> None:
    with pytest.raises(ValueError, match="acs_url"):
        _config(acs_url=bad_url)


@pytest.mark.parametrize(
    "url_with_userinfo",
    ["https://user@sp.example.com/acs", "https://admin@sp.example.com:8443/acs"],
)
def test_rejects_acs_url_with_userinfo(url_with_userinfo: str) -> None:
    with pytest.raises(ValueError, match="userinfo"):
        _config(acs_url=url_with_userinfo)


@pytest.mark.parametrize("blank", ["", "   "])
def test_rejects_blank_idp_metadata(blank: str) -> None:
    with pytest.raises(ValueError, match="idp_metadata"):
        _config(idp_metadata=blank)


def test_rejects_non_xml_idp_metadata() -> None:
    with pytest.raises(ValueError, match="idp_metadata"):
        _config(idp_metadata="https://idp.example.com/metadata")


def test_rejects_negative_clock_skew() -> None:
    with pytest.raises(ValueError, match="clock_skew"):
        SamlConfig(
            entity_id=_ENTITY_ID,
            acs_url=_ACS_URL,
            idp_metadata=_METADATA,
            clock_skew=timedelta(seconds=-1),
        )


def test_accepts_zero_clock_skew() -> None:
    cfg = SamlConfig(
        entity_id=_ENTITY_ID,
        acs_url=_ACS_URL,
        idp_metadata=_METADATA,
        clock_skew=timedelta(0),
    )
    assert cfg.clock_skew == timedelta(0)


def test_rejects_blank_decrypt_key() -> None:
    with pytest.raises(ValueError, match="decrypt_key"):
        SamlConfig(
            entity_id=_ENTITY_ID,
            acs_url=_ACS_URL,
            idp_metadata=_METADATA,
            decrypt_key="   ",
        )
