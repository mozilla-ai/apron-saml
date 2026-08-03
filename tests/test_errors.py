import pytest

from apron_saml import (
    AssertionExpiredError,
    AudienceMismatchError,
    InResponseToError,
    MalformedResponseError,
    MetadataError,
    RecipientMismatchError,
    ReplayError,
    SamlError,
    SignatureError,
    StatusError,
)

# The concrete rejection types the library raises; callers catch them individually or, uniformly,
# as SamlError.
_CONCRETE_ERRORS = (
    MetadataError,
    MalformedResponseError,
    StatusError,
    SignatureError,
    AssertionExpiredError,
    AudienceMismatchError,
    RecipientMismatchError,
    InResponseToError,
    ReplayError,
)


def test_saml_error_derives_from_builtin_exception() -> None:
    assert issubclass(SamlError, Exception)


@pytest.mark.parametrize("error_type", _CONCRETE_ERRORS)
def test_every_concrete_error_derives_from_saml_error(error_type: type[SamlError]) -> None:
    assert issubclass(error_type, SamlError)


@pytest.mark.parametrize("error_type", _CONCRETE_ERRORS)
def test_concrete_error_is_catchable_as_saml_error(error_type: type[SamlError]) -> None:
    with pytest.raises(SamlError):
        raise error_type("domain condition")


@pytest.mark.parametrize("error_type", _CONCRETE_ERRORS)
def test_concrete_error_preserves_its_message(error_type: type[SamlError]) -> None:
    message = "domain condition"
    assert str(error_type(message)) == message
