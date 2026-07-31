"""Stateless SP-side SAML 2.0 protocol library."""

from __future__ import annotations

from apron_saml.errors import (
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
from apron_saml.metadata import parse_idp_metadata
from apron_saml.models import AuthnRequest, IdPDescriptor, SamlConfig, SamlIdentity
from apron_saml.protocols import AssertionStore, Clock
from apron_saml.service_provider import ServiceProvider
from apron_saml.stores import MemoryAssertionStore

__all__ = [
    "AssertionExpiredError",
    "AssertionStore",
    "AudienceMismatchError",
    "AuthnRequest",
    "Clock",
    "IdPDescriptor",
    "InResponseToError",
    "MalformedResponseError",
    "MemoryAssertionStore",
    "MetadataError",
    "RecipientMismatchError",
    "ReplayError",
    "SamlConfig",
    "SamlError",
    "SamlIdentity",
    "ServiceProvider",
    "SignatureError",
    "StatusError",
    "parse_idp_metadata",
]
