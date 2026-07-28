"""Parsing identity-provider metadata and generating service-provider metadata."""

from __future__ import annotations

from apron_saml.models import IdPDescriptor, SamlConfig


def parse_idp_metadata(xml: str) -> IdPDescriptor:
    """Parse IdP metadata XML into the entity ID, SSO URL, and signing certificates an SP needs."""
    raise NotImplementedError


def generate_sp_metadata(config: SamlConfig) -> str:
    """Generate this service provider's SAML metadata document as an XML string."""
    raise NotImplementedError
