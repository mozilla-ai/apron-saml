"""Decoding SAML Responses from their transport encoding (internal)."""

from __future__ import annotations


def decode_response(saml_response_b64: str) -> str:
    """Base64-decode (and inflate when required) a SAML Response into its XML string."""
    raise NotImplementedError
