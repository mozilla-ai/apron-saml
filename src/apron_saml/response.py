"""Decoding a SAML Response from its transport encoding and locating its assertion (internal)."""

from __future__ import annotations

import base64
import zlib
from xml.etree.ElementTree import Element, ParseError

from defusedxml.ElementTree import fromstring as parse_safe_xml

from apron_saml.errors import MalformedResponseError, StatusError

# SAML 2.0 protocol and assertion namespaces, for navigating a <Response> and its <Assertion>.
_SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
_SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"

# The one top-level <StatusCode> value that admits an assertion; any other denotes a failed Response.
_STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"

# Characters that may precede the root element of a decoded XML document: a UTF-8 BOM and whitespace.
_XML_PROLOGUE = "\ufeff \t\r\n"

# Upper bound on the inflated size of a DEFLATE-compressed (HTTP-Redirect) Response. Inflating without
# a cap lets a small payload amplify into a memory-exhaustion denial of service (CWE-409); the bound
# sits well above any legitimate Response. Limiting the overall request size remains the caller's job.
_MAX_INFLATED_BYTES = 5 * 1024 * 1024


def decode_response(saml_response_b64: str) -> str:
    """Base64-decode (and inflate when required) a SAML Response into its XML string.

    Reverses the transport encoding of the ``SAMLResponse`` message. The HTTP-POST binding carries
    the response XML as plain base64; the HTTP-Redirect binding DEFLATE-compresses it first. The
    binding is not signaled to this function, so it is inferred from content: a decoded payload that
    is already XML text is returned unchanged, otherwise it is treated as a raw DEFLATE stream and
    inflated. Whitespace within the base64 is tolerated; any other non-alphabet character is rejected.

    Args:
        saml_response_b64: The base64-encoded ``SAMLResponse`` value received at the ACS endpoint.

    Returns:
        The decoded SAML Response as an XML string.

    Raises:
        MalformedResponseError: If the input is blank, is not valid base64, decodes to neither XML
            text nor a single complete DEFLATE-compressed UTF-8 document, or inflates beyond the
            maximum decoded size.
    """
    if not saml_response_b64.strip():
        raise MalformedResponseError("SAML Response is empty")
    try:
        raw = base64.b64decode("".join(saml_response_b64.split()), validate=True)
    except ValueError as e:
        # A non-ASCII value fails base64's ASCII pre-encode with a bare ValueError; incorrect padding
        # or non-alphabet characters raise binascii.Error, a ValueError subclass. Both are caught here.
        raise MalformedResponseError("SAML Response is not valid base64") from e
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if text.lstrip(_XML_PROLOGUE).startswith("<"):
        return text
    # A raw DEFLATE payload (the HTTP-Redirect binding). Inflate under a size cap so a small
    # compressed payload cannot amplify into a memory-exhaustion denial of service.
    decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
    try:
        inflated = decompressor.decompress(raw, _MAX_INFLATED_BYTES)
    except zlib.error as e:
        raise MalformedResponseError("SAML Response is neither an XML document nor a DEFLATE-compressed one") from e
    if decompressor.unconsumed_tail:
        raise MalformedResponseError("SAML Response exceeds the maximum decoded size")
    # decompress() does not raise on a stream that ends early or carries trailing bytes: a truncated
    # stream leaves eof False, and bytes past the stream end land in unused_data. Reject both here so
    # a partial or padded document fails at the decoding boundary rather than later, as invalid XML.
    if not decompressor.eof or decompressor.unused_data:
        raise MalformedResponseError("SAML Response is not a single complete DEFLATE stream")
    try:
        return inflated.decode("utf-8")
    except UnicodeDecodeError as e:
        raise MalformedResponseError("SAML Response did not decode to UTF-8 text") from e


def parse_response(response_xml: str) -> Element:
    """Parse a decoded SAML Response, require a successful top-level Status, and return its assertion.

    Performs the structural read that precedes security validation: it parses the ``<Response>``,
    checks the top-level ``<StatusCode>``, and locates the assertion. The assertion is taken only from
    a direct-child ``<Assertion>`` of the response — never a descendant — and exactly one is required,
    so a response that wraps or duplicates assertions is rejected rather than resolved arbitrarily. No
    signature, ``Conditions``, or ``SubjectConfirmation`` check has run, so the returned element is
    located but not yet trustworthy; authenticating it is the validation pipeline's responsibility.

    Args:
        response_xml: The decoded SAML Response XML, as produced by ``decode_response``.

    Returns:
        The response's single direct-child ``<Assertion>`` element.

    Raises:
        MalformedResponseError: If the input is not well-formed XML, carries a disallowed DTD or
            entity declaration, is not rooted at a ``<Response>``, has no top-level ``<StatusCode>``,
            or does not carry exactly one direct-child ``<Assertion>``.
        StatusError: If the top-level ``<StatusCode>`` is not the success status.
    """
    try:
        response = parse_safe_xml(response_xml)
    except ParseError as e:
        raise MalformedResponseError("SAML Response is not well-formed XML") from e
    except ValueError as e:
        # The XML backend rejects a DTD or entity definition (an XXE/expansion vector) by raising a
        # ValueError subclass; translate it into a domain error rather than leaking it.
        raise MalformedResponseError("SAML Response contains a disallowed DTD or entity declaration") from e

    if response.tag != f"{{{_SAMLP_NS}}}Response":
        raise MalformedResponseError("SAML Response root element is not a Response")

    status_code = response.find(f"{{{_SAMLP_NS}}}Status/{{{_SAMLP_NS}}}StatusCode")
    if status_code is None:
        raise MalformedResponseError("SAML Response has no top-level Status")
    if status_code.get("Value") != _STATUS_SUCCESS:
        raise StatusError("SAML Response carried a non-success status")

    assertions = response.findall(f"{{{_SAML_NS}}}Assertion")
    if len(assertions) != 1:
        raise MalformedResponseError("SAML Response does not carry exactly one assertion")
    return assertions[0]
