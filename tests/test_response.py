import base64
import zlib

import pytest

from apron_saml import MalformedResponseError, SamlError, StatusError
from apron_saml.response import _MAX_INFLATED_BYTES, decode_response, parse_response

_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"

_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"
_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"


def _assertion(assertion_id: str = "_assertion") -> str:
    return f'<saml:Assertion ID="{assertion_id}"/>'


def _status(value: str = _SUCCESS, *, nested: str | None = None) -> str:
    inner = f'<samlp:StatusCode Value="{nested}"/>' if nested is not None else ""
    return f'<samlp:Status><samlp:StatusCode Value="{value}">{inner}</samlp:StatusCode></samlp:Status>'


def _response(*, status: str | None = None, body: str | None = None) -> str:
    status_xml = _status() if status is None else status
    body_xml = _assertion() if body is None else body
    return (
        f'<samlp:Response xmlns:samlp="{_SAMLP}" xmlns:saml="{_SAML}" ID="_r1" Version="2.0">'
        f"<saml:Issuer>https://idp.example.com/entity</saml:Issuer>"
        f"{status_xml}"
        f"{body_xml}"
        f"</samlp:Response>"
    )


def _b64(xml: str) -> str:
    return base64.b64encode(xml.encode("utf-8")).decode("ascii")


def _deflate_bytes_b64(data: bytes) -> str:
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return base64.b64encode(compressor.compress(data) + compressor.flush()).decode("ascii")


def _deflate_b64(xml: str) -> str:
    return _deflate_bytes_b64(xml.encode("utf-8"))


# --- decode_response ---------------------------------------------------------------------------


def test_decode_returns_xml_for_post_binding_base64() -> None:
    xml = _response()
    assert decode_response(_b64(xml)) == xml


def test_decode_inflates_redirect_binding_payload() -> None:
    xml = _response()
    assert decode_response(_deflate_b64(xml)) == xml


def test_decode_tolerates_whitespace_in_base64() -> None:
    xml = _response()
    encoded = _b64(xml)
    wrapped = "\n".join(encoded[i : i + 64] for i in range(0, len(encoded), 64))
    assert decode_response(wrapped) == xml


def test_decode_rejects_blank_input() -> None:
    with pytest.raises(MalformedResponseError):
        decode_response("   ")


def test_decode_rejects_invalid_base64() -> None:
    with pytest.raises(MalformedResponseError):
        decode_response("not valid base64 %%%")


def test_decode_rejects_payload_that_is_neither_xml_nor_deflate() -> None:
    payload = base64.b64encode(b"\xff\xfe\x00\x01 not xml or deflate").decode("ascii")
    with pytest.raises(MalformedResponseError):
        decode_response(payload)


def test_decode_rejects_decompression_bomb() -> None:
    # A tiny DEFLATE payload inflating past the cap must be rejected, not expanded into memory.
    bomb = _deflate_bytes_b64(b"A" * (_MAX_INFLATED_BYTES + 1))
    with pytest.raises(MalformedResponseError):
        decode_response(bomb)


def test_decode_rejects_non_ascii_input() -> None:
    # A non-ASCII value fails base64's ASCII pre-encode; it must still surface as a domain error.
    with pytest.raises(MalformedResponseError):
        decode_response("abéd")


def test_decode_rejects_truncated_deflate_stream() -> None:
    truncated = base64.b64decode(_deflate_b64(_response()))[:-3]
    with pytest.raises(MalformedResponseError):
        decode_response(base64.b64encode(truncated).decode("ascii"))


def test_decode_rejects_deflate_with_trailing_garbage() -> None:
    padded = base64.b64decode(_deflate_b64(_response())) + b"\x00\x01\x02"
    with pytest.raises(MalformedResponseError):
        decode_response(base64.b64encode(padded).decode("ascii"))


def test_decode_rejects_deflate_payload_that_is_not_utf8() -> None:
    payload = _deflate_bytes_b64(b"\xff\xfe\x00\x01")
    with pytest.raises(MalformedResponseError):
        decode_response(payload)


def test_decode_malformed_error_is_catchable_as_saml_error() -> None:
    with pytest.raises(SamlError):
        decode_response("   ")


# --- parse_response ----------------------------------------------------------------------------


def test_parse_returns_the_assertion_element() -> None:
    assert parse_response(_response()).assertion.tag == f"{{{_SAML}}}Assertion"


def test_parse_returns_the_direct_child_assertion() -> None:
    assert parse_response(_response(body=_assertion("_real"))).assertion.get("ID") == "_real"


def test_parsed_response_carries_source_document() -> None:
    xml = _response()
    assert parse_response(xml).response_xml == xml


def test_decode_then_parse_roundtrip() -> None:
    parsed = parse_response(decode_response(_b64(_response(body=_assertion("_a1")))))
    assert parsed.assertion.get("ID") == "_a1"


def test_parse_rejects_non_success_status() -> None:
    with pytest.raises(StatusError):
        parse_response(_response(status=_status(_RESPONDER)))


def test_parse_reads_top_level_status_ignoring_nested_status_code() -> None:
    # A top-level Responder failure with a nested Success second-level code is still a failure.
    failure = _status(_RESPONDER, nested=_SUCCESS)
    with pytest.raises(StatusError):
        parse_response(_response(status=failure))


def test_status_error_is_catchable_as_saml_error() -> None:
    with pytest.raises(SamlError):
        parse_response(_response(status=_status(_REQUESTER)))


def test_parse_rejects_missing_status() -> None:
    with pytest.raises(MalformedResponseError):
        parse_response(_response(status=""))


def test_parse_rejects_non_response_root() -> None:
    with pytest.raises(MalformedResponseError):
        parse_response(f'<samlp:LogoutResponse xmlns:samlp="{_SAMLP}"/>')


def test_parse_rejects_malformed_xml() -> None:
    with pytest.raises(MalformedResponseError):
        parse_response("<samlp:Response><unclosed>")


def test_parse_rejects_response_with_entity_declaration() -> None:
    # A DTD with an internal entity definition (billion-laughs/XXE vector) is a domain error.
    xml = (
        f'<!DOCTYPE Response [<!ENTITY x "y">]>'
        f'<samlp:Response xmlns:samlp="{_SAMLP}" xmlns:saml="{_SAML}">'
        f"{_status()}{_assertion()}</samlp:Response>"
    )
    with pytest.raises(MalformedResponseError):
        parse_response(xml)


def test_parse_rejects_response_with_external_entity() -> None:
    xml = (
        f'<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        f'<samlp:Response xmlns:samlp="{_SAMLP}" xmlns:saml="{_SAML}">'
        f"{_status()}<saml:Issuer>&xxe;</saml:Issuer>{_assertion()}</samlp:Response>"
    )
    with pytest.raises(MalformedResponseError):
        parse_response(xml)


def test_parse_rejects_response_without_assertion() -> None:
    with pytest.raises(MalformedResponseError):
        parse_response(_response(body=""))


def test_parse_rejects_response_with_multiple_assertions() -> None:
    with pytest.raises(MalformedResponseError):
        parse_response(_response(body=_assertion("_a1") + _assertion("_a2")))


def test_parse_takes_direct_child_over_nested_decoy_assertion() -> None:
    # An assertion smuggled beneath a wrapper must not be selected; the direct child wins.
    body = _assertion("_real") + f"<samlp:Extensions>{_assertion('_fake')}</samlp:Extensions>"
    assert parse_response(_response(body=body)).assertion.get("ID") == "_real"


def test_parse_rejects_when_only_assertion_is_nested() -> None:
    # A wrapped assertion with no direct-child assertion is rejected, not resolved by deep search.
    body = f"<samlp:Extensions>{_assertion('_fake')}</samlp:Extensions>"
    with pytest.raises(MalformedResponseError):
        parse_response(_response(body=body))


def test_parsed_response_carries_root_element() -> None:
    parsed = parse_response(_response())
    assert parsed.root.tag == f"{{{_SAMLP}}}Response"
    assert parsed.assertion in list(parsed.root)
