import base64
import zlib
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit
from xml.etree import ElementTree as ET

from apron_saml import IdPDescriptor, SamlConfig
from apron_saml.requests import build_authn_request

_ENTITY_ID = "https://sp.example.com/metadata"
_ACS_URL = "https://sp.example.com/saml/acs"
_SSO_URL = "https://idp.example.com/sso"
_METADATA = "<EntityDescriptor/>"

_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
_DSIG = "http://www.w3.org/2000/09/xmldsig#"
_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"


class _FixedClock:
    """Deterministic Clock returning a fixed moment."""

    def __init__(self, moment: datetime) -> None:
        self._moment = moment

    def now(self) -> datetime:
        return self._moment


def _config() -> SamlConfig:
    return SamlConfig(entity_id=_ENTITY_ID, acs_url=_ACS_URL, idp_metadata=_METADATA)


def _idp() -> IdPDescriptor:
    return IdPDescriptor(entity_id="https://idp.example.com/entity", sso_url=_SSO_URL)


def _root(xml: str) -> ET.Element:
    return ET.fromstring(xml)


def test_request_id_is_persisted_and_matches_xml() -> None:
    authn = build_authn_request(_config(), _idp())
    assert authn.request_id
    assert _root(authn.xml).get("ID") == authn.request_id


def test_request_id_is_a_valid_ncname() -> None:
    request_id = build_authn_request(_config(), _idp()).request_id
    assert request_id[0] == "_" or request_id[0].isalpha()
    assert ":" not in request_id


def test_request_ids_are_unique() -> None:
    ids = {build_authn_request(_config(), _idp()).request_id for _ in range(5)}
    assert len(ids) == 5


def test_xml_is_a_saml2_authn_request() -> None:
    root = _root(build_authn_request(_config(), _idp()).xml)
    assert root.tag == f"{{{_SAMLP}}}AuthnRequest"
    assert root.get("Version") == "2.0"


def test_destination_is_the_idp_sso_url() -> None:
    authn = build_authn_request(_config(), _idp())
    assert authn.destination == _SSO_URL
    assert _root(authn.xml).get("Destination") == _SSO_URL


def test_xml_names_the_sp_as_issuer() -> None:
    issuer = _root(build_authn_request(_config(), _idp()).xml).find(f"{{{_SAML}}}Issuer")
    assert issuer is not None
    assert issuer.text == _ENTITY_ID


def test_xml_directs_the_response_to_the_acs_over_the_post_binding() -> None:
    root = _root(build_authn_request(_config(), _idp()).xml)
    assert root.get("AssertionConsumerServiceURL") == _ACS_URL
    assert root.get("ProtocolBinding") == _HTTP_POST


def test_issue_instant_uses_the_injected_clock() -> None:
    clock = _FixedClock(datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC))
    authn = build_authn_request(_config(), _idp(), clock=clock)
    assert _root(authn.xml).get("IssueInstant") == "2026-01-02T03:04:05Z"


def test_request_is_unsigned() -> None:
    authn = build_authn_request(_config(), _idp())
    assert "Signature" not in authn.xml
    assert _root(authn.xml).find(f"{{{_DSIG}}}Signature") is None


def test_relay_state_is_carried_onto_the_result() -> None:
    authn = build_authn_request(_config(), _idp(), relay_state="return-to-dashboard")
    assert authn.relay_state == "return-to-dashboard"


def test_relay_state_defaults_to_none() -> None:
    assert build_authn_request(_config(), _idp()).relay_state is None


def test_built_request_roundtrips_through_the_redirect_binding() -> None:
    authn = build_authn_request(_config(), _idp())
    params = parse_qs(urlsplit(authn.redirect_url()).query)
    raw = base64.b64decode(params["SAMLRequest"][0])
    assert zlib.decompress(raw, -zlib.MAX_WBITS).decode("utf-8") == authn.xml
