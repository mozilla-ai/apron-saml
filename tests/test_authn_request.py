import base64
import zlib
from urllib.parse import parse_qs, urlsplit
from xml.etree import ElementTree as ET

from apron_saml import AuthnRequest

_SSO_URL = "https://idp.example.com/sso"
_XML = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_id" Version="2.0"/>'


def _authn(*, destination: str = _SSO_URL, relay_state: str | None = None, xml: str = _XML) -> AuthnRequest:
    return AuthnRequest(request_id="_id", xml=xml, destination=destination, relay_state=relay_state)


def _input_value(form_html: str, name: str) -> str | None:
    root = ET.fromstring(f"<root>{form_html}</root>")
    for inp in root.iter("input"):
        if inp.get("name") == name:
            return inp.get("value")
    return None


def _decode_redirect(url: str) -> str:
    params = parse_qs(urlsplit(url).query)
    raw = base64.b64decode(params["SAMLRequest"][0])
    return zlib.decompress(raw, -zlib.MAX_WBITS).decode("utf-8")


# --- HTTP-Redirect binding --------------------------------------------------


def test_redirect_url_deflate_encodes_the_request_xml() -> None:
    assert _decode_redirect(_authn().redirect_url()) == _XML


def test_redirect_url_targets_the_destination() -> None:
    url = _authn().redirect_url()
    assert url.startswith(f"{_SSO_URL}?")
    assert "SAMLRequest" in parse_qs(urlsplit(url).query)


def test_redirect_url_includes_relay_state_when_present() -> None:
    params = parse_qs(urlsplit(_authn(relay_state="return-to-dashboard").redirect_url()).query)
    assert params["RelayState"] == ["return-to-dashboard"]


def test_redirect_url_omits_relay_state_when_absent() -> None:
    assert "RelayState" not in parse_qs(urlsplit(_authn().redirect_url()).query)


def test_redirect_url_appends_to_an_existing_query() -> None:
    url = _authn(destination=f"{_SSO_URL}?foo=bar").redirect_url()
    assert url.startswith(f"{_SSO_URL}?foo=bar&")
    params = parse_qs(urlsplit(url).query)
    assert params["foo"] == ["bar"]
    assert "SAMLRequest" in params


# --- HTTP-POST binding ------------------------------------------------------


def test_post_form_base64_encodes_the_request_xml() -> None:
    value = _input_value(_authn().post_form(), "SAMLRequest")
    assert value is not None
    assert base64.b64decode(value).decode("utf-8") == _XML


def test_post_form_posts_to_the_destination() -> None:
    form = _authn().post_form()
    assert 'method="post"' in form
    assert f'action="{_SSO_URL}"' in form


def test_post_form_includes_relay_state_when_present() -> None:
    assert _input_value(_authn(relay_state="return-to-dashboard").post_form(), "RelayState") == "return-to-dashboard"


def test_post_form_omits_relay_state_when_absent() -> None:
    assert _input_value(_authn().post_form(), "RelayState") is None


def test_post_form_auto_submits() -> None:
    form = _authn().post_form()
    assert "<script" in form
    assert ".submit()" in form


def test_post_form_escapes_relay_state_to_prevent_injection() -> None:
    injection = '"><script>alert(1)</script>'
    form = _authn(relay_state=injection).post_form()
    assert "<script>alert(1)</script>" not in form
    assert _input_value(form, "RelayState") == injection


def test_post_form_escapes_the_destination() -> None:
    form = _authn(destination='https://idp.example.com/sso"><script>alert(1)</script>').post_form()
    assert "<script>alert(1)</script>" not in form


def test_post_form_has_an_always_visible_submit_fallback() -> None:
    form = _authn().post_form()
    assert "<noscript>" not in form
    root = ET.fromstring(f"<root>{form}</root>")
    submits = [inp for inp in root.iter("input") if inp.get("type") == "submit"]
    assert len(submits) == 1


def test_redirect_url_avoids_a_double_question_mark_on_a_bare_query() -> None:
    url = _authn(destination=f"{_SSO_URL}?").redirect_url()
    assert "??" not in url
    assert "SAMLRequest" in parse_qs(urlsplit(url).query)
    assert _decode_redirect(url) == _XML


def test_redirect_url_places_params_before_a_fragment() -> None:
    url = _authn(destination=f"{_SSO_URL}#frag").redirect_url()
    split = urlsplit(url)
    assert split.fragment == "frag"
    assert "SAMLRequest" in parse_qs(split.query)
    assert _decode_redirect(url) == _XML
