import pytest
from defusedxml.ElementTree import fromstring

from apron_saml import SignatureError
from apron_saml.signatures import _require_strong_algorithms

_DS = "http://www.w3.org/2000/09/xmldsig#"

_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
_RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
_SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1"


def _sig(sig_alg: str, digest_alg: str):
    xml = (
        f'<ds:Signature xmlns:ds="{_DS}"><ds:SignedInfo>'
        f'<ds:SignatureMethod Algorithm="{sig_alg}"/>'
        f'<ds:Reference URI="#_a1"><ds:DigestMethod Algorithm="{digest_alg}"/></ds:Reference>'
        f"</ds:SignedInfo></ds:Signature>"
    )
    return fromstring(xml)


def test_accepts_sha256() -> None:
    _require_strong_algorithms(_sig(_RSA_SHA256, _SHA256))  # no raise


def test_rejects_sha1_signature() -> None:
    with pytest.raises(SignatureError):
        _require_strong_algorithms(_sig(_RSA_SHA1, _SHA256))


def test_rejects_sha1_digest() -> None:
    with pytest.raises(SignatureError):
        _require_strong_algorithms(_sig(_RSA_SHA256, _SHA1))
