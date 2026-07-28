import os

import pytest

pytestmark = pytest.mark.integration

_ENABLED = os.environ.get("APRON_SAML_INTEGRATION_TESTS") == "1"


@pytest.mark.skipif(not _ENABLED, reason="set APRON_SAML_INTEGRATION_TESTS=1 to run live-IdP tests")
def test_mocksaml_round_trip():
    # Target: SP-initiated round-trip against https://mocksaml.com once Epic 2/3 flows exist.
    # Prefer a pinned self-hosted boxyhq/mock-saml in CI over the public host.
    pytest.skip("SP flows not yet implemented (Epic 2/3)")
