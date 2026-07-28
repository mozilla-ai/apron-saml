# apron-saml

Stateless **Service-Provider-side** SAML 2.0 protocol library: build `AuthnRequest`s, parse IdP
metadata, decode SAML Responses, and validate assertions — as an importable primitive, never a
service.

Part of the `apron-*` family of stateless protocol primitives. Like the others, apron-saml owns
protocol mechanics only: it holds no state, opens no sockets, and persists nothing. Storage,
sessions, and the stateful federation belong to the consuming application.

> **Status: scaffolding.** The public surface below is the *target* API (pending the API-surface
> ADR); most of it currently raises `NotImplementedError`. Track progress in the issue backlog.

## Scope

- **In scope (v1):** SP-side consumption — build authentication requests, parse IdP / generate SP
  metadata, decode Responses, and validate assertions (signature, XML-Signature-Wrapping hardening,
  `Conditions`, `SubjectConfirmation`, replay prevention, optional encrypted-assertion decryption).
- **Out of scope (v1):** issuing assertions (IdP side), Single Logout (SLO), and IdP-initiated SSO —
  deferred; see the backlog.

All XML-security is delegated to a vetted library, never hand-rolled.

## Install

```bash
pip install apron-saml
```

Requires Python 3.11+. Once the XML-security backend lands (tracked in the backlog), a system
`xmlsec`/`libxmlsec1` dependency will be required — installation notes will follow here.

## Usage (target API)

```python
from apron_saml import ServiceProvider, SamlConfig

sp = ServiceProvider(
    SamlConfig(
        entity_id="https://sp.example.com/metadata",
        acs_url="https://sp.example.com/saml/acs",
        idp_metadata=idp_metadata_xml,   # the caller fetches this; apron-saml does no network I/O
    )
)

# Outbound: start an SP-initiated login.
authn = sp.build_authn_request(relay_state="/dashboard")
redirect_to = authn.redirect_url()

# Inbound: decode, fully validate, and extract the identity (or raise a SamlError subclass).
identity = sp.process_response(saml_response_b64, expected_in_response_to=authn.request_id)
```

Every rejection raises a `SamlError` subclass — there are no boolean-returning validators and no
silent failure.

## Development

```bash
make setup   # bootstrap uv + venv + pre-commit
make test    # unit tests
make lint    # ruff + ty via pre-commit
```

## License

Apache-2.0.
