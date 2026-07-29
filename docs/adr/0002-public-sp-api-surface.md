# 2. Public SP API surface

- Status: Accepted
- Date: 2026-07-29
- Deciders: apron-saml maintainers
- Supersedes: —
- Related: ADR 0001 (XML-security backend)

## Context

apron-saml is a stateless, Service-Provider-side SAML 2.0 primitive. Before any feature work lands,
the library needs one agreed public surface: the entry point callers construct, the flow methods they
invoke, the result and error types they handle, and the names re-exported from the package root. That
surface shapes every subsequent `feat(...)` change, so it is settled once, here, rather than drifting
type by type.

The scaffold already builds against a proposed surface (bring-up runbook §4). The adoption rule is
that the implementation builds against that proposal unless this ADR records a change: this ADR's job
is to **ratify or amend** it, not to design a new one. Most of the proposal is ratified verbatim; the
open sub-questions are settled below, and exactly one carries a concrete design decision that changes
a type.

The proposal left five points open: facade versus free functions; whether to add a network-fetch
convenience; the package export list; the `SamlConfig` field defaults; and the `SamlIdentity` field
schema. The last is the only genuinely open design question and is treated at length.

## Decision

Ratify the proposed surface (runbook §4) with a single amendment: `SamlIdentity` gains a required
`issuer` field. Each open sub-question is resolved below.

### Facade, not free functions

The public entry point is a single synchronous facade, `ServiceProvider`, constructed from an
immutable `SamlConfig` plus optional caller-provided replay storage and clock:

```python
ServiceProvider(config: SamlConfig, *,
                assertion_store: AssertionStore | None = None,
                clock: Clock | None = None)
```

It exposes the SP flows — `build_authn_request`, `generate_metadata`, `process_response` — and holds
the per-SP configuration and injected collaborators that those flows share. The per-module free
functions (`requests.build_authn_request`, `response.decode_response`, `metadata.generate_sp_metadata`,
`validation.validate_and_extract`) stay internal and are not re-exported.

Rationale: a facade gives consumers one obvious entry point and one place to thread shared state
(config, clock, replay store) rather than passing that state through every free-function call. It also
keeps the backend an implementation detail behind a stable boundary, which ADR 0001 relies on for
reversibility. The one exception is `parse_idp_metadata`, a genuinely stateless helper re-exported so a
caller can parse IdP metadata into an `IdPDescriptor` without constructing a full `ServiceProvider`; it
takes no SP state and so does not belong behind the facade.

### No network I/O; no `metadata_from_url()` in v1

The library performs zero network I/O. The caller fetches IdP metadata and passes the XML string in via
`SamlConfig.idp_metadata`; `parse_idp_metadata` likewise takes a string. We do **not** add a
`metadata_from_url()` convenience for v1.

Rationale: a stateless protocol primitive should not own HTTP. Keeping I/O out keeps the core
dependency-light and trivially testable, avoids taking on an HTTP client and its retry/timeout/TLS
surface, and matches the "never a service" stance — the consuming application (onoma) owns fetching.
The convenience can be added later behind an injected client without breaking the surface, so declining
it now costs nothing.

### Public export list

The package root re-exports exactly the proposed surface (runbook §4c), which the scaffold's `__all__`
already realizes: `ServiceProvider`, `SamlConfig`, `SamlIdentity`, `IdPDescriptor`, `AuthnRequest`,
`parse_idp_metadata`, the full `SamlError` hierarchy (`SamlError`, `MalformedResponseError`,
`StatusError`, `SignatureError`, `AssertionExpiredError`, `AudienceMismatchError`,
`RecipientMismatchError`, `InResponseToError`, `ReplayError`), the `AssertionStore` and `Clock`
protocols, and `MemoryAssertionStore`. Everything else (`response`, `validation` internals) stays
module-private. This is ratified unchanged.

### `SamlConfig` fields and defaults

The immutable `SamlConfig` is ratified field-for-field, with these defaults:

| Field | Default | Note |
|---|---|---|
| `entity_id` | — (required) | This SP's entityID. Validated non-empty at construction. |
| `acs_url` | — (required) | Assertion Consumer Service URL. Validated non-empty at construction. |
| `idp_metadata` | — (required) | IdP metadata XML the caller fetched. Validated non-empty at construction. |
| `want_assertions_signed` | `True` | Secure default: require signed assertions. |
| `clock_skew` | `timedelta(minutes=3)` | Tolerance for `NotBefore`/`NotOnOrAfter`. Convention, not spec-mandated. |
| `allow_idp_initiated` | `False` | Secure default: IdP-initiated SSO carries a documented replay risk and is deferred. |
| `decrypt_key` | `None` | PEM key enabling the encrypted-assertion path; off unless configured. |

The three identifiers are validated non-empty at construction (fail fast on unusable config). The
defaults are chosen to fail closed: signatures required, IdP-initiated flows off, decryption off unless
a key is supplied. `clock_skew` defaults to three minutes; SAML 2.0 does not mandate a skew tolerance,
so this is a convention balancing tolerance for real-world clock drift against the replay window it
opens. Callers may narrow or widen it.

### `SamlIdentity` field schema

This is the one open design question, and the sole amendment. The runbook (§6, Epic 1) intends
`SamlIdentity` to carry a NameID/subject, an attributes map, an email convenience, and a *tenancy hint*;
the scaffold placeholder omitted any tenancy hint. This ADR defines the schema and fills that gap:

```python
@dataclass(frozen=True)
class SamlIdentity:
    name_id: str
    issuer: str
    name_id_format: str | None = None
    email: str | None = None
    attributes: dict[str, list[str]] = field(default_factory=dict)
    session_index: str | None = None
```

| Field | Type | Meaning |
|---|---|---|
| `name_id` | `str` | The Subject `<NameID>` value. Always present in a validated assertion. |
| `issuer` | `str` | The `<Issuer>` entityID — the IdP whose configured certificate signed the assertion. |
| `name_id_format` | `str \| None` | The NameID `Format` URI; needed to interpret `name_id` (persistent, transient, emailAddress, unspecified). Optional: IdPs may omit it. |
| `email` | `str \| None` | A normalized, provider-neutral email convenience. |
| `attributes` | `dict[str, list[str]]` | The raw `AttributeStatement`, keyed by attribute name, multi-valued. |
| `session_index` | `str \| None` | The `AuthnStatement` `SessionIndex`. |

The tenancy-hint decision is the substantive one. Unlike OAuth/OIDC — where providers expose
well-known tenant claims (Google `hd`, Microsoft `tid`) — SAML defines **no** standard tenant claim.
The honest, always-present tenant discriminator in a SAML assertion is the `<Issuer>` entityID: in
enterprise SSO each customer configures its own IdP connection, so one issuer entityID maps to one
tenant, and it is exactly the entityID whose statically-configured certificate validated the assertion
(ADR 0001, and the Epic 3 signature checks). We therefore surface `issuer` as a first-class field and
stop there.

We deliberately do **not** add a normalized `tenancy`/`hosted_domain` field or any provider-specific
claim field. A normalized tenancy field would have to guess which custom attribute is "the tenant,"
which is per-deployment and not spec-defined; and provider-specific tenant assertions are plural and
unordered (an Entra tenant asserts several verified domains), so collapsing them into one field answers
downstream domain gates arbitrarily. Any richer tenancy signal remains available as raw entries in
`attributes`, and normalization is the consuming application's (onoma's) job — matching the rule that
apron-* libraries stay flat and independent and composition happens in onoma. `issuer` is made
**required** (not defaulted) because it is a spec-required element that is always known by the time an
assertion has been validated; encoding it as required states that invariant in the type.

`email` is kept as a provider-neutral convenience: the field name names no provider claim, and *which*
source (an emailAddress-format NameID, or a `mail`/`email` attribute) populates it is assembly logic,
resolved in the assemble step (#26), not a schema concern. Likewise the attribute-keying policy (URI
`Name` versus `FriendlyName`) is an assembly concern for #26, not fixed here. `session_index` is
retained even though Single Logout is deferred (Epic 5): it is a standard element already present in
the assertion and cheap to capture, so surfacing it now avoids a later schema change when SLO lands.

Scope note: this ADR defines the field schema (names and types) only. The concrete type definition
lands in #14 and the population/assembly logic in #26; this PR amends only the scaffold dataclass so the
skeleton and this ADR agree.

## Consequences

- **`src/apron_saml/models.py`**: `SamlIdentity` gains a required `issuer: str` field, positioned after
  `name_id`. This is the only code change to the surface; every other type is ratified as scaffolded.
- **Package exports (`__init__.py`)**: unchanged — the scaffold's `__all__` already matches the ratified
  export list, and `SamlIdentity` is already exported.
- **Deferred convenience**: no `metadata_from_url()`; the caller owns HTTP. Revisit only if a concrete
  consumer need appears, and add it behind an injected client so the surface stays stable.
- **Downstream issues**: `feat(models): SamlConfig` (#13), `feat(models): SamlIdentity and IdPDescriptor`
  (#14), and `feat(errors): SamlError hierarchy` (#15) build against this ratified surface; the assemble
  step (#26) populates `SamlIdentity`, including choosing the `email` source and the attribute-keying
  policy left open here.
- **Reversibility**: the result types sit behind the `ServiceProvider` facade as plain dataclasses.
  Appending optional fields later is backward-compatible; `name_id` and `issuer` are the required
  invariants a validated identity must carry.
- **Encapsulation**: consistent with ADR 0001, the backend is never re-exported and runtime-visible
  strings describe conditions in domain terms, never naming the backend library.

## References

- Bring-up runbook §4 (proposed public API surface: §4a stance, §4b surface, §4c exports) and §6
  (Epic 1 type intentions), verified 2026-07-28.
- ADR 0001 (XML-security backend) — the facade and `SamlError` hierarchy this surface sits on.
- OASIS SAML 2.0 Core — https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
  (§2.3.3 `<Assertion>`/`<Issuer>`, §2.5.1 `<Conditions>`, §2.4.1.1 `<SubjectConfirmation>`).
