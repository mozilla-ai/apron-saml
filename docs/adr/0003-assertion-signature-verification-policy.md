# 3. Assertion signature verification policy

- Status: Accepted
- Date: 2026-08-07
- Deciders: apron-saml maintainers
- Related: ADR 0001 (XML-security backend), ADR 0002 (public API surface), #20, #21

## Context

apron-saml is a stateless, Service-Provider-side SAML 2.0 primitive. Response decoding (#19) base64-decodes a Response, checks the top-level Status, and structurally locates the assertion — but performs **no** authentication. Epic 3 must settle, once, what "this assertion is authentic" means, because every downstream check (`Conditions`, `SubjectConfirmation`, replay prevention, identity assembly) trusts that assertion. Signature verification (#20) is the root of trust.

apron-saml sends its `AuthnRequest` over the HTTP-POST binding (`ProtocolBinding=HTTP-POST`), so the POST-binding profile rules govern the inbound Response.

The open questions: must the `<Assertion>` itself be signed, or is a signed `<Response>` sufficient? And how do we drive the vetted backend (ADR 0001) so we verify against the right key, reject weak algorithms, and bind the signature to the exact element we consume?

## Decision

Require an **assertion-level** signature. The consumed `<Assertion>` MUST carry exactly one valid enveloped XML signature that:

- verifies against the statically-configured IdP certificate(s) (`IdPDescriptor.signing_certificates`), trying each so key rollover is supported;
- **ignores any in-message `<ds:KeyInfo>`** for key selection — trust is pinned to the configured certificates;
- uses an allowed algorithm — RSA or ECDSA with SHA-256 or stronger; **SHA-1 is rejected**;
- **covers the consumed element** — the signature's `ds:Reference` resolves to the assertion's `ID`, which must be present and non-empty.

A signed `<Response>` alone is **not** accepted (see Deferred). Any failure raises `SignatureError` — a single error type across all failure modes, so callers get no signature-failure oracle — with messages in domain terms that never name the backend.

Supporting design choices:

- **One coherent artifact across the parse→verify seam.** `response.parse_response` returns a `ParsedResponse` bundling the exact decoded document with the located assertion, built together, so *the element that is verified is the element that is consumed*. This replaces passing a parsed element and the raw string separately (two representations that could disagree).
- **Deep, private module.** Verification lives in a module-private `apron_saml/signatures.py` behind the `ServiceProvider` facade; the backend (ADR 0001) is never re-exported.

### Rationale

- **Normative.** OASIS SAML 2.0 Profiles §4.1.4.2 (*"The `<Assertion>` element(s) in the `<Response>` MUST be signed, if the HTTP POST binding is used…"*) and §4.1.4.5 (*"If the HTTP POST binding is used to deliver the `<Response>`, the enclosed assertion(s) MUST be signed."*).
- **Interoperable.** Okta, Microsoft Entra/Azure AD, and Google Workspace (by default) all sign the assertion. Google's "Signed response" is unchecked by default (first-party: *"If this is unchecked (the default), only the assertion within the response is signed."*) — response-only signing is an operator opt-in, not the norm.
- **OWASP-aligned defense in depth.** Pin the certificate and ignore in-message `KeyInfo`, verify the `ds:Reference` covers the consumed element (XML Signature Wrapping defense), and reject SHA-1.
- **Fail-closed by default;** any relaxation is explicit and documented, never silent.

### Deferred: response-level acceptance (`want_assertions_signed=False`)

Accepting a signed `<Response>` that provably covers the assertion is a predictable need for a public SDK (e.g. an operator who ticked Google's "Signed response"). It depends on the same coverage/wrapping verification as #21 (XSW hardening), so it is deferred to a **follow-up issue coupled to #21**. Until it lands:

- verification always requires the assertion-level signature (the invariant above);
- `want_assertions_signed=False` does **not** silently weaken behavior — `ServiceProvider` warns at construction that response-level acceptance is not yet implemented and assertion signatures are still required; `SamlConfig` and the README document the same. The surprise, if any, is in the safe (stricter) direction.

## Consequences

- New module `apron_saml/signatures.py`: `verify_assertion_signature(parsed, idp)`.
- `response.parse_response` returns `ParsedResponse` (internal, non-breaking refactor of #19).
- `ServiceProvider.__init__` emits the `want_assertions_signed=False` warning; `SamlConfig` docstring + README record the current contract.
- A follow-up issue tracks response-level acceptance (with #21).
- **CI:** #20 is the first runtime use of the `xmlsec1` binary (ADR 0001) — the system-package step must actually provision it on ubuntu and macos.
- **Reversibility.** The verifier and the `ParsedResponse` carrier are module-private; the policy sits behind the `ServiceProvider` facade and the `SamlError` hierarchy, so it can evolve without a public-API break.

## References

- OASIS SAML 2.0 Profiles §4.1.4.2 / §4.1.4.5 — https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf
- OWASP SAML Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- Google Workspace custom SAML app, "Signed response" default (first-party) — https://support.google.com/a/answer/6087519
- authentik #22811 (corroborating Google default = assertion-signed) — https://github.com/goauthentik/authentik/issues/22811
