# 4. XML-Signature-Wrapping (XSW) hardening

- Status: Accepted
- Date: 2026-08-11
- Deciders: apron-saml maintainers
- Related: ADR 0001 (XML-security backend), ADR 0003 (assertion signature verification policy), #21, #55

## Context

apron-saml verifies an assertion-level signature (ADR 0003) by driving the vetted backend to check the enveloped signature over the node with the assertion's `ID`, and confirms the signature's `ds:Reference` covers that `ID`. This is necessary but not sufficient against XML-Signature-Wrapping (XSW): an attacker takes a validly-signed assertion, relocates it (into `<Advice>`, a `<ds:Object>`, or a second envelope), and inserts a forged assertion for the application to consume. If the backend's ID-based node resolution can land on a *different* element than the one the application reads, the forged content is trusted under a valid signature.

The signature-verification step alone does not close this: its guarantee is "some element with this `ID` was signed", and the parse step's guarantee is "there is exactly one direct-child `<Assertion>`". Neither rules out a duplicate `ID`, a second assertion elsewhere in the tree, or a second signature planted in an open-content slot — and neither *binds*, by identity, the counted assertion to the one consumed.

Issue #21 makes position integrity explicit. The DoD requires: the consumed element MUST be the signed element (position-aware); select the assertion via an absolute path against a hardened local schema, never `getElementsByTagName`/first-match; reject `>1` Assertion or `>1` Signature where exactly one is expected; and it notes schema validation alone is insufficient.

## Decision

Add a module-private XSW-hardening step, `apron_saml/wrapping.py::reject_signature_wrapping(parsed)`, run in the validation pipeline **after** structural parsing and **before** signature verification. It enforces four checks. Malformed input raises `MalformedResponseError`; a missing or corrupt schema bundle raises `SchemaBundleError`.

1. **Single assertion, bound by identity.** Exactly one `{saml}Assertion` element across `parsed.root.iter()`, **and that element is `parsed.assertion`** (an identity check, not a bare count). `iter()` recurses into `<ds:Signature>`/`<ds:Object>`/`<Advice>`, so a copy hidden in the canonical XSW payload locations is rejected.
2. **ID uniqueness.** Decisively: the consumed assertion's `ID` value must not appear as the value of any attribute on any other element. Additionally (defense-in-depth): no ID-typed attribute value (local name `ID`/`Id`/`xml:id`) is shared by two elements. The uniqueness set is a verified superset of what the backend actually resolves: pysaml2 7.5.0 drives xmlsec1 with `--id-attr:ID ...:Assertion` + `--node-id <assertion ID>` on the signature-verification path (and `--id-attr:Id` on the unrelated decrypt path), so covering `ID`/`Id`/`xml:id` spans every attribute the backend can treat as the resolvable ID. Bare lowercase `id` is excluded from the ID-typed set (not ID-typed without a DTD/schema; appears in XHTML `AttributeValue` content), but the decisive value rule still catches it.
3. **One signature within the assertion subtree.** Exactly one `{ds}Signature` inside `parsed.assertion.iter()`, closing a `<ds:Signature>` planted in an open-content slot. A document-wide one-signature rule is deliberately **not** imposed — an independently signed `<Response>` is legitimate. This check is defense-in-depth: the enveloped-signature digest covers the whole assertion subtree, so a planted second signature perturbs the digest and the cryptographic verification (ADR 0003) already fails regardless of which signature the backend resolves (verified empirically); the structural check makes the rejection explicit and independent of that digest behavior.
4. **Assertion-scoped hardened local schema.** The consumed assertion is validated against a bundled, pinned OASIS SAML assertion XSD (with its xmldsig/xmlenc/xml imports), resolved entirely offline. Validation runs **from the response string** (`is_valid(response_xml, path=<anchored saml:Assertion>, schema_path="saml:Assertion", namespaces=<collected>, allow_empty=False)`); `schema_path` binds the selection to the `Assertion` global-element declaration and enforces the content model (without it, validation is toothless). Because `xmlschema` 2.5.1 collects namespaces `root_only=True`, an `xsi:type` prefix declared *inside* the assertion subtree (idiomatic on `<AttributeValue>`) would otherwise fail to resolve and fail closed; the check therefore seeds `namespaces` with every prefix declaration recovered from the document via `defusedxml` `iterparse` `start-ns` events (first binding wins), merged under the anchored-selection `saml` prefix. A standard XSD type reached through any prefix then validates, while a genuinely-unknown custom type still (correctly) rejects. Any `xmlschema` exception over attacker input is translated to `MalformedResponseError`. Residual, documented limitation: the collected prefix map is flat, so a prefix rebound across sibling subtrees resolves to its outermost binding.

These layer on the signature-side binding already in `signatures.py` (exactly one direct-child `<Signature>`; its single `Reference` equals `#{assertion_id}`). Jointly they establish — **conditional on parser equivalence** (see Consequences) — the invariant: **the element the backend resolves by `ID` is the unique direct-child assertion the application consumes.**

Supporting choices:

- **The primary defence is structural, not schema-based.** Per Somorovsky et al. and OWASP, schema validation is neither necessary nor sufficient against XSW; checks 1–3 plus the signature binding defeat the family. The schema is defence-in-depth, satisfies the DoD's explicit "hardened local schema", and — via the anchored `path`/`schema_path` selection — *is* the "select via absolute path against a hardened local schema" mechanism. It does not validate the assertion's *position* within the Response (that is structural); the enclosing protocol schema is deliberately not loaded.
- **Anchored selection.** The assertion is selected by its qualified direct-child name on the root, returning all matches (exactly one required) — never a descendant or first-match lookup — both in the structural read and in the schema `path`.
- **Assertion-scoped schema, offline and pinned.** `xmlschema` (already a transitive dependency of pysaml2, pure-Python — no `lxml`/compiled footprint, consistent with ADR 0001) is promoted to a declared direct dependency, floored `>=2.5` with **no hard upper cap** — a hard cap in a library propagates resolution conflicts (xmlschema is also a pysaml2 transitive dep), so a content-model canary test guards against a behavior-breaking future major instead. The XSDs are vendored under `apron_saml/schemas/` with rewritten local `schemaLocation` hints; the schema is built once behind a cached accessor located via `importlib.resources`, with `allow="sandbox"` so no resolution can reach the network or be steered by the document's `xsi:schemaLocation`.
- **No new public error type.** Failures raise `MalformedResponseError` (as `parse_response` already does), keeping `SignatureError` for the cryptographic outcome and giving no signature-failure oracle. A missing/corrupt schema bundle is a *distinct internal error* (packaging), not malformed input.
- **`ParsedResponse` carries the parsed root** so the scans operate on the same tree the assertion was located in; the identity check (1) makes the "consumed is a node of the verified document" property enforced rather than assumed.

Response-level signature acceptance (`want_assertions_signed=False`) remains **out of scope** and deferred (ADR 0003): bundling it would double the adversarial matrix, dilute review of the hardening that protects every current user, force the signed-`Response`+`EncryptedAssertion` binding question, and freeze a security-relaxing flag into the public surface before any field demand. The interim gap — that flag currently only warns — is tracked as #55.

## DoD traceability

| DoD clause | Satisfied by |
|---|---|
| consumed element MUST be the signed element | Check 1 identity + Check 2 ID-value uniqueness + Check 3 + ADR-0003 `Reference==#id` + ID-pinned verify (conditional on parser equivalence) |
| absolute path against a hardened local schema; no getElementsByTagName/first-match | Anchored all-matches direct-child selection; Check 4 `path`+`schema_path` against the bundled assertion XSD |
| reject `>1` Assertion | Check 1 |
| reject `>1` Signature where exactly one is expected | ADR-0003 direct-child + Check 3 subtree |
| schema validation alone is insufficient | Schema is defence-in-depth; Checks 1–3 are load-bearing |

## Consequences

- New module `apron_saml/wrapping.py`; `validation.validate_and_extract` wires `parse_response → reject_signature_wrapping → verify_assertion_signature`.
- `response.ParsedResponse` gains an appended `root: Element` field (internal, non-breaking); its docstring notes the `Element` trees are shared mutable views that must not be mutated.
- New vendored schema bundle `apron_saml/schemas/*.xsd` shipped as package data; `schemas/README.md` records provenance, checksums, retrieval date, license, and the `schemaLocation` edits.
- `pyproject.toml`: `xmlschema>=2.5` (no upper cap) added to `[project].dependencies`; package-data extended. No new *system* dependency; the `xmlsec1` runtime requirement is unchanged. **Dependency dossier (verified 2026-08-13):** pure-Python, MIT-licensed; maintained by sissaschool (Davide Brunato); latest upstream 4.3.2 (2026-06-30), actively released; zero open security advisories (GitHub Security Advisories + OSV.dev). The lockfile currently resolves 2.5.1 (the version pysaml2 pulls under the repo's `exclude-newer` policy); the empirical wiring was pinned against that line.
- **Interop tradeoffs (deliberate, fail-closed, tested):** an assertion containing an `<Advice>`-nested `<saml:Assertion>` is rejected (nesting is rare and creates the exact ambiguity XSW exploits); an `AttributeValue` whose `xsi:type` names a type in a namespace outside the bundle is rejected. Both are recorded as interop costs with no XSW-relevant downside; the Okta/Entra/Ping golden-vector suite (Epic 4) is their interop proof.
- **Residual risk:** the checks run on the ElementTree tree while the backend verifies the `response_xml` string via libxml2; the position invariant is conditional on parser equivalence, mitigated today by defusedxml's DTD/entity rejection and closed by the Epic 4 parser-differential suite.
- The exhaustive XSW1–8 adversarial suite, comment-injection, parser-differential, and IdP golden vectors land in Epic 4; #21 ships the hardening plus focused unit tests and no-false-reject interop guards.
- **Reversibility.** The step, the schema bundle, and the carrier change are all module-private behind the `ServiceProvider` facade and the `SamlError` hierarchy, so the policy can evolve without a public-API break.

## References

- Somorovsky, Mayer, Schwenk, Kampmann, Jensen — "On Breaking SAML: Be Whoever You Want to Be" (USENIX Security 2012) — https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky
- OWASP SAML Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- SAML Raider / NetSPI XSW taxonomy (XSW1–XSW8).
- OASIS SAML 2.0 Core §5.4 (XML Signature profile) — https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
