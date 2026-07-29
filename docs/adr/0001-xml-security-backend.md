# 1. XML-security backend: pysaml2

- Status: Accepted
- Date: 2026-07-28
- Deciders: apron-saml maintainers
- Supersedes: —
- Related: ADR 0002 (public SP API surface)

## Context

apron-saml is a stateless, Service-Provider-side SAML 2.0 primitive. All XML-security work
(canonicalization, XML-Signature verification, and `EncryptedAssertion` decryption) is delegated to a
vetted library — never hand-rolled. This ADR picks that library. Its output is concrete: the runtime
dependency in `pyproject.toml` and the system-package step in CI.

Two mature Python options exist:

- **pysaml2** (IdentityPython) — a SAML 2.0 toolkit.
- **python3-saml** (SAML-Toolkits, formerly OneLogin) — an SP-oriented SAML helper.

We spiked both on 2026-07-28 (evidence in the appendix) and compared them across the five axes below.

### Established fact (not re-litigated)

Both backends require a system xmlsec/libxmlsec1 dependency; it is **not** a differentiator on
"needs a system library at all." pysaml2 shells out to the `xmlsec1` command-line binary at runtime;
python3-saml links compiled `python-xmlsec` bindings against libxml2/libxmlsec1. pysaml2's
alternative pure-crypto `XMLSecurity` backend cannot decrypt `EncryptedAssertion`, so "dodge the
binary entirely" is not a viable option for a real SP. The differentiator is the *shape* of that
dependency (runtime CLI vs build-time native bindings), plus maintenance and API fit.

## Decision

**Use pysaml2** as the XML-security backend, consumed as an internal toolkit behind apron-saml's own
`ServiceProvider` facade and `SamlError` hierarchy. pysaml2 is never re-exported, and its
HTTP-capable helpers are never called — the caller supplies IdP metadata as an XML string, preserving
the "no network I/O in the library" stance.

## Comparison

| Axis | pysaml2 | python3-saml |
|---|---|---|
| xmlsec dependency shape | Runtime `xmlsec1` **CLI binary**; no `python-xmlsec`/`lxml` bindings, installs from prebuilt wheels | Compiled `python-xmlsec` + `lxml` bindings; source build needs libxml2/libxmlsec1 headers |
| Maintenance | Active — v7.5.4 (2025-10) under IdentityPython | Dormant — v1.16.0 (2023-10); OneLogin abandoned it, community fork, single maintainer |
| Encrypted assertions | Supported via the xmlsec1 binary | Supported via `python-xmlsec` |
| XSW/CVE posture | Non-trivial CVE history, all patched; maintained ⇒ future fixes land | Non-trivial CVE history; dormant ⇒ future fixes uncertain |
| API ergonomics | Raises an exception hierarchy; usable as a toolkit | Boolean + `get_errors()` string list; servlet-oriented |

### xmlsec dependency shape

The spike confirmed pysaml2's dependency tree pulls **no** `python-xmlsec`/`lxml` bindings and
installs entirely from prebuilt wheels — the native ones (e.g. `cryptography`, `cffi`) ship compiled
and need no local build toolchain — and it imports with no system xmlsec1 present; the binary is
needed only at runtime for signing/encryption/decryption. In CI this is one `apt-get`/`brew` line and
no XML-security build step.

python3-saml pulls compiled `xmlsec` and `lxml`. Where a prebuilt wheel exists for the platform and
Python version the install is smooth; where one does not, it falls back to a source build requiring
`pkg-config` plus `libxml2-dev` and `libxmlsec1-dev` headers. Across a `[ubuntu, macos] × [3.11,
3.12, 3.13]` matrix this is more moving parts and a larger native-toolchain surface. Both shapes are
manageable; pysaml2's is simpler and more predictable.

### Maintenance

This is the decisive axis. pysaml2 ships regular releases under IdentityPython (v7.5.4, 2025-10).
python3-saml's last release was v1.16.0 (2023-10); after OneLogin stepped back, maintenance moved to
a community fork with limited activity. For security-critical assertion-validation code, a maintained
upstream that ships timely fixes is worth more than any single API convenience.

### Encrypted assertions

Both decrypt `EncryptedAssertion` through their xmlsec backend, so this axis does not separate them.
It does foreclose one option: pysaml2's pure-crypto `XMLSecurity` backend is DSIG-only and cannot
decrypt, so we cannot use it to avoid the `xmlsec1` binary. The binary stays a hard requirement.

### XSW/CVE posture

Both libraries have a non-trivial CVE history (signature-wrapping, comment-injection, and
canonicalization classes). Neither is "clean," and neither choice lets us outsource our security
posture: XML-Signature-Wrapping hardening, ignoring in-message `KeyInfo` for key selection,
verifying against the statically-configured IdP certificate, rejecting SHA-1, and running the full
validation pipeline on the decrypted plaintext all remain apron-saml's responsibility as
defense-in-depth on top of the backend.
Given that, the tie-breaker is again maintenance: the parser-differential and canonicalization attack
classes keep evolving (e.g. the 2025 SAML-SSO-bypass disclosures against other toolkits), and only a
maintained upstream reliably ships fixes for the next one.

### API ergonomics

pysaml2 raises a real exception hierarchy on validation failure (`saml2.SAMLError` →
`SignatureError`, `StatusError`, `VerificationError`, `DecryptError`), and exposes toolkit-level entry
points such as `Saml2Client.parse_authn_request_response`. This maps directly onto apron-saml's
contract — "every rejection raises a `SamlError` subclass, no boolean-returning validators."

python3-saml's `OneLogin_Saml2_Auth` takes a request-data dict and reports failure as an
`is_authenticated()` boolean plus a `get_errors()` list of string codes. Adapting that to an
exception-based contract means translating string codes back into exceptions — friction that works
against the design rather than with it.

## Consequences

- **`pyproject.toml`**: add `pysaml2>=7.5,<8` to `[project].dependencies`; regenerate `uv.lock`.
- **CI (`.github/workflows/ci.yaml`)**: enable the runtime xmlsec1 system-package step on the `test`
  job — `apt-get install -y xmlsec1` (Linux) and `brew install libxmlsec1` (macOS, which provides the
  `xmlsec1` CLI). The step is a no-op until code actually imports the backend, but it is wired now so
  the choice is real and CI is ready for the first `feat(...)` that uses it.
- **Deployment contract**: consumers must have the `xmlsec1` binary available at runtime. This is
  documented in the README install section.
- **Transitive footprint**: pysaml2 pulls `requests`/`urllib3`/`pyopenssl`. apron-saml does not call
  pysaml2's HTTP paths (metadata is passed in as a string), so the "no network I/O" stance holds; the
  footprint is accepted and left as a watch item, not a blocker.
- **Encapsulation**: pysaml2 is an implementation detail. It is not re-exported, and runtime-visible
  strings (error messages, log lines) describe conditions in domain terms and never name the backend.
- **Reversibility**: because the backend sits behind the `ServiceProvider` facade and the `SamlError`
  hierarchy, swapping it later is a localized change, not an API break.

## Appendix — spike evidence (verified 2026-07-28)

Both spikes ran under the repo's `exclude-newer = "7 days"` policy (pinned to 2026-07-28) on
Python 3.13, macOS/arm64.

**pysaml2**
- Resolves to `pysaml2==7.5.4`; installs 15 packages from prebuilt wheels (`cryptography`, `cffi`,
  `defusedxml`, `pyopenssl`, `xmlschema`, `python-dateutil`, `requests`, …). No `python-xmlsec` or
  `lxml` bindings, and no source build — the native wheels (`cryptography`, `cffi`) need no dev headers.
- `import saml2` succeeds with no system xmlsec1 present; the default path locates the `xmlsec1` CLI
  binary at runtime (`saml2.sigver.get_xmlsec_binary`).
- Exception hierarchy present: `saml2.SAMLError` → `SignatureError`, `StatusError`,
  `VerificationError`, `DecryptError` (in `saml2.response`).

**python3-saml**
- Resolves to `python3-saml==1.16.0`; dep tree pulls compiled `xmlsec==1.3.17` and `lxml==6.1.1`,
  plus `isodate`.
- Installed via a prebuilt `xmlsec` wheel on macOS/arm64/py3.13; `pkg-config` was absent on the host,
  so a platform without a matching wheel would require a source build (libxml2/libxmlsec1 dev headers).
- Failure surface is `OneLogin_Saml2_Auth.is_authenticated()` + `get_errors()` (string list).

## References

- pysaml2 — https://github.com/IdentityPython/pysaml2 ; https://pypi.org/project/pysaml2/ (v7.5.4)
- python3-saml — https://github.com/SAML-Toolkits/python3-saml ; https://pypi.org/project/python3-saml/ (v1.16.0)
- OASIS SAML 2.0 Core — https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
- OWASP SAML Security Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html
- Bring-up runbook §6 (Epic 1), §9 (research provenance, verified 2026-07-28)
