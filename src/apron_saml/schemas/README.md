# Vendored SAML/W3C XML Schemas

This directory vendors the authoritative OASIS/W3C XML Schema (XSD) documents needed to validate a
SAML 2.0 `<saml:Assertion>` against its full content model offline. The runtime never fetches these
over the network — they ship with the package so schema validation works with no external
dependency and no risk of resolving a schema from an attacker-controlled or unreachable location.

## Files

| File | Source URL | Retrieved | SHA256 (as downloaded) | SHA256 (as committed) | License |
|---|---|---|---|---|---|
| `saml-schema-assertion-2.0.xsd` | <https://docs.oasis-open.org/security/saml/v2.0/saml-schema-assertion-2.0.xsd> | 2026-08-12 | `006eb7553843cb7baa9b08da2a9d444346c0e982fb9d9293babe08ede680924b` | `60b4dbc3a7821487e1dc7f2943534c05edb78e4ad4fd62a427be3941a1904e71` | OASIS |
| `xmldsig-core-schema.xsd` | <https://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd> | 2026-08-12 | `35cf8197da812c85e40d57891b35c94187569ed474a2dac813ce5090dafcd35c` | `76e4a6d9c876e11c2d9230e084fa28220968c7361d1ac671f17d321e8fc7de87` | W3C |
| `xenc-schema.xsd` | <https://www.w3.org/TR/2002/REC-xmlenc-core-20021210/xenc-schema.xsd> | 2026-08-12 | `5dd57f074870e1d91f7eb814aa92967cefcce9011a86adf5e12a769fcf2a237e` | `0d7f845ca73f8f65bd259294acc08aabc3702b0aa46dee6fad245a720c5f8f64` | W3C |
| `xml.xsd` | <https://www.w3.org/2001/xml.xsd> | 2026-08-12 | `61960fb3131e38022caad5360e2f33a3382578ab3c80cd58bd74320ede61b20c` | `1cbe7ac519f6d3b42b04f1d5c4c0d09ca5497347c2a947b286bb31cd4e627587` | W3C |

The "as downloaded" SHA256 was recorded immediately after download, before any edits, and is the
value to check against the authoritative source. The "as committed" SHA256 is the file as it landed
in this repository: after the `schemaLocation` rewrites below and after this repo's `pre-commit`
hooks (`trailing-whitespace`, `end-of-file-fixer`) normalized incidental trailing whitespace and
final-newline formatting — the schema's element/type declarations are byte-identical apart from
that whitespace. `saml-schema-assertion-2.0.xsd` differs from its "as downloaded" hash only because
of its two `schemaLocation` rewrites (see below); the hooks made no further change to it.

**License terms:**
- OASIS material (`saml-schema-assertion-2.0.xsd`) may be reproduced and distributed, in whole or in
  part, without restriction of any kind, provided the copyright notice and this permission are
  included on all copies.
- W3C material (the other three files) is licensed under the W3C Document/Software License, which
  permits redistribution with retention of the copyright/license notice.

Each vendored file retains its original copyright/license notice embedded in the file itself.

## Local edits

Only `xs:import`/`xs:include` `schemaLocation` attributes were rewritten to local relative paths;
no content models were modified. Specifically:

- `saml-schema-assertion-2.0.xsd`: both `<import>` elements (for the `ds:` and `xenc:` namespaces)
  now point at `xmldsig-core-schema.xsd` and `xenc-schema.xsd` respectively, instead of their
  original remote URLs.
- `xenc-schema.xsd`: its `<import>` of the `ds:` namespace now points at `xmldsig-core-schema.xsd`
  instead of its original remote URL.
- `xmldsig-core-schema.xsd` and `xml.xsd` had no `schemaLocation` rewrite — neither file contains a
  real `xs:import`/`xs:include` `schemaLocation` attribute in this revision (their only changes are
  the whitespace normalization noted above). `xml.xsd` contains two literal
  `schemaLocation="http://www.w3.org/…/xml.xsd"` strings, but both live inside its own
  `<xs:documentation>` prose (escaped example code showing *other* schemas how to import it) — they
  are content, not a real import, so `grep -REn 'schemaLocation="https?://'` over this directory
  reports those two lines even though no schema in the bundle resolves anything remotely.

## Rebuilding

To refresh this bundle: re-download each file from its source URL above, re-apply the same
`schemaLocation` rewrites, and update the checksums and retrieval date in this file.
