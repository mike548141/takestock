# 2026-10-17 — Readers library, and a CycloneDX reader

## What was done

- **A readers library.** takestock can now ship plug-ins of its own, in
  `src/takestock/readers/`. Each is written to the plug-in contract in
  `docs/PLUGINS.md`, as a reader in another package would be. A target
  profile runs one by naming it in `plugins:`, exactly as it names an
  installed plug-in, and it never runs otherwise. takestock finds them in its
  own package rather than through installed package metadata, so a clone and
  an installed copy find the same readers. Named alone, a library reader's
  `summary.json` origin is `library`. Library readers are not listed as
  installed and undeclared, since every installation has them.
- **A name two plug-ins answer to is refused.** Before, when two installed
  packages declared a plug-in of the same name, the first one found ran and
  nothing said so. Now a name given alone that two different plug-ins answer
  to (the library and a package, or two packages) is not run; its gap says
  who offers it, and the profile chooses one with `module:`. The same plug-in
  offered twice is one offer.
- **The first library reader, `sbom`**, in `readers/cyclonedx.py`: CycloneDX
  software bills of materials in JSON, one file or a folder of them. It reads
  the document as the CycloneDX specification defines it: its format and
  version, `metadata`, `components` (nested ones included) and the
  `dependencies` graph. Components are classed by the
  words in their names (secure shell, key management, cryptographic library,
  security token, identity, data transport); each classified component is a
  row, followed by one row per application and a scope row. Flags mark a
  direct dependency, a pre-release build of a cryptographic or identity
  component, an application that can open SSH connections itself, and a
  library whose documented default is to encrypt its connections. The rest of
  the applications, with no bill of materials, are a coverage gap.
- **Roles:** an application component's role takes "An" before a vowel.
- **Docs:** a readers library section in `COLLECTORS.md` with the `sbom`
  reader's own; `PLUGINS.md` on finding library readers and on a name two
  plug-ins answer to; the README and `ARCHITECTURE.md` point at the library.

## Checks

- The test fixture, `tests/fixtures/cyclonedx/example-orders-api.cdx.json`,
  was written by hand from the CycloneDX 1.6 JSON schema, with synthetic
  names only, and checked against that schema and the 1.7 one with a small
  validator for the schema keywords the file exercises. The validator was
  first shown to reject a broken copy (an unknown component type, an unknown
  hash algorithm, a malformed serial number and an extra property).
- New tests: the classes, pre-release versions, every row and flag of the
  fixture, a folder with unreadable and non-CycloneDX files, an empty folder,
  the file-date fallback, the informational flags, and the library and
  duplicate-name rules through a whole observation of the sample. The
  duplicate-name tests were seen to fail with the refusal switched off.
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- More readers for the library, one product or format at a time.
- A way for a workspace to add rows to a library reader's own reference
  table, merged over the bundled one, once a reader with such a table needs
  it.
