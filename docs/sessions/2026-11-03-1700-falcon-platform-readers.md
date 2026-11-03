# 2026-11-03 — Five CrowdStrike Falcon platform and software readers in the readers library

## What was done

- **`takestock.readers`** gains five readers (`general`, no default input):
  - `falcon_software`: a CSV of installed applications (a LogScale query over
    `InstalledApplication` events), matched against a register of
    cryptographic software; one row per product and release line graded for
    a capability ceiling, a version-spread row per product, one row per
    exact secure-shell server package version, and a scope row.
  - `falcon_vulnerabilities`: a Spotlight vulnerability list, read a row at a
    time. One row per cryptographic product with open defects (a package
    name, or a Microsoft component named in the advisory text), one per open
    catalogued exploited defect with its due date, one per operating system
    and machine type, a scope row, and a gap when machines' criticality is
    unset.
  - `falcon_system_resources`: firmware versions by manufacturer, with
    machines behind the estate's own newest on the same hardware family.
  - `falcon_windows_os_security`: Windows platform protections counted per
    protection, with optional unidentified columns (each a gap), a second
    reading compared machine by machine, and a platform export that shows
    whether any Windows machine is missing.
  - `falcon_sha1_signed_modules`: one row for the machines whose module
    signing events carry SHA-1, with the primitive on the row and a gap
    saying where in the certificate chain it sits is not established.
- `readers/_falcon_platform.py`: what the five share (headings from
  `settings: columns:`, with a list tried in order; a streaming CSV read that
  raises the field size limit only for the read; nested file settings).
- `roles.py`: role phrases for the new rows.
- `docs/COLLECTORS.md`: a shared section with the public source of every
  name, a section per reader, and the library table rows. Changelog.

Sources read on 4 November 2026 (New Zealand time):
`CrowdStrike/logscale-community-content` on GitHub (the FLTR core package's
two *Installed Application Events* queries and the FLTR tutorial's *The
Basics - Field Extraction* dashboard); `elastic/integrations` on GitHub,
`packages/crowdstrike` (the `vulnerability` data stream's field list and
sample records, the `host` data stream's sample record, and the Falcon Data
Replicator sample events); Microsoft Learn, *PKCS #7 EOBO Encoded ASN.1*;
the LogScale documentation pages *Query Filters* and *Field Naming and
Standards*, and its knowledge-base article *How-To: Case-Insensitive Searches*;
and the CVSS v3.1 specification's qualitative severity scale.

Choices worth recording:

- Three input shapes, three kinds of default. A query's export takes the
  sensor's field names; an API record flattened to CSV takes the API's field
  paths, as Elastic's integration documents them; the console's Windows
  protection export, whose headings no public source lists, takes each
  field's own name and expects `columns:`.
- Values no public source explained are settings with no default meaning:
  which exploit status values mean an exploit is in use, status words beyond
  `open`, and criticality words meaning unset.
- `falcon_software` groups by release line (first component, or first two
  after a leading `1`) and grades a line only by a register entry for exactly
  that line. That differs from `software_inventory`, which grades each
  version by the longest matching branch; both are documented.
- `falcon_sha1_signed_modules` counts the platform export's Windows machines
  once each, by name, so a machine with two network adapters is not counted
  twice.

## Checks

- Tests on exports composed in the tests (made-up machines, products and
  firmware, identifiers and dates in 2030, a documentation-range network
  adapter address). One test feeds a field longer than the CSV module's
  default limit, with line breaks in it.
- Lines of the reader logic were removed one at a time and the tests went
  red, then restored (see the list below).
- `make check`: guard, ruff, mypy and the full test suite.

## Left to do

- Run the two LogScale queries against a tenant and compare the CSV's
  headings and values with the readers'.
- Find a public source for the meaning of the vulnerability record's
  `exploit_status` values and for the Falcon console's export headings.
