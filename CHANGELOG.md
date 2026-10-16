# Changelog

Every change a user of takestock would notice is recorded here. The format
follows *Keep a Changelog*, and the version numbers follow *Semantic
Versioning*: while the version starts with 0, a minor release may change the
command line or a file format, and its entry says how.

## [Unreleased]

### Added

- **IP address plan**: a source can set `name_is: history` for an export that
  lists every address a device has held. Its names are kept on each address
  as past holders and never count as a second machine.
- **IP address plan**: each address says how it was given out (`static`,
  `dynamic`, or `disputed` when sources disagree) and on what basis, from an
  allocation or DHCP setting a reader reports, and which VLANs it was seen
  on. The `csv` reader takes optional `assignment` and `vlan` columns.
- **IP address plan**: a plan file can declare `segment_codes`, the meanings
  of the parts of segment names, so each segment says what it carries and a
  subnet a segment declares takes that as its purpose; `exposure_chains`, the
  hops from the internet to a service as a declared source describes them;
  and `audience`, who the plan is written for.
- **IP address plan**: a subnet's `addressing` value that the plan does not
  know is listed as a check and treated as `static`, so a typing slip no
  longer silently changes which name conflicts are reported; `static` is now
  a documented value. A superseding source can say with `cannot_see` which
  sightings it would never list, and an address the older source reports
  with one of those values is no longer flagged as only in the older source.
- **IP address plan page**: the address finder also takes a MAC address and
  lists every address it was seen at; the view (section, address search or
  subnet filter) is kept in the page's address so a copied link opens where
  it was copied, and the page still works in a sandboxed preview frame
  where the address cannot change; a plan file's `part` and `author` give a
  label above the title and a line under it.
- **HTML pages**: `htmlpage.page` takes an optional `eyebrow` (a short label
  above the title) and `byline` (a line under it).

## [0.1.0] — 2026-10-17

The first release.

### Added

- **`takestock observe`** takes an observation of an estate: every row found,
  graded against a bundled algorithm baseline, with the coverage gaps (what
  the run could not see), written as JSON and as a CycloneDX 1.6
  cryptographic bill of materials (CBOM).
  - **Passive collectors** read public DNS, mail-authentication records
    (SPF, DKIM, DMARC, MTA-STS, TLS-RPT), and certificate-transparency logs,
    including the names beneath a domain and domains parked for no mail.
  - **Active collectors** probe TLS, mail transport, SSH, HSTS, cleartext
    services, SMB, RDP and IKE, plus services reached from inside a network.
    They run only with `--scan` and a complete authorisation record in the
    target profile, contact only the hosts and ports the profile names, and
    print their plan before contacting anything.
  - **Ingest collectors** read exports someone supplies: SSH audit reports,
    network device configurations, software inventories, DNS zone files and
    Windows remote management settings.
  - `--offline` reads the supplied exports only; `--carry-scan` takes a new
    observation and carries in the probe rows of a recent one, each keeping
    the date it was measured.
  - A target profile can turn a built-in collector off.
- **Plug-in collectors**: a reader for an export takestock does not know can
  live in another package and run as if built in, with a fixed record schema
  for each kind of evidence (see `docs/PLUGINS.md`).
- **Dispositions**: a proposed track, reason and effort size for every graded
  row, read against an organisation's own decisions, ladder, adoptions and
  dispensations kept in an overlay beside the profile. Lifecycle, crypto
  agility, usage and binding facts feed the proposal.
- **`takestock cmdb`** drafts a configuration register: a schema plus every
  configuration item found, with how strongly each fact is known, as JSON, CSV
  and a workbook.
- **`takestock ipam`** builds an IP address plan from a plan file and the
  exports it names, as JSON, CSV and one HTML page.
- **`takestock comply <standard>`** reads an observation against a published
  standard and reports every requirement as met, not met or not measured, as
  a self-contained HTML note or, with `--format text`, as plain text. It
  exits 1 when a requirement stated as *must* is not met.
  `takestock comply --list` names the standards. The first is `sge`, New
  Zealand's Secure Government Email framework. Every standard sits behind
  this one command, and a new one is added by registering it (see
  `docs/ARCHITECTURE.md`, *Adding a standard*).
- **`takestock requirements`** derives requirements from the findings and
  gaps, written from public standards, with tests and an evidence sentence,
  as Markdown, a workbook and JSON.
- **Bundled reference data**: Windows and software lifecycles, daemon and
  service names, port encryption, vendor service domains, cryptographic
  software, the Secure Government Email requirement set and a requirements
  catalogue.
- **Reference documents** for the standards takestock grades against (the
  NZISM, Secure Government Email, the Protective Security Requirements, NCSC
  and NIST guidance, IETF RFCs), the New Zealand laws and policies above them,
  and the government risk scale.
- **A sample organisation**, Example Widgets Ltd, in `examples/`, with every
  name reserved and every address from a documentation range.
- **One exit-code contract** for every command: 0 clean, 1 findings present,
  2 error.
- **A publication guard**, `tools/guard.py`, that refuses a commit carrying an
  address, host name, email address or GUID outside the reserved and
  documentation ranges.
- Type information for programs that embed takestock (`py.typed`), and
  embedding hooks such as declaring a flag adverse.
- Packaging metadata, continuous integration on Python 3.11 to 3.14, and a
  release workflow that publishes to PyPI by trusted publishing.
