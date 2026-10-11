# Changelog

Every change a user of takestock would notice is recorded here. The format
follows *Keep a Changelog*, and the version numbers follow *Semantic
Versioning*: while the version starts with 0, a minor release may change the
command line or a file format, and its entry says how.

## [Unreleased]

## [0.1.0] — unreleased

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
- **`takestock sge-note`** and **`takestock sge`** read every requirement of
  New Zealand's Secure Government Email framework as met, not met or not
  measured, as an HTML note or plain text.
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
