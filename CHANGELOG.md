# Changelog

Every change a user of takestock would notice is recorded here. The format
follows *Keep a Changelog*, and the version numbers follow *Semantic
Versioning*: while the version starts with 0, a minor release may change the
command line or a file format, and its entry says how.

## [Unreleased]

### Added

- **Configuration register**: machines, Software Products and Applications
  carry `technology_zone`, one of the five technology zones of New Zealand's
  GEANZ Technologies model (`TAP.00`, `TFA.00`, `TI.00`, `TN.00`, `TUD.00`),
  and machines and Applications carry `technology_location`, one of its two
  technology locations (`TLC.00` cloud, `TLO.00` on-premise). A machine row
  states them in `extra.technology_zone` and `extra.technology_location`;
  a product's or application's are for the organisation to fill. A schema
  attribute can name a `vocabulary`, and the build refuses a value outside
  it on any row.
- **Configuration register**: `takestock cmdb --ip-plan <plan>.json` (and
  `ip_plan=` in Python) reads an IP address plan's JSON and makes an item for
  each machine it names at an address, carrying the plan's addresses. It is
  off unless given. Aliases, labels, past holders and addresses only a
  superseded source lists are left out.
- **DNS zone files**: the "names nobody measured" row lists every name the
  served zones publish in `extra.dns_names`, and the configuration register
  makes a DNS Name for each. The observation gains no rows.
- **Configuration register**: a machine with no host type takes its class
  from a network device export's equipment category, so a switch, router,
  firewall, wireless device or VPN gateway is a Network Device rather than an
  untyped Host.
- **Configuration register**: a row that names software and no machine, such
  as a software inventory's row for one product at one version, now makes its
  Software Product and Software Release. The release is installed on each
  machine the row names in `extra.hosts`, and a machine only that list names
  becomes a Host. A `version-spread:` row makes no release.
- **Software inventory**: the scope row names every product the export lists,
  cryptographic or not, in `extra.software_products`, and the configuration
  register makes a Software Product for each. A product outside the
  cryptographic software register is still not graded.
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
- **IP address plan**: an exposure-chain hop may be a network in CIDR form,
  for a group of machines a request can reach any one of. It is written as
  `network` rather than `address` and shown as a network on the page; a
  range with host bits set is still refused.
- **IP address plan**: a segment that only replaced sources list, and that a
  newer source listing segments of its own does not, is marked
  `superseded_by` and left out of the segment and VLAN counts and the VLAN
  check (`counts.segments_superseded` says how many). `Segment` takes an
  optional `detail`, which a newer source's `cannot_see` is compared with.

### Changed

- **Configuration register**: a declared-estate row's `collectors_live` may
  name an instrument by its collector id (a row's `source`) as well as by its
  display name (`source_name`), and a `member-of` edge is drawn either way.
  Before, a row's display name was matched, and its id only when it had no
  display name, so a list of collector ids drew no edge for rows that carry
  both. A machine gets one edge per declared class, where before it got one
  per instrument.
- **IP address plan**: a subnet a source declares goes to the site whose
  plan-file range holds it, even when the source reports another site; the
  source's site is used only when no range holds the subnet.
- **IP address plan**: a subnet a source of class `observed` declares reads
  `confidence: measured` (it was `declared`); other sources' subnets still
  read `declared`.

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
