# Changelog

Every change a user of takestock would notice is recorded here. The format
follows *Keep a Changelog*, and the version numbers follow *Semantic
Versioning*: while the version starts with 0, a minor release may change the
command line or a file format, and its entry says how.

## [Unreleased]

### Added

- **Readers library**: three readers for VMware vSphere estates.
  `vmware` reads a PowerCLI CSV of VM Encryption and vSAN encryption state,
  one row per machine or cluster: a vSAN cluster with encryption off is
  `weak`, a machine with it off is recorded as a fact (its storage may
  encrypt), and encryption on is graded as XTS-AES-256, the one cipher
  vSphere uses; key custody is flagged. `rvtools` reads RVTools workbooks
  (one, or a folder): a census of machines' firmware and secure boot,
  configured guest types and ESXi versions, with templates and Site
  Recovery Manager placeholders left out of the machine count and a scope
  row saying the workbooks hold no encryption data. `vsphere_lists` reads
  the vSphere Client's exported lists of virtual machines, hosts and
  datastores: VM encryption, virtual TPM and virtualisation-based security
  per site, guest types and ESXi versions with their vendor support status
  from a lifecycle table (the bundled one, or one named in `settings:`),
  host certificate expiry as at the export date, and what backs each
  datastore, read from the maker prefix in its device identifier. When
  `settings: {vsphere_lists: <folder>}` names a folder holding a
  virtual-machine list, `vmware` raises no gap for a missing export and
  `rvtools` writes only its firmware rows.
- **Roles**: plain-English roles for the rows of the three VMware readers.
- **IP address plan**: a segment carries how it is attached (`mode`:
  `access` or `trunk`) and, for a trunk, the VLANs it carries
  (`trunk_vlans`), when its reader says. Where the newest source reporting
  a segment gives it no VLAN and it is not a trunk, the segment keeps the
  VLAN an older source stated, with `vlan_source` naming that source.
- **IP address plan**: `segment_location` in the plan file names a
  separator (such as `.`) after which a segment's name says what it
  carries. The text before it is recorded as the segment's `location`, with
  what that location is from `names`, and is not read with the segment
  codes, so a cluster prefix is never read as a purpose.
- **IP address plan**: a `summary` item may be `{heading, text}`, written to
  the JSON as given and shown on the page under its heading. Before, such
  an item was written as the text of the mapping.
- **IP address plan page**: the VLANs and segments table has a *Mode and
  notes* column, and a segment's name shows its location.

- **Readers library**: `exchange_online` reads an export of Exchange Online
  settings (accepted domains, DKIM signing, anti-phishing policies and
  rules, preset security policy rules, inbound and outbound connectors,
  quarantine policies), a folder or a zip, one `n/a` row per object and a
  scope row. A PowerShell script in `docs/EXCHANGE-ONLINE-EXPORT.md` writes
  the export; it runs only `Get-*` cmdlets. Its `-IncludeDlp` switch also
  exports mail flow rules and Microsoft Purview data loss prevention
  settings, which nothing reads yet.
- **Secure Government Email**: SGE-DMARC-02 (inbound mail checked for DMARC
  and acted on), SGE-DMARC-R04 (mail failing DMARC kept in a quarantine
  only an administrator releases from) and SGE-DKIM-01 (outbound mail DKIM
  signed) are graded per domain from that export when an observation holds
  one, and stay `no-instrument` when it does not. SGE-DMARC-02 reads the
  anti-phishing policy that governs each domain's recipients and whether
  the route the mail arrives by lets the platform honour DMARC: behind a
  non-Microsoft MX, only with Enhanced Filtering on the receiving connector.
  The requirement set's `measurable` field takes a new value,
  `inside-export`, for these three.
- **Grading**: rows with protocol `mail-policy` carry no cryptography, like
  the DNS mail policy records.

- **Readers library**: `oracle_tde` reads an Oracle Database administrator's
  CSV export of Transparent Data Encryption state (keystore status and type
  from `V$ENCRYPTION_WALLET`, encrypted tablespaces and their algorithms from
  `V$ENCRYPTED_TABLESPACES`, and the count of all tablespaces), one row per
  database, graded `weak` where no keystore is open or nothing is encrypted.
  `docs/COLLECTORS.md` gives a query that writes its columns.
- **Readers library**: `commvault` reads a CSV of Commvault storage policy
  copies' software encryption settings (whether it is on, cipher, key length
  and where the keys are held), one row per copy.
- **Roles**: `database_encryption` and `backup_encryption`.
- **Configuration register**: `takestock cmdb --target <profile>` reads the
  profile's new `cmdb:` block (`title`, `schema_overlay`, `how_to_read`,
  `jira_assets`), its organisation's name and its `branding:` block, when
  that sets anything. The title and organisation head the JSON
  (`register.organisation` is new) and the workbook; `how_to_read` replaces
  the built-in reading notes in both; `branding` gives the workbook its
  colours and font. From Python: `build_register(..., title=,
  organisation=, schema_overlay=, how_to_read=)`, `write_outputs(...,
  theme=, jira_assets=)` and `cmdb.profile_options(target)`. Without them
  nothing changes.
- **Configuration register**: a **schema overlay** rewords the register
  schema without a copy of it: notes, questions and definitions of the
  classes, families, attributes, relationships and vocabulary codes it
  already declares, and who holds each governance role. It never changes the
  model: an overlay that names something the schema does not declare, or
  sets any other field, stops the build with every problem listed. The
  register names the overlay used in `register.schema_overlay`. A file named
  `<stem>.cmdb-schema-overlay.yaml` beside a profile is never read as a
  profile.
- **Configuration register**: with `jira_assets`, the register is also
  written as an external import for Jira Assets, in `cmdb/jira-assets/`:
  `schema-and-mapping.json` (one object type per class, matched on the
  register key, with a reference attribute per kind of relationship) in
  Atlassian's published 2023-10-19 schema-and-mapping format, and
  `data.json`, the items as one data chunk.
- **Observation archives**: `obsarchive.add_archive_dir(...)` names further
  folders to look in for an archived observation whose file is not beside
  its manifest, such as a working copy reading the main copy's archives.
  Every member read is still checked against the manifest. An archive name
  that is not a plain file name is never looked for.
- **Readers library**: takestock ships plug-ins of its own for standard
  formats and named products' exports, in `takestock.readers`. A target
  profile runs one by naming it in `plugins:`, as it names an installed
  plug-in; it never runs otherwise. Named alone, its record in
  `summary.json` has origin `library`. Library readers are not listed under
  `plugins_installed_not_declared`.
- **`sbom` reader** (readers library): CycloneDX software bills of materials
  in JSON, one file or a folder of them. Each component of an application
  whose name marks it as a secure-shell, key management, cryptographic,
  security-token, identity or data-transport library becomes a row, with
  flags for a direct dependency, a pre-release build of a cryptographic or
  identity component, an application that can open SSH connections itself,
  and a library that encrypts its connections by default. One row for each
  application and a scope row follow, and the applications with no bill of
  materials are a coverage gap.
- **Configuration register**: a row can list software releases in
  `extra.releases`, each with its product, version or vendor version line
  and the versions it covers, support status and dates, and the CVE
  identifiers of known exploited defects open against it. Each entry makes a
  Software Product and Software Release; Software Release gains
  `covered_versions`, `exploited_defect_ids` and
  `exploited_defects_past_due`, citing CISA's Known Exploited
  Vulnerabilities Catalog. An entry that lists several versions with no line
  is refused.
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
  machine the row names in `extra.installed_on` (a list, or names separated
  by commas), and a machine only that list names becomes a Host. A name
  holding a space is refused. A row with no `installed_on` may name its
  machines in `extra.hosts` as a list of names; a `hosts` string, such as a
  count of machines or names joined by spaces, is not read. The software
  inventory's rows carry `installed_on` beside their `hosts`; a machine
  name with a space in the export is counted in `hosts_count` and left out
  of `installed_on`, and the scope row gives how many in
  `extra.installed_on_skipped`, so one bad name never stops the build. A
  `version-spread:` row makes no release. (This was first written to read
  `extra.hosts` in any shape; that was never released, so the rename costs
  no user anything.)
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

- **Plug-ins**: a name a profile gives alone that two different plug-ins
  answer to (the readers library and an installed package, or two packages)
  is no longer run with whichever was found first. It is not run, and its gap
  names who offers it; the profile chooses one with `module:`.
- **Roles**: an application component's role reads "An" before a label
  starting with a vowel ("An authentication and identity component").
- **Daemon dictionary** (`data/daemon-dictionary.csv`) more than doubles in
  size. The new rows cover the standard services of Linux
  distributions, Windows and Windows Server components, Microsoft server
  products, databases and connection poolers, proxies, application
  servers, virtualisation and container runtimes, Kubernetes networking, cloud
  guest agents, monitoring and logging agents, backup software, configuration
  management agents, VNC and other remote-access servers, and host and network
  security sensors. Each row cites the vendor, project or distribution
  document that gives the name. The header now describes how rows are chosen
  and sourced.
- **Vendor domains** (`data/vendor-domains.csv`) gain registered domains
  taken from the providers' own published lists of service domains:
  more of the large cloud and enterprise platforms (Amazon Web Services,
  Apple, Google, Oracle, IBM, SAP, Salesforce), collaboration and
  software-as-a-service platforms, identity and password managers, security
  services, certificate authorities' status domains, Linux distributions'
  mirrors, and language package registries. The header now describes how
  rows are chosen and sourced.
- **Configuration register**: a declared-estate row's `collectors_live` may
  name an instrument by its collector id (a row's `source`) as well as by its
  display name (`source_name`), and a `member-of` edge is drawn either way.
  Before, a row's display name was matched, and its id only when it had no
  display name, so a list of collector ids drew no edge for rows that carry
  both. A machine gets one edge per declared class, where before it got one
  per instrument.
- **Configuration register**: a row whose protocol is `dns` or `dnssec` and
  that names a port is read as a probe of the machine answering DNS there,
  so it makes a Network Service on that machine. Before, it made a DNS Name
  with the machine's name and no service. A DNS or DNSSEC reading with no
  port is still a DNS Name, and a discovery or mail-authentication row stays
  a name row even when it names a port.
- **Configuration register**: `contains` is drawn once per machine and
  Network Service, keeping the strongest evidence among the rows that name
  the service, then the most recent. Before, every row naming the service
  drew its own edge, so a listener two instruments read had two.
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
