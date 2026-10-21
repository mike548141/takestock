# The configuration register

takestock builds a **draft configuration register** from one observation: a
list of the things an estate runs, what is known about each, how strongly it
is known, and how the things connect. This guide says what the register
holds, how it is built, what it writes, and how to read what it writes.

A register built this way is a draft. It holds what instruments saw. It
cannot hold what only people know (who owns a system, what it costs, which
service stops when it stops) until someone supplies that.

## Terms used here

- **Observation**: one run's output directory, named by its UTC time stamp
  (`2030-01-15T0000Z`). The register reads its `assets.json` (one row per
  thing found) and, if present, `summary.json`.
- **Configuration item (CI)**: one thing in the register: a server, a
  certificate, a DNS name, a software release.
- **Class** and **family**: every item has a class (`Server`,
  `Certificate`); classes are grouped into families (`Hardware`,
  `Network and Naming`).
- **Attribute**: one named fact a class carries, such as `os_version` or
  `not_after`.
- **Assertion**: one recorded fact: an attribute value for one item, with how
  strongly it is known, when it was true, when it was recorded, and who or
  what said so.
- **Relationship**: a typed, directed link between two items, such as
  `installed-on` or `presents`.
- **Schema**: `src/takestock/data/cmdb-schema.yaml`, which declares every
  class, attribute, relationship and vocabulary. The builder refuses to record
  anything the schema does not declare.

## Building a register

```bash
takestock cmdb <observation_dir> [<out_dir>] [--keys <keys.jsonl>] [--ip-plan <plan.json>]
               [--target <profile>] [--workspace <dir>]
```

For the sample organisation, from inside a copy of its workspace (see the
README's quick start):

```console
$ takestock cmdb observations/latest
observations/latest/cmdb/cmdb.json
observations/latest/cmdb/csv/account.csv
...
observations/latest/cmdb/csv/relationships.csv
observations/latest/cmdb/cmdb.xlsx
observations/latest/cmdb/keys.jsonl
```

- `out_dir` defaults to `<observation_dir>/cmdb`.
- `--keys` names the `keys.jsonl` an earlier build wrote, so every item keeps
  the key it had before (see [Keys](#keys-and-identity)).
- `--ip-plan` names an IP address plan's JSON, as `takestock ipam` writes it,
  so the machines it names become items too (see
  [Machines from an IP address plan](#machines-from-an-ip-address-plan)). It
  is off unless given.
- `--target` names a target profile (a path, or a name under `targets/`)
  whose `cmdb:`, `organisation` and `branding:` blocks set the register's
  title, schema overlay, reading notes, workbook style and Jira Assets
  import (see [Options a profile sets](#options-a-profile-sets)). Without
  it, the register takes the defaults.
- The recording date is the observation's own date when its directory is
  named by a time stamp, otherwise today. Rebuilding the same observation
  therefore gives the same register.
- A derived observation (`takestock rerun`) holds rows read on different
  dates: the rows it carries were read when the full observation it comes
  from was taken, and the rows of the plug-ins it read again were read on its
  own date. Each fact, key and relationship drawn from a row is dated by the
  observation that read the row: a row a plug-in wrote (it names the plug-in
  in `extra.plugin`) by the latest observation that read that plug-in again,
  and every other row by the full observation, following a chain of derived
  observations back to it. A row that gives its own `collected_at` keeps it
  as the date the value was true. The register's own recording date, and
  what the build says of the whole (the count of every machine, the classes
  a machine is attributed to), take the full observation's date. A recording
  date given to `build(..., recorded_at=)` is the recording date of every
  fact; each row is still dated as true when it was read.
- If `summary.json` gives a `total_assets` count that differs from the rows
  in `assets.json`, the build stops: the observation is incomplete.
- The schema is read from `data/cmdb-schema.yaml` in the workspace if one is
  there, otherwise from the package. Only a workspace named explicitly, by
  `--workspace` or `TAKESTOCK_HOME`, is consulted; a `data/` folder in the
  current directory is never read unless it was named that way (see
  [`TARGET-PROFILE.md`](TARGET-PROFILE.md#bundled-data-and-a-workspaces-data)).
- The command exits 0 when the register is written, and 2 on an error such
  as an incomplete observation or a schema that does not hold together.

The build checks the schema before it starts and stops with a list of every
problem it finds (see [Changing the schema](#changing-the-schema)).

From Python, `takestock.cmdb.build_register(observation_dir, keys=...,
ip_plan=...)` returns the whole register as one dictionary, and `write_outputs(register,
out_dir)` writes it.

## Options a profile sets

A target profile may hold a `cmdb:` block. Every key in it is optional, and
any other key stops the build:

```yaml
organisation:
  name: Example Widgets Ltd

branding:
  font: "Example Sans, sans-serif"
  palette:
    accent: "#7a1f4d"

cmdb:
  title: Example Widgets configuration register
  schema_overlay: example-widgets.cmdb-schema-overlay.yaml
  how_to_read:
    - heading: Start with the servers.
      body: The Server sheet lists every server an instrument saw.
  jira_assets: true
```

| Key | Sets |
|---|---|
| `cmdb.title` | The register's title, at the head of the JSON and the workbook (default *Configuration register*) |
| `organisation` | The organisation's name, under the title, in `register.organisation` and in the Jira Assets object schema's description |
| `cmdb.schema_overlay` | A schema overlay file, relative to the profile, whose wording is merged over the schema (see [Rewording the schema with an overlay](#rewording-the-schema-with-an-overlay)) |
| `cmdb.how_to_read` | Reading notes that replace the built-in ones in the JSON's `how_to_read` and on the workbook's Read me sheet: a list of `heading` and `body` entries, or the path of a YAML file holding that list |
| `branding` | When the profile's `branding:` block sets anything, the workbook takes its light colours and font: headers in `text` on `surface`, the title, headings and contested values in `accent`, absences in `muted`, and the first font named in `font` (a generic family such as `sans-serif` names none). Without it, or with an empty block, the workbook keeps its plain style |
| `cmdb.jira_assets` | `true` also writes an import for Jira Assets (see [An import for Jira Assets](#an-import-for-jira-assets)) |

From Python, the same options are keyword arguments:
`build_register(..., title=, organisation=, schema_overlay=, how_to_read=)`
and `write_outputs(register, out_dir, theme=, jira_assets=)`.
`cmdb.profile_options(target)` reads them from a loaded profile.

## How rows become items

Each row of `assets.json` is read in two passes: first to decide which items
exist and of which class, then to record what the row says about them.

| A row that is | becomes |
|---|---|
| from the target profile's declared estate (`data_state: estate`) | a **Declared Asset Class**: something the organisation says it has, which no instrument may yet have seen |
| a third-party row naming a vendor (`extra.vendor`) | a **Vendor** |
| a third-party row naming only a domain (`extra.registrable_domain`) | an **Unattributed Dependency**, keyed on that domain |
| a certificate | a **Certificate**, keyed on its host |
| key material | a **Credential**, keyed on its name |
| a discovered name or a mail-authentication record, whether or not it names a port; or a DNS or DNSSEC reading that names no port | a **DNS Name** |
| one of those that lists names in `extra.dns_names`, such as the zone-file reader's list of every published name | a **DNS Name** for each listed name |
| anything else with a host name or a management agent's id | a **machine** |

A name row is about a name, not a machine. A zone's top (`example.test`)
read for DNSSEC, a service-record name (`_http._tcp.example.test`) and a mail
domain's published records each describe what a name publishes; no machine
is called `_http._tcp`. So a row that reads the DNS makes a DNS Name and never
a Host, whatever its data state. A row whose protocol is `dns` and that
names a port is different: it is a probe of a machine that answers DNS on
that port, so it is a machine row and makes a Network Service like any other
probe.

A name and a machine spelled alike are two items. Names are keyed as names
and machines as host names, so the DNS Name `web-02.example.test` and the
Host a probe reached through that name stay apart, whichever row comes
first. The register does not join them, because `resolves-to` is not drawn.

A machine's class comes from the row's `extra.host_type`:

| `host_type` (any case) | class |
|---|---|
| `server` | Server |
| `workstation`, `desktop`, `laptop`, `endpoint` | Endpoint Device |
| `domain controller` | Domain Controller |
| `network device`, `router`, `switch`, `firewall` | Network Device |
| `virtual machine` | Virtual Machine |
| missing or anything else | **Host** |

Where a row gives no host type, a network device export's equipment category
(`extra.netdev_device_class`) is read instead: `switch`, `router`,
`firewall`, `wireless` and `vpn-gateway` make a **Network Device**. A
`wan-link`, `out-of-band` management processor, `storage` or `other` says
nothing more about the machine, so it stays a Host.

`Host` is a class of its own, not a guess: "nothing said what this machine
is" is a finding someone can act on. A later row that does type the machine
moves it to the matching class.

A machine row that names a port (`extra.service` such as `443/tcp`, or
`port` with `extra.transport`, `tcp` when none is given) also creates a
**Network Service** contained by the machine:

- **A port alone is enough.** A probe that got an answer on a port has
  measured a listener, whether it wrote the port as `extra.service` or as
  `port`. A TLS scan, a plain-text scan, an HSTS reading and a mail server's
  STARTTLS probe all make the listener's service.
- **A probe of an address makes a service too.** A row whose host is an
  address, such as `192.0.2.80` on `80/tcp`, makes a **Host** labelled with
  the address, containing `192.0.2.80 80/tcp`: something answered there,
  and nothing named or typed the machine behind it.
- **Several rows naming one listener make one service**, keyed on the host
  as spelled and the port, and one `contains` edge. A TLS scan and an HSTS
  reading of `web-03.example.test` on `443/tcp` are one listener. The edge
  keeps the strongest evidence among the rows, then the most recent, and
  every row's facts about the service are kept as its assertions.

A row
that names software also creates a **Software Product** and a **Software
Release**, and records that the release is installed on the machine.

A row that names software and no machine, such as a software inventory's row
for one product at one version, still creates its Software Product and
Software Release. If it names the machines carrying that version in
`extra.installed_on` (a list, or names separated by commas), the release is
recorded as installed on each of them, and a machine no other row names
becomes a **Host** with that host name. A row that names no machine at all
leaves the release installed on nothing.

- A name in `installed_on` that holds a space cannot be one host name, so
  the build stops on it, naming the row's source. It stops too on an
  `installed_on` that is neither a list nor a string. That refusal is for a
  plug-in that writes a bad `installed_on` itself.
- takestock's software inventory never writes such a name. A machine name
  with a space in the export is counted in the row's `hosts_count` and left
  out of its `installed_on`, and the scope row says how many machines were
  left out, and why, in `extra.installed_on_skipped`. One bad name in an
  export therefore never stops the build.
- A row with no `installed_on` may name its machines in `extra.hosts`
  instead, but only as a list of names, such as
  `["app-02.example.test", "build-02.example.test"]`. A `hosts` value of
  any other shape is not read: a plug-in reader may use `hosts` for a count
  of machines (`"12"`) or for names joined by spaces, and reading either as
  a name would make a machine called `12`. A list holding a number itself,
  such as `[3]`, is not read either.

A row flagged `version-spread:`
counts how many versions of a product are in service; it is not an install
and creates no release. A row that lists product names in
`extra.software_products`, such as a software inventory's scope row listing
every product it names, cryptographic or not, creates a Software Product for
each, with no release.

A **DNS Name** for a domain the target profile names also carries two facts
read from public DNS by `ct_dns`. `name_servers` lists the hosts its NS
records say are authoritative for it (RFC 1035 §3.3.11), which is who hosts
its DNS. `dmarc_report_address` is the `rua=` tag of the DMARC record
published at the name itself, as published (RFC 9989 §4.7). Each is *not
applicable*, with a note, when the lookup settled with nothing to report: no NS
record because the name is not the top of its own zone, or no DMARC record or
no `rua=` in it. A name nothing read for them shows *not collected*.

### Releases a row lists

A row can list software releases in `extra.releases`, such as a plug-in that
reads a vendor's lifecycle data or a vulnerability export. Each entry becomes
a **Software Product** and a **Software Release**, joined by `release-of`:

```json
{"releases": [
  {"product": "Example TLS library", "line": "41.x", "versions": ["41.7.3", "41.9.0"],
   "support": {"status": "security-only", "end_of_support": "2031-06-30",
               "end_of_life": "2033-06-30", "as_of": "2030-01-12"},
   "exploited": {"identifiers": ["CVE-2099-4826193"], "past_due": 1, "as_of": "2030-01-11"}}
]}
```

| Field | Means | Becomes |
|---|---|---|
| `product` | The product's name. Required | the product's `name` |
| `versions` | The version strings the release covers, as the source spells them | `covered_versions`; with no `line`, the one version is the release's `version` |
| `line` | The vendor's version line the versions belong to, such as `41.x`. Required when `versions` lists more than one | the release is the line; its `version` is *not applicable* |
| `label` | The release's name, if not `product` and the line or version | the release's `name` |
| `support` | `status`, `end_of_support` and `end_of_life` as the vendor publishes them, and the `as_of` date they were read | `support_status`, `end_of_support`, `end_of_life` |
| `exploited` | `identifiers`: the CVE identifiers of defects in CISA's *Known Exploited Vulnerabilities Catalog* that the source says are open against the release; `past_due`: how many were past the catalogue's own remediation date; `as_of`: the source's date | `exploited_defect_ids`, `exploited_defects_past_due` |

- The release is keyed on its name, as a machine row's release is, so an
  entry for one version and a row naming that software at that version on a
  machine are the same item, and the release keeps its `installed-on` edge.
- An entry draws no `installed-on` of its own: listing a release says what is
  known about it, not where it is.
- A support date is `declared` (the vendor's published date) and the support
  status is `inferred`, as a status read on one date is. The names and the
  defects take the row's own strength, capped at `reported` for the defects,
  because the source attributes each defect to the release. An empty
  identifier list is *not applicable*: the source found none open.
- The build stops on an entry that is not a mapping, names no product, or
  lists several versions with no `line`, because joining versions without
  the vendor's line would be a guess.

### Technology zones and locations

The New Zealand Government Enterprise Architecture's *GEANZ Technologies
model* (August 2025 baseline, published as a dataset in the government's
open data catalogue under CC BY 4.0) is a shared set of categories for
technology. It was the source of the technology categories in the GEANZ
Standards and Guidance Catalogue; since that catalogue's September 2026
update they come from the model's review-draft successor, which keeps the
codes below. The model sorts technology two ways, and the register keeps
them as two attributes:

- `technology_zone`, carried by machines, Software Products and
  Applications: what kind of technology the item is, one of the model's five
  technology zones.
- `technology_location`, carried by machines and Applications: where it
  runs, one of the model's two technology locations.

They are kept apart because they answer different questions: an
infrastructure machine is `TI.00` whether it is on-premise or in a cloud,
and the model's own infrastructure zone holds both server services such as
infrastructure as a service (`TI.01`) and on-premise server equipment
(`TI.02`). A product has no location, because one product can run in both.

| Technology zone | | Technology location | |
|---|---|---|---|
| `TAP.00` | Application Technology | `TLC.00` | Cloud |
| `TFA.00` | Technology Facilities | `TLO.00` | On-premise |
| `TI.00` | Infrastructure Technology | | |
| `TN.00` | Network Technology | | |
| `TUD.00` | User Devices Technology | | |

A machine row states them in `extra.technology_zone` and
`extra.technology_location`. No row gives a Software Product or an
Application either value: those are for the organisation to fill. Each value
must be one of its own list's codes, on any row, even one whose item does
not carry the attribute: the build stops on any other, naming the row's
source and the codes it accepts. Each is `declared` evidence at most,
because a person or a document assigns it. takestock never derives either
from an item's class, so an item nothing places shows *not collected*. A
review draft of the model's successor, the GEANZ Technologies Taxonomy, adds
an operational technology zone (`TO.00`), renames `TUD.00` the User Endpoint
Technology Zone, and renames the two locations as computing environments,
keeping their codes; the new zone is not accepted until the successor is
approved.

### Machines from an IP address plan

Given `--ip-plan`, the build also reads the plan's addresses. Each name a
source gives as a **machine** at an address, and that the plan counts as the
address's current holder, becomes a machine item keyed on that name, with the
plan's addresses for it as its `address`:

- a name no row of the observation uses becomes a **Host**; a name a row
  already typed keeps its class, and the plan's addresses sit beside the
  row's, so a difference shows as contested;
- the evidence is `reported` when a source saw or named the address in use,
  and `declared` when the address is only documented; the date is the newest
  the plan holds for that machine;
- aliases (DNS names), labels, past holders, and addresses that only a
  superseded source lists are not machines and are left out;
- the plan is counted as one more instrument in the population rows.

A machine is matched on its name exactly as the plan's source spells it. A
source that gives `app-01` and a probe that names `app-01.example.test` make
two items, because nothing in either says they are the same machine.

## What the register holds

### Classes

| Family | Class | Built from |
|---|---|---|
| Service | Business Service, Technical Service | nothing yet: declared for the organisation to fill |
| Deployment | Application, Application Instance | nothing yet |
| Hardware | Server, Endpoint Device, Domain Controller, Network Device, Virtual Machine, Host | machine rows, by host type; with `--ip-plan`, the plan's machines |
| Software | Software Product, Software Release | rows naming software, on a machine or in an inventory, and releases a row lists |
| Network and Naming | DNS Name | discovery and mail-authentication rows, DNS-layer readings of a name, and names a zone file publishes |
| Network and Naming | Network Service | rows naming a listening port on a machine |
| Network and Naming | Certificate | certificate rows |
| Network and Naming | Network Range | nothing yet |
| Location | Site | nothing yet |
| Identity and Secret | Account | nothing yet |
| Identity and Secret | Credential | key-material rows |
| Commercial and Organisation | Vendor, Unattributed Dependency | third-party rows |
| Commercial and Organisation | Contract, Support Arrangement, Licence Entitlement | nothing yet |
| Commercial and Organisation | Declared Asset Class | the target profile's declared estate |

A class marked "nothing yet" is still listed in every register, with a count
of zero and the reason: it is declared for the organisation to populate, so
an empty class there means *not measured*, not *found empty*. A class that
rows do feed but that this observation left empty is reported as possibly
unmeasured, not clean.

Support and end-of-life dates live on the **Software Release** only: on the
product, every version would share one date; on each copy, the same date
would be repeated per machine.

### Attributes and evidence strength

Every value says how it came to be known, strongest first:

| Strength | Meaning |
|---|---|
| `measured` | An instrument read the value off the thing itself. |
| `reported` | A management system states it about something it manages. It read its own record, not the thing. |
| `declared` | A person or a document says so. |
| `inferred` | Derived from other facts by a rule. |

A row may state its own strength in `extra.evidence_strength`. Otherwise
rows from the declared estate are `declared`, rows from a collector that
registered itself as `reported` are `reported`, and everything else is
`measured`. Each attribute in the schema
also states the strongest evidence it can honestly carry
(`expected_strength`), and a claim above that is lowered to it: a grading is
`inferred` however directly the graded thing was read.

Each attribute also declares a `refresh_interval_days`: how long a value
stays fresh. A machine's operating system changes in days and its business
owner in a year, so one interval for everything would be wrong for most
attributes. `null` means the value does not go stale on a clock.

The attributes the NCSC NZ *Minimum Cyber Security Standards* suggest an
inventory hold are mapped in the schema's `minimum_attribute_set`, with a
note for each saying whether takestock fills it from an observation.

### When sources disagree

Every assertion is kept. Where the live assertions for one attribute
disagree, one value is published by a fixed order of preference:

1. a value a person decided beats one the tool proposed;
2. a value beats an absence;
3. stronger evidence beats weaker;
4. a more recent `valid_at` beats an older one.

The attribute is then marked **contested**, and every source's value is
listed beside the published one. If nothing in that order separates the top
two, the result is also marked a **tie**.

Nothing is ever deleted. A fact is withdrawn by a new assertion that
retracts it and states why.

### Absences

No cell is silently empty. A missing value carries a reason:

| Code | Shown as | Meaning |
|---|---|---|
| `not-collected` | not collected | Nobody has supplied this input yet. Says nothing about the estate. |
| `could-not-test` | could not test | The question was asked and no answer came back; usually fixable. |
| `extent-unknown` | extent unknown | Something can be shown to be missing, but not what. |
| `not-measured` | not measured | The instrument ran, and this attribute was absent from its result. |
| `not-applicable` | not applicable | There is no proper value (a virtual machine has no chassis serial). |
| `asked-unknown` | asked, unknown | The source was asked and does not know. |
| `asked-declined` | asked, declined | The source was asked and declined to answer. |
| `temp-unknown` | not known yet | The value is expected to become known, such as an open request. |
| `masked` | withheld | Not available for security, privacy or similar reasons. |
| `unsupported` | source cannot hold it | The source system cannot hold this element. |

The last six are adopted from the HL7 FHIR *DataAbsentReason* code system,
with its definitions. An attribute a class declares and no row stated is
counted separately as **declared and unasserted**, and never added to the
counts above.

### Lifecycle

The build sets each item's lifecycle state: `discovered` for anything an
instrument saw, `planned` for a Declared Asset Class. It never sets `live`,
because live means an owner has accepted the item, and a tool cannot. The
other states (`retiring`, `retired`, `disposed`) are for people to record.

### Relationships

Every relationship is declared in the schema with a direction, a
cardinality and a one-sentence **test** that decides whether an edge is the
right kind. These are drawn from an observation:

| Relationship | From → to | Test |
|---|---|---|
| `contains` | machine → Network Service | If the parent is deleted, does the child cease to exist? |
| `installed-on` | Software Release → machine | Is a copy of this release present on that machine? |
| `release-of` | Software Release → Software Product | Is the left a version of the right? |
| `presents` | DNS Name → Certificate | Does a client connecting here receive that certificate? |
| `member-of` | machine → Declared Asset Class | Is this item one of that group, without depending on it to exist? |

- `contains` is drawn once per machine and service, however many rows name
  the service.
- `installed-on` carries a **count** and its unit, never one item per copy.
- `presents` drawn from certificate-transparency logs carries a qualifier: a
  logged certificate was issued for the name, which does not show a server
  presents it.
- `member-of` is drawn only where the instrument that saw a machine is live
  for exactly one declared class. A declared-estate row lists its live
  instruments in `extra.collectors_live`, each by its collector id (a row's
  `source`, such as `example_agent`) or its display name (a row's
  `source_name`, such as `Example endpoint agent`). Both name the same
  instrument, so one listed by its id for one class and by its name for
  another is live for two classes and joins a machine to neither. A machine
  that two such instruments place in the same class gets one edge.

Declared and **not** drawn, each with its reason in every register:
`runs-on`, `hosted-at`, `realised-by`, `instance-of`, `depends-on`,
`communicates-with`, `supported-by`, `covered-by`, `entitled-by`,
`owned-by`, `resolves-to`, `replaces`, `part-of`. Most need facts no
collector reads (applications, locations, contracts, owners). Two are
withheld on purpose: `depends-on`, because nothing collected shows need and
a name lookup must never stand in for it; and `communicates-with`, because a
third-party row does not say which machine made the lookup.

### Population counts

Machines are counted once per instrument, and those counts are kept side by
side, never averaged: one instrument's count is what it can see, not what
exists. A software inventory counts the machines its rows name in
`extra.installed_on`. A discovery source that reports how many machines exist is counted
as `reported`. A final row counts every machine any instrument named, once.
Where the counts differ, every row is marked contested.

### Governance

The schema names who is accountable for the register as **role titles**
(`authority`, `accountable_owner`, `conflict_arbiter`, `resourcing`). Who
holds each role is the organisation's appointment and is never written in
the schema. A role set to `null` is reported as unassigned in every register.

## Keys and identity

Every item gets a surrogate key such as `CI-000001`. It carries no meaning,
is never reused, and survives a rename or a re-address. Match records on the
key, never on a name.

Every identifier an item was seen under is kept as an **alias**, with its
source and the first and last dates it was seen. Items are matched on
aliases in this order, most stable first:

| Alias kind | What it is |
|---|---|
| `estate-name` | A name the organisation assigns: hostname, service name, certificate subject |
| `hostname` | A host's name as an export gives it |
| `agent-id` | A management agent's install identifier, unchanged by renames |
| `serial` | A hardware serial number |
| `address` | A network address, used only when nothing better exists |

A MAC address may never be a key: modern client operating systems rotate a
private one per network. It is held as an attribute instead.

When one row names identifiers that already belong to two items (a host
name on one, an agent id on another), the items are **merged**: the key found
through the most stable identifier is kept, the other redirects to it, and the merge is recorded with its
date and reason.

To keep keys stable across builds, pass the previous `keys.jsonl` with
`--keys`.

## What it writes

| File | What it holds |
|---|---|
| `cmdb.json` | The whole register: the schema first, then the data. Empty values and false contest markers are left out. |
| `csv/<class>.csv` | One file per declared class, header only when the class is empty. Columns: `key`, `name`, `lifecycle_state`, `identifiers`, `contested`, then every attribute the class carries. |
| `csv/relationships.csv` | Every drawn edge: from, type, to, both names, count, unit, strength, date, qualifier. |
| `cmdb.xlsx` | The same register as a workbook (sheets below). |
| `keys.jsonl` | The key ledger: every key with its aliases, and every redirect. Feed it to the next build. |
| `jira-assets/schema-and-mapping.json` | Only when asked for: the object schema and import mapping for Jira Assets |
| `jira-assets/data.json` | Only when asked for: the register's items as one data chunk for that import |

A missing value is written as its reason in brackets, such as
`[not measured]`, never as an empty cell.

The workbook's sheets:

| Sheet | Answers |
|---|---|
| Read me | What was built, from which observation, the headline counts, unassigned governance roles, and how to read the rest |
| one per populated class | The items of that class; contested values in the accent colour, absences in grey italics |
| Relationships | Every drawn edge |
| Not in here | Every declared class with its count and, for a zero, why; then every relationship not drawn and why |
| Absence counted | How many values are missing, by reason, and the declared-and-unasserted count kept apart |
| Disagreements | Every contested attribute: the published value and what each source said |
| Populations | Machine counts per instrument |
| Facts | Every assertion with its strength, dates, source and artefact |
| Data dictionary | Every attribute: expected strength, refresh interval, which classes carry it |

## An import for Jira Assets

Jira Assets is Atlassian's asset and configuration database. With
`jira_assets` set, takestock writes the register in the form Assets' external
imports take, as Atlassian's developer documentation for Assets describes
them in two pages: *Imports REST API Guide* and *External Imports - Schema
and mapping*.

- `schema-and-mapping.json` follows Atlassian's published JSON schema, the
  *Imports Schema and Mapping definition*, version 2023-10-19. It names no
  `$schema`: the schema and mapping page says a document that uses external
  ids is read against that version, and every object type and attribute here
  has one. It is the document the guide's workflow submits to the import's
  `mapping` link.
- `data.json` is one data chunk: a `data` object holding a list of records
  for each object type's selector, and `completed: true`. It is the body the
  workflow posts to the execution's `submitResults` link.

How the register maps onto Assets:

| Register | Assets |
|---|---|
| Each declared class, empty ones included | One object type, its description the class's question; external id `takestock/<class>` |
| The key (`CI-000001`) | The *Register key* attribute, marked unique, and the only part of the external id, so an import matches objects on it. Every Assets object has a key of its own, so the register's key takes this name |
| The item's name | *Name*, the object's label |
| Lifecycle state, identifiers, contested attributes | *Lifecycle state*, *Identifiers* (a text area), *Contested* |
| Each attribute the class declares | A text attribute of the same name, the schema's note as its description. One whose name is the same as a fixed attribute's (such as `name`), compared without regard to case, gets the suffix ` (attribute)` |
| A missing value | Its reason in brackets, as in the CSV (`[not measured]`), never an empty value |
| Each kind of drawn relationship from one class to another | A reference attribute on the class it starts from, named `<relationship> <class>` (such as *installed-on Server*), holding every key it points at. It is resolved with the query `"Register key" IN (${<locator>${0}})`, the form Atlassian's knowledge-base article *How to import Assets object types with attributes referencing existing objects* gives for a reference to several objects |

What it leaves to the person running the import:

- **Keys across imports.** A register key names the same item from one
  import to the next only when each build is given the previous build's
  `keys.jsonl` (see [Keys and identity](#keys-and-identity)).
- **What the import drops.** A reference attribute holds only the objects it
  points at, so an edge's count, unit, evidence strength, date and qualifier
  stay in `cmdb.json` and the workbook. So do each value's evidence strength,
  dates and source, and the disagreements.
- **Items that are gone.** An item the next build does not list is simply
  absent from its data; these files never ask for an object to be removed.
- **Checked against the format, not a live site.** The files are checked
  against Atlassian's published JSON schema; takestock's tests do not
  submit them to an Assets site.

## How to read it

1. **Every value says how strongly it is known.** Strength and date are
   separate columns: a strong old fact and a weak fresh one are different
   problems.
2. **No cell is silently empty.** *Not measured* means the instrument ran and
   the attribute was missing. *Not collected* means nobody supplied the
   input, which says nothing about the estate.
3. **Where sources disagree, both are kept.** Read the Disagreements sheet
   before trusting a contested value.
4. **Match on the key, never on a name.**
5. **What is missing is counted.** The Not in here and Absence counted sheets
   are part of the answer, not an appendix to it.

## Rewording the schema with an overlay

An organisation often wants its own wording (a note on an attribute, a
class's question in its own words, who holds a governance role) without
taking a copy of the whole schema. A **schema overlay** does that. Name it in
the profile's `cmdb.schema_overlay`, or pass `schema_overlay=` from Python,
and its text is merged over the schema before the build checks it:

```yaml
# A schema overlay, such as targets/example-widgets.cmdb-schema-overlay.yaml
attributes:
  serial_number:
    note: As printed on the asset label Example Widgets fixes to each machine.
classes:
  Server:
    answers: Which servers does Example Widgets run?
vocabularies:
  absence_reason:
    not-collected:
      definition: Nobody at Example Widgets supplied the input.
governance:
  accountable_owner: Head of Operations, Example Widgets
```

Each field the overlay gives replaces the schema's text. It may set only
these:

| Section | Fields it may set on a declared entry |
|---|---|
| `families` | `answers`, `definition`, `note` |
| `classes` | `answers`, `built_from`, `note` |
| `attributes` | `note` |
| `relationships` | `asserts`, `test`, `wrong_if`, `qualifier`, `note` |
| `vocabularies` | on a declared code of a declared vocabulary: `definition`, `note`, `source` |
| `governance` | who holds a declared role (text, or null for unassigned) |

**An overlay rewords the model and never changes it.** The build stops,
listing every problem at once, when the overlay names a class, relationship,
attribute, family, vocabulary, code or governance role the schema does not
declare; sets any other field (a class's `family` or `attributes`, a
relationship's ends or `built`, an attribute's `expected_strength`); gives a
value that is not text; or holds any other section. To change the model
itself, change the schema as below.

The overlay is merged over whichever schema the build reads, the bundled one
or a workspace copy, and the register names the overlay's file in
`register.schema_overlay`.

## Changing the schema

Copy `src/takestock/data/cmdb-schema.yaml` to `data/cmdb-schema.yaml` in the
workspace, edit the copy, and name the workspace with `--workspace` or
`TAKESTOCK_HOME` when you build. For each element you add, say what question it
answers, and cite an authority for any obligation you claim. The build
refuses a schema in which:

- a class names an undeclared family or carries an undeclared attribute;
- a relationship's ends are neither a declared family nor a declared class,
  it has no `test`, it does not say whether it is drawn (`built`), or it is
  not drawn and gives no `note` saying why;
- an attribute has no `refresh_interval_days` or no valid `expected_strength`,
  or names a `vocabulary` that is not declared (an attribute that names one
  accepts only that vocabulary's codes);
- the `evidence_strength`, `basis`, `lifecycle_state` or `actor_kind`
  vocabulary differs from the values the code uses;
- a `cites:` entry names no key under `authorities:`.

A new attribute or class declared in the schema is listed in every register
straight away (as declared and unasserted, or as an empty class with its
reason). Filling it from observation rows needs a change to the builder.

## What it cannot see

- Applications, services, owners, contracts, licences, sites and accounts:
  no collector reads them, so their classes stay empty until someone supplies
  them.
- Which machine depends on which, or which application runs where: those
  relationships stay undrawn rather than guessed.
- Anything an instrument could not reach: an empty class fed by rows means
  the evidence may not have been gathered, not that nothing exists.
