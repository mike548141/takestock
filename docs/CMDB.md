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
takestock cmdb <observation_dir> [<out_dir>] [--keys <keys.jsonl>] [--workspace <dir>]
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
- The recording date is the observation's own date when its directory is
  named by a time stamp, otherwise today. Rebuilding the same observation
  therefore gives the same register.
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

From Python, `takestock.cmdb.build_register(observation_dir, keys=...)`
returns the whole register as one dictionary, and `write_outputs(register,
out_dir)` writes it.

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
| a discovered name, a mail-authentication record, or a DNS or DNSSEC reading | a **DNS Name** |
| anything else with a host name or a management agent's id | a **machine** |

A machine's class comes from the row's `extra.host_type`:

| `host_type` (any case) | class |
|---|---|
| `server` | Server |
| `workstation`, `desktop`, `laptop`, `endpoint` | Endpoint Device |
| `domain controller` | Domain Controller |
| `network device`, `router`, `switch`, `firewall` | Network Device |
| `virtual machine` | Virtual Machine |
| missing or anything else | **Host** |

`Host` is a class of its own, not a guess: "nothing said what this machine
is" is a finding someone can act on. A later row that does type the machine
moves it to the matching class.

A machine row that names a port (`extra.service` such as `443/tcp`, or
`port`) also creates a **Network Service** contained by the machine. A row
that names software also creates a **Software Product** and a **Software
Release**, and records that the release is installed on the machine.

A **DNS Name** for a domain the target profile names also carries two facts
read from public DNS by `ct_dns`. `name_servers` lists the hosts its NS
records say are authoritative for it (RFC 1035 §3.3.11), which is who hosts
its DNS. `dmarc_report_address` is the `rua=` tag of the DMARC record
published at the name itself, as published (RFC 9989 §4.7). Each is *not
applicable*, with a note, when the lookup settled with nothing to report: no NS
record because the name is not the top of its own zone, or no DMARC record or
no `rua=` in it. A name nothing read for them shows *not collected*.

## What the register holds

### Classes

| Family | Class | Built from |
|---|---|---|
| Service | Business Service, Technical Service | nothing yet: declared for the organisation to fill |
| Deployment | Application, Application Instance | nothing yet |
| Hardware | Server, Endpoint Device, Domain Controller, Network Device, Virtual Machine, Host | machine rows, by host type |
| Software | Software Product, Software Release | rows naming software installed on a machine |
| Network and Naming | DNS Name | discovery and mail-authentication rows, and DNS-layer readings of a name |
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

- `installed-on` carries a **count** and its unit, never one item per copy.
- `presents` drawn from certificate-transparency logs carries a qualifier: a
  logged certificate was issued for the name, which does not show a server
  presents it.
- `member-of` is drawn only where the instrument that saw a machine is live
  for exactly one declared class.

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
exists. A discovery source that reports how many machines exist is counted
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
- an attribute has no `refresh_interval_days` or no valid `expected_strength`;
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
